//! Secure Enclave P-256 key + Touch-ID-gated ECDH.
//!
//! The SE private key never leaves the Secure Enclave; each ECDH requires a live
//! biometric (access control `BiometryCurrentSet | PrivateKeyUsage`). ECDH against
//! a fixed peer public key is deterministic, which is what makes it a stable KEK
//! source.
//!
//! ## ECDH equivalence (load-bearing correctness assumption)
//!
//! Enrollment ([`crate::unlock::se`]) computes the shared secret on the *host* with
//! the `p256` crate as `ECDH(eph_priv, se_pub)`; unlock computes it here in the
//! Secure Enclave as `ECDH(se_priv, eph_pub)`. Standard (cofactor-1) ECDH on a prime
//! curve is symmetric, so both yield the same point, and both encode the raw
//! big-endian X-coordinate (32 bytes for P-256, NO KDF):
//!
//! * SE side: [`Algorithm::ECDHKeyExchangeStandard`] →
//!   `kSecKeyAlgorithmECDHKeyExchangeStandard`, documented by Apple as the raw shared
//!   secret (the X-coordinate), no key-derivation applied.
//! * Host side: `p256` `SharedSecret::raw_secret_bytes()` is the affine X-coordinate
//!   as `FieldBytes` (big-endian, 32 bytes).
//!
//! These MUST produce identical bytes or the wrapped DEK will not unwrap. The host
//! half is covered by a non-ignored software test in [`crate::unlock::se`]; the full
//! SE round-trip is gated behind `#[ignore]` tests below (it needs a code-signed
//! binary with Secure Enclave entitlements and Touch ID hardware).
//!
//! ## One FFI symbol: `SecKeyCreateWithData`
//!
//! Importing a peer EC public key from raw SEC1 bytes (needed to make it the peer of
//! the SE-side ECDH) has no safe wrapper in security-framework 3.7
//! (`SecKeyCreateWithData` lives only in the `security-framework-sys` crate, which is
//! not a direct dependency here). We bind that single symbol locally — it is already
//! linked via `Security.framework` (`build.rs`) — and bridge its result back into the
//! safe [`SecKey`] wrapper through `core-foundation`'s `TCFType`. Key generation,
//! lookup, ECDH, public-key export and deletion all use the safe `security-framework`
//! API. The `kSecAttr*` dictionary constants are bound as the framework's own exported
//! `CFStringRef`s, so their runtime string identifiers are never guessed.
use core_foundation::base::{CFOptionFlags, TCFType, TCFTypeRef};
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::string::{CFString, CFStringRef};
use err_mac::create_err_with_impls;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// A `Send + Sync` projection of a Core Foundation `CFError`.
///
/// `core_foundation::error::CFError` wraps a `*mut __CFError` and is therefore `!Send`,
/// so it cannot live inside an error type that crosses threads (e.g. via the bootstrap
/// ritual or the `Unlocker` trait, both `Send`). We capture the actionable, owned parts
/// — the numeric error `code` (the precise OSStatus-equivalent) and the `domain`
/// identifier — at the FFI boundary instead of holding the foreign handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfError {
    pub code: i64,
    pub domain: String,
}

impl From<core_foundation::error::CFError> for CfError {
    fn from(e: core_foundation::error::CFError) -> Self {
        Self {
            code: e.code() as i64,
            domain: e.domain().to_string(),
        }
    }
}

// Variant meanings (the `create_err_with_impls!` grammar does not allow doc comments
// on variants):
//   - KeyNotFound:      no SE key exists under the requested label.
//   - NotSecureEnclave: an enrollment was not Secure-Enclave-shaped (used by the unlocker).
//   - BadPubKeyLen(n):  a SEC1 public key was not 65 bytes / not `0x04`-tagged.
//   - Ecdh:             the SE key-exchange produced an unexpected-length result.
//   - ImportPubKey:     `SecKeyCreateWithData` returned NULL importing the peer pubkey.
//   - NoExternalRep:    `public_key()` / `external_representation()` returned `None`.
//   - SecFramework:     wrapped Security.framework `OSStatus` error (already `Send`).
//   - CoreFoundation:   `Send` projection of a `CFError` (see `CfError`).
create_err_with_impls!(
    #[derive(Debug)]
    pub SeErr,
    NotImplemented,
    KeyNotFound,
    NotSecureEnclave,
    BadPubKeyLen(usize),
    BadPeerPoint,
    SoftwareKey,
    TouchIdDenied,
    Ecdh,
    ImportPubKey,
    NoExternalRep,
    SecFramework(security_framework::base::Error),
    CoreFoundation(CfError),
    StdIo(std::io::Error)
    ;
);

// `CFError`-returning Security.framework calls (`SecKey::new`, `key_exchange`,
// `SecKeyCreateWithData`, `SecAccessControl::create_with_protection`) can use `?`
// directly: convert through the `Send` projection. (CLAUDE.md: implement
// `From<InnerError>` so `?` works without `map_err` boilerplate.)
impl From<core_foundation::error::CFError> for SeErr {
    fn from(e: core_foundation::error::CFError) -> Self {
        SeErr::CoreFoundation(e.into())
    }
}

/// `kSecAccessControlBiometryCurrentSet` (`1 << 3`): require a biometric enrolled at
/// key-creation time. Re-enrolling a fingerprint invalidates the key — exactly the
/// property we want (no silent biometric swap). Fixed ABI value from
/// `<Security/SecAccessControl.h>`.
const K_SEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET: CFOptionFlags = 1 << 3;
/// `kSecAccessControlPrivateKeyUsage` (`1 << 30`): permit private-key operations
/// (sign / key-exchange) under this access control. Fixed ABI value.
const K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE: CFOptionFlags = 1 << 30;

/// `ECDHKeyExchangeStandard` on P-256 yields the 32-byte field element (X-coordinate).
const P256_SHARED_LEN: usize = 32;
/// Uncompressed SEC1 point: `0x04 || X(32) || Y(32)`.
const SEC1_UNCOMPRESSED_LEN: usize = 65;
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;

/// The keychain label under which every machine stores its device-bound Secure Enclave
/// KEK key. Shared by the CLI and the SSH bootstrap so they always reference the same key.
pub const SE_KEY_LABEL: &str = "hotcheese.se.kek.v1";

extern "C" {
    /// Reconstruct a `SecKey` from raw key material (an uncompressed SEC1 EC public
    /// point) plus an attributes dictionary describing the key type/class. Part of
    /// `Security.framework`, linked by `build.rs`. No safe wrapper exists in
    /// security-framework 3.7, so we bind the one symbol we need.
    fn SecKeyCreateWithData(
        keyData: CFDataRef,
        attributes: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> *const c_void;

    // The `kSecAttr*` dictionary keys/values for `SecKeyCreateWithData`: exported
    // `CFStringRef` constants from `Security.framework`. Bound here (rather than via
    // security-framework-sys, not a direct dep) and used by Get-Rule, since we borrow
    // them. (These four are not declared by any sibling module's FFI block.)
    static kSecAttrKeyType: CFStringRef;
    static kSecAttrKeyClass: CFStringRef;
    static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
    static kSecAttrKeyClassPublic: CFStringRef;
}

/// Borrow one of the framework's `CFStringRef` constants as a `CFString` (Get Rule).
///
/// SAFETY: every `kSecAttr*` static above is a valid, immortal `CFStringRef` exported
/// by Security.framework; `wrap_under_get_rule` borrows it (balanced on drop).
fn cf_const(s: CFStringRef) -> CFString {
    unsafe { CFString::wrap_under_get_rule(s) }
}

/// Build the access control object that gates the SE private key: usable only when the
/// device is unlocked, on this device, and only after a live biometric from the
/// fingerprint set enrolled when the key was created.
fn biometric_access_control() -> Result<SecAccessControl, SeErr> {
    let flags = K_SEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET | K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE;
    Ok(SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        flags,
    )?)
}

/// Look up this machine's SE private key by `label`. Returns `Ok(None)` if absent so
/// callers can branch without treating "missing" as an error.
///
/// SE keys are token-backed (`kSecAttrTokenID`), so `SecItemCopyMatching` finds them by
/// class + label through the Secure Enclave token; no data-protection-keychain flag is
/// required at lookup (and the safe wrapper cannot emit one without its `OSX_10_15`
/// feature, which we are not enabling here).
fn find_se_key(label: &str) -> Result<Option<SecKey>, SeErr> {
    let mut opts = ItemSearchOptions::new();
    opts.class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        .limit(1);
    let results = match opts.search() {
        Ok(r) => r,
        // `errSecItemNotFound` surfaces as `Err`; treat it as "no key".
        Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    for r in results {
        if let SearchResult::Ref(Reference::Key(k)) = r {
            return Ok(Some(k));
        }
    }
    Ok(None)
}

/// `errSecItemNotFound` from `<Security/SecBase.h>`: the requested item could not be
/// found. Returned by `SecItemCopyMatching` when no key matches the label.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// Create (idempotently) this machine's Touch-ID-bound SE key under `label`.
pub fn ensure_se_key(label: &str) -> Result<(), SeErr> {
    if software_enclave_enabled() {
        return ensure_software_key();
    }
    if find_se_key(label)?.is_some() {
        return Ok(());
    }
    let access_control = biometric_access_control()?;
    let mut opts = GenerateKeyOptions::default();
    opts.set_token(Token::SecureEnclave)
        .set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_access_control(access_control)
        // A location is REQUIRED for the key to be *permanent*: `GenerateKeyOptions`
        // only sets `kSecAttrIsPermanent` when a location is present. On macOS,
        // `DefaultFileKeychain` adds no keychain-selection key to the request (it is a
        // no-op in the builder), so the `SecureEnclave` token id alone directs storage
        // to the data-protection keychain — i.e. this yields the canonical permanent
        // SE-key creation request. (We cannot name `Location::DataProtectionKeychain`:
        // it is gated behind the crate's `OSX_10_15` feature, which we are not
        // enabling.)
        .set_location(Location::DefaultFileKeychain)
        .set_label(label);
    // `SecKey::new` itself is not deprecated (only the public struct fields and
    // `generate()`/`to_dictionary()` are). Allow at the call site to stay clean across
    // patch releases that might tighten the lint.
    #[allow(deprecated)]
    let _key = SecKey::new(&opts)?;
    tracing::info!(label = %label, "created Secure Enclave P-256 key");
    Ok(())
}

/// Export the SE public key as uncompressed SEC1 (`0x04 || X || Y`, 65 bytes).
pub fn se_public_key(label: &str) -> Result<Vec<u8>, SeErr> {
    if software_enclave_enabled() {
        return software_pubkey();
    }
    let key = find_se_key(label)?.ok_or(SeErr::KeyNotFound)?;
    let pubkey = key.public_key().ok_or(SeErr::NoExternalRep)?;
    let data = pubkey
        .external_representation()
        .ok_or(SeErr::NoExternalRep)?;
    let bytes = data.to_vec();
    if bytes.len() != SEC1_UNCOMPRESSED_LEN || bytes[0] != SEC1_UNCOMPRESSED_TAG {
        return Err(SeErr::BadPubKeyLen(bytes.len()));
    }
    Ok(bytes)
}

/// Import a raw uncompressed-SEC1 EC public key into a transient `SecKey` so it can be
/// the peer in an ECDH. Returns a fully-owned, safe `SecKey` (CFRelease handled by
/// `TCFType`'s Drop).
fn import_peer_public_key(peer_pub_sec1: &[u8]) -> Result<SecKey, SeErr> {
    if peer_pub_sec1.len() != SEC1_UNCOMPRESSED_LEN || peer_pub_sec1[0] != SEC1_UNCOMPRESSED_TAG {
        return Err(SeErr::BadPubKeyLen(peer_pub_sec1.len()));
    }
    // Defense in depth: reject anything that isn't a valid P-256 curve point (off-curve /
    // identity) BEFORE handing the bytes to the SE private key's ECDH, rather than trusting
    // Security.framework to validate them.
    if p256::PublicKey::from_sec1_bytes(peer_pub_sec1).is_err() {
        return Err(SeErr::BadPeerPoint);
    }
    let key_data = CFData::from_buffer(peer_pub_sec1);
    // Attributes: an EC (prime random) *public* key. Keys and values are the
    // framework's own `CFStringRef` constants.
    let attrs = CFDictionary::from_CFType_pairs(&[
        (
            cf_const(unsafe { kSecAttrKeyType }),
            cf_const(unsafe { kSecAttrKeyTypeECSECPrimeRandom }).into_CFType(),
        ),
        (
            cf_const(unsafe { kSecAttrKeyClass }),
            cf_const(unsafe { kSecAttrKeyClassPublic }).into_CFType(),
        ),
    ]);
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: `key_data`/`attrs` are valid CF objects held for the call; `error` is a
    // valid out-pointer. `SecKeyCreateWithData` follows the Create Rule (+1), handed to
    // `wrap_under_create_rule` so the wrapper owns exactly one reference.
    let raw = unsafe {
        SecKeyCreateWithData(
            key_data.as_concrete_TypeRef(),
            attrs.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if !error.is_null() {
        // SAFETY: non-null `error` is a +1 CFError from the Create Rule.
        let err = unsafe { CFError::wrap_under_create_rule(error) };
        return Err(err.into());
    }
    if raw.is_null() {
        return Err(SeErr::ImportPubKey);
    }
    // SAFETY: `raw` is a non-null +1 `SecKeyRef` (as `*const c_void`); `from_void_ptr`
    // reconstitutes the typed ref without us naming the opaque sys type, and
    // `wrap_under_create_rule` takes ownership of the single reference.
    let key =
        unsafe { SecKey::wrap_under_create_rule(<SecKey as TCFType>::Ref::from_void_ptr(raw)) };
    Ok(key)
}

/// Deterministic ECDH between the SE private key and `peer_pub_sec1` (65-byte SEC1).
/// Triggers Touch ID. Returns the 32-byte shared X-coordinate, zeroized on drop.
pub fn se_ecdh(label: &str, peer_pub_sec1: &[u8]) -> Result<Zeroizing<[u8; 32]>, SeErr> {
    if software_enclave_enabled() {
        return software_se_ecdh(peer_pub_sec1);
    }
    let key = find_se_key(label)?.ok_or(SeErr::KeyNotFound)?;
    let peer = import_peer_public_key(peer_pub_sec1)?;
    // `ECDHKeyExchangeStandard` = raw shared secret (X-coordinate), no KDF. This is the
    // call that prompts Touch ID at runtime. `requested_size` is the desired byte
    // length; for the standard algorithm the result is the full field element (32).
    let mut shared = key.key_exchange(
        Algorithm::ECDHKeyExchangeStandard,
        &peer,
        P256_SHARED_LEN,
        None,
    )?;
    if shared.len() != P256_SHARED_LEN {
        shared.zeroize();
        return Err(SeErr::Ecdh);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&shared);
    // Wipe the intermediate Vec; the returned value is already zeroize-on-drop.
    shared.zeroize();
    Ok(Zeroizing::new(out))
}

/// Delete the SE key (rotation / uninstall). Idempotent: deleting an absent key is Ok.
/// Deletes by direct key reference (`SecItemDelete` via the safe wrapper), so there is
/// no keychain-selection ambiguity.
pub fn delete_se_key(label: &str) -> Result<(), SeErr> {
    if software_enclave_enabled() {
        let _ = std::fs::remove_file(software_key_path());
        return Ok(());
    }
    match find_se_key(label)? {
        Some(key) => {
            key.delete()?;
            tracing::info!(label = %label, "deleted Secure Enclave key");
            Ok(())
        }
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// DEMO software "enclave" — preview the flow with NO $99 / NO code signing.
//
// When `HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE` is set, the four entry points above
// operate on a software P-256 key in a FILE instead of the Secure Enclave, and gate
// each ECDH with a real Touch ID prompt via LAContext (which works on an unsigned
// binary). This reproduces the EXACT enroll/unlock/serve flow you get with the real
// enclave — the only difference is key custody: this key is on disk and extractable,
// and the biometric here is a gate, not hardware-enforced. NEVER use for real keys.
// ---------------------------------------------------------------------------

/// True only when the insecure software-enclave demo backend is explicitly enabled.
pub fn software_enclave_enabled() -> bool {
    std::env::var_os("HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE").is_some()
}

/// On-disk location of the demo software key.
fn software_key_path() -> PathBuf {
    crate::config::home_dir().join("software_enclave.key")
}

/// Write `data` to `path` with 0600 perms (best-effort containment of the demo key).
fn write_private_file(path: &Path, data: &[u8]) -> Result<(), SeErr> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

fn ensure_software_key() -> Result<(), SeErr> {
    ensure_software_key_at(&software_key_path())
}

/// Create the demo software key if absent (idempotent).
fn ensure_software_key_at(path: &Path) -> Result<(), SeErr> {
    if path.exists() {
        return Ok(());
    }
    let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let mut raw = sk.to_bytes();
    write_private_file(path, &raw)?;
    raw.as_mut_slice().zeroize();
    tracing::warn!(
        path = %path.display(),
        "DEMO: created a SOFTWARE 'enclave' key ON DISK (extractable, NOT hardware-backed). \
         For previewing the flow only — use the real Secure Enclave for production."
    );
    Ok(())
}

/// Load the demo software key (32-byte P-256 scalar) from `path`.
fn load_software_key_at(path: &Path) -> Result<p256::SecretKey, SeErr> {
    let bytes = std::fs::read(path)?;
    if bytes.len() != P256_SHARED_LEN {
        return Err(SeErr::SoftwareKey);
    }
    let field = p256::FieldBytes::clone_from_slice(&bytes);
    p256::SecretKey::from_bytes(&field).map_err(|_| SeErr::SoftwareKey)
}

/// Demo public key as uncompressed SEC1 (65 bytes).
fn software_pubkey() -> Result<Vec<u8>, SeErr> {
    let sk = load_software_key_at(&software_key_path())?;
    Ok(sk.public_key().to_sec1_bytes().into_vec())
}

/// Demo ECDH: gate with a real Touch ID prompt (LAContext, unsigned-OK), then ECDH
/// against the software key. Same deterministic raw shared secret as the SE path.
fn software_se_ecdh(peer_pub_sec1: &[u8]) -> Result<Zeroizing<[u8; 32]>, SeErr> {
    tracing::warn!("DEMO software enclave: unlocking with an on-disk key (NOT hardware)");
    if !crate::mac::authorize_with_touch_id("unlock key (DEMO software enclave)") {
        return Err(SeErr::TouchIdDenied);
    }
    let sk = load_software_key_at(&software_key_path())?;
    let peer = p256::PublicKey::from_sec1_bytes(peer_pub_sec1).map_err(|_| SeErr::BadPeerPoint)?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    Ok(Zeroizing::new(out))
}

/// Validate the Secure Enclave path end-to-end (requires a code-signed binary + Touch ID
/// hardware): create a throwaway key under `label`, confirm its public-key shape, confirm
/// ECDH is deterministic AND equals the host-side p256 ECDH used at enrollment, then delete
/// the key. Returns the first failed property. Each ECDH prompts Touch ID. `label` MUST NOT
/// be a real deployment key — it is deleted at the end.
pub fn selftest(label: &str) -> Result<(), SeErr> {
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;

    // Clean slate, then create (idempotently).
    delete_se_key(label)?;
    ensure_se_key(label)?;
    ensure_se_key(label)?;

    let result = (|| {
        let pk = se_public_key(label)?;
        if pk.len() != SEC1_UNCOMPRESSED_LEN || pk[0] != SEC1_UNCOMPRESSED_TAG {
            return Err(SeErr::BadPubKeyLen(pk.len()));
        }
        // A fixed ephemeral peer point: ECDH must be deterministic (stable KEK source).
        let eph = EphemeralSecret::random(&mut OsRng);
        let eph_pub = eph.public_key().to_encoded_point(false);
        let s1 = se_ecdh(label, eph_pub.as_bytes())?;
        let s2 = se_ecdh(label, eph_pub.as_bytes())?;
        if s1.as_slice() != s2.as_slice() {
            tracing::error!("SE ECDH is non-deterministic for a fixed peer");
            return Err(SeErr::Ecdh);
        }
        // And it must equal host ECDH(eph_priv, se_pub): the equivalence enroll/unlock rests on.
        let se_pub = p256::PublicKey::from_sec1_bytes(&pk).map_err(|_| SeErr::BadPeerPoint)?;
        let host_shared = eph.diffie_hellman(&se_pub);
        if s1.as_slice() != host_shared.raw_secret_bytes().as_slice() {
            tracing::error!(
                "SE ECDH(se_priv, eph_pub) != host ECDH(eph_priv, se_pub) — SE-wrapped DEKs \
                 would be unrecoverable"
            );
            return Err(SeErr::Ecdh);
        }
        Ok(())
    })();

    // Always remove the throwaway key, even on failure.
    let _ = delete_se_key(label);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Label used only by the ignored, hardware-touching test. Distinct so a stray run
    // cannot collide with a real deployment's key.
    const TEST_LABEL: &str = "com.cc.hot_cheese.se_test_key";

    #[test]
    fn bad_peer_pubkey_is_rejected_without_hardware() {
        // Wrong length and wrong tag are rejected purely host-side (no SE access),
        // proving the SEC1 validation guards before any FFI/import happens.
        assert!(matches!(
            import_peer_public_key(&[0x04u8; 10]),
            Err(SeErr::BadPubKeyLen(10))
        ));
        let mut not_uncompressed = vec![0u8; SEC1_UNCOMPRESSED_LEN];
        not_uncompressed[0] = 0x02; // compressed-point tag
        assert!(matches!(
            import_peer_public_key(&not_uncompressed),
            Err(SeErr::BadPubKeyLen(SEC1_UNCOMPRESSED_LEN))
        ));
    }

    #[test]
    fn access_control_flag_values_match_apple_sdk() {
        // Guards the locally-pinned flag constants against accidental edits: fixed ABI
        // values from <Security/SecAccessControl.h>.
        assert_eq!(K_SEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET, 1 << 3);
        assert_eq!(K_SEC_ACCESS_CONTROL_PRIVATE_KEY_USAGE, 1 << 30);
    }

    #[test]
    fn software_demo_key_persists_and_exports_uncompressed_pubkey() {
        // Non-interactive: exercises the DEMO software-enclave FILE backend (no Touch ID,
        // no Secure Enclave). Proves the key persists, reloads identically, and exports a
        // 65-byte uncompressed SEC1 public key — the shape enroll/unlock depend on.
        let path = std::env::temp_dir().join(format!("hc_sw_se_{}.key", std::process::id()));
        let _ = std::fs::remove_file(&path);
        ensure_software_key_at(&path).expect("create");
        ensure_software_key_at(&path).expect("idempotent second call");
        let sk1 = load_software_key_at(&path).expect("load");
        let sk2 = load_software_key_at(&path).expect("reload");
        assert_eq!(sk1.to_bytes(), sk2.to_bytes(), "persisted key must be stable");
        let pk = sk1.public_key().to_sec1_bytes().into_vec();
        assert_eq!(pk.len(), SEC1_UNCOMPRESSED_LEN);
        assert_eq!(pk[0], SEC1_UNCOMPRESSED_TAG);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[ignore = "requires code-signed binary with Secure Enclave entitlements + Touch ID hardware"]
    fn se_key_lifecycle_and_deterministic_ecdh() {
        // Full validation lives in `selftest` (also exposed via `hot_cheese se-selftest`):
        // create → 65B/0x04 pubkey → deterministic ECDH (Touch ID) → SE/host equivalence → delete.
        selftest(TEST_LABEL).expect("SE self-test");
        // selftest deletes the throwaway key; confirm it is gone.
        assert!(matches!(se_public_key(TEST_LABEL), Err(SeErr::KeyNotFound)));
    }
}
