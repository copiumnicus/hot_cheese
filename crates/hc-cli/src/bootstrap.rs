//! SSH bootstrap ritual: move the DEK from authority machine A to new machine B.
//!
//! A new machine B obtains the Data Encryption Key (DEK) from an authority machine
//! A over an SSH pipe, using ECIES so the DEK NEVER crosses the wire in plaintext.
//!
//! # Transport
//! `bootstrap_from(target)` spawns `ssh <target> hot_cheese bootstrap-serve` and
//! speaks a length-prefixed frame protocol over the child's piped stdin/stdout.
//! `bootstrap_serve()` is the far end of that SSH command: it speaks the SAME
//! protocol over its OWN process stdin/stdout. No new network listener is opened —
//! we reuse SSH purely as an authenticated, encrypted byte pipe.
//!
//! # Roles
//! - **B** (`bootstrap_from`) is the client: it has a Secure Enclave (SE) key and
//!   wants the DEK delivered sealed to that key.
//! - **A** (`bootstrap_serve`) is the authority: it already holds the DEK (wrapped
//!   in its keyring) and authorizes the transfer with a live Touch ID on A.
//!
//! # Cryptographic core (ephemeral-static ECIES to B's SE key)
//! 1. B sends its SE public key `b_se_pub` (65-byte uncompressed SEC1).
//! 2. A generates an EPHEMERAL P-256 keypair `E`, computes
//!    `shared = ECDH(E_priv, b_se_pub)` and `wrapKey = HKDF-SHA256(shared, INFO)`.
//! 3. A seals the DEK: `enc_dek = AEAD_seal(wrapKey, aad = b_se_pub ++ E_pub, dek)`
//!    and sends `E_pub` + `enc_dek`. The DEK on the wire is ciphertext only.
//! 4. B recomputes `shared = ECDH(SE_priv, E_pub)` (Touch ID on B), derives the same
//!    `wrapKey`, and opens `enc_dek` with `aad = b_se_pub ++ E_pub`.
//!
//! Ephemeral-static ECDH gives DEK confidentiality and forward secrecy even if the
//! transport is fully compromised: an attacker who records the stream cannot recover
//! the DEK without B's SE private key (which never leaves the enclave). The AAD
//! `b_se_pub ++ E_pub` binds the sealed DEK to BOTH endpoints, so a recorded `OFFER`
//! cannot be relayed to a different B or replayed under a different ephemeral key.
//!
//! # Residual trust assumptions
//! - **A's host identity / channel auth comes from SSH** (known_hosts / TOFU). We do
//!   NOT add a second authentication layer: if you trust `ssh <target>` to reach the
//!   real A, you trust this bootstrap. A MITM that can fully impersonate A over SSH
//!   could serve a DEK of its choosing — but it still cannot LEARN B's DEK, because
//!   confidentiality rests on B's SE key, not on the channel. Verify the SSH host key
//!   fingerprint out-of-band before first connect.
//! - **A authorizes the transfer with Touch ID on A's physical machine.** Because
//!   A's stdin/stdout are consumed by this protocol, A cannot prompt for an
//!   interactive recovery passphrase; the supported authority path is therefore a
//!   Secure Enclave enrollment on A (see [`select_authority_unlocker`]).
//! - **B re-wraps under its OWN keys.** A's keyring enrollments (A's `se_pub` /
//!   stored `eph_pub`) are device-bound and meaningless on B, so B builds a FRESH
//!   keyring enrolling the DEK under B's SE (and, with `--recovery-passphrase`, a
//!   recovery passphrase read from a masked prompt or stdin). A's `keyring.json` is
//!   never copied. The one thing
//!   B does copy from it is A's vault id, carried in `OFFER`: B holds the SAME DEK, so
//!   it is the same vault and must back up into the same remote subtree.
//! - The plaintext DEK exists transiently in A's and B's process memory during the
//!   ritual; it is zeroized as soon as it is no longer needed.
use err_mac::create_err_with_impls;
use hc_core::config::Config;
use hc_core::crypto::envelope::{
    self, atomic_write_new, enforce_store_modes, Dek, EncFile, MAX_KEYSTORE_FILE_BYTES,
};
use hc_core::is_valid_key_name;
use hc_core::keyring::{Keyring, VaultId, KEYRING_FILE};
use hc_core::mac::secure_enclave;
use hc_core::unlock::{PassphraseUnlocker, SecureEnclaveUnlocker, Unlocker};
use hc_sign::policy::{Policy, MAX_POLICY_BYTES};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Keychain label for this host's Secure Enclave bootstrap key. Stable per machine.
const LABEL: &str = hc_core::mac::secure_enclave::SE_KEY_LABEL;
/// Protocol version carried in `HELLO` and checked by A.
const PROTO: u32 = 1;
/// HKDF `info` string — domain-separates this wrap key from any other ECDH use.
const HKDF_INFO: &[u8] = b"hotcheese/bootstrap/v1";
/// Uncompressed SEC1 P-256 public key length (`0x04 || X || Y`).
const SEC1_LEN: usize = 65;
/// Hard cap on a single frame payload. A maximum-sized keystore is hex encoded inside JSON,
/// so 512 KiB leaves ample framing room while bounding allocation before deserialization.
const MAX_FRAME: u32 = 512 * 1024;
/// Same whole-store ceilings used by backup-tree validation.
const MAX_BOOTSTRAP_FILES: usize = hc_core::MAX_STORE_FILES;
const MAX_BOOTSTRAP_BYTES: u64 = hc_core::MAX_STORE_BYTES;
/// Touch ID sheet text for B's enclave ECDH that opens the DEK sealed by the authority.
const ECDH_REASON: &str = "Unlock this machine's hot_cheese enclave key for bootstrap";
/// Ceiling on a piped passphrase: the enrolment maximum plus its trailing newline.
const MAX_PIPED_PASSPHRASE_BYTES: u64 = hc_core::unlock::pass::MAX_NEW_PASSPHRASE_BYTES as u64 + 1;
const SSH_CONNECT_TIMEOUT_SECS: u64 = 5;
const SSH_ALIVE_INTERVAL_SECS: u64 = 5;
const SSH_ALIVE_COUNT_MAX: u64 = 3;
/// The whole explicit, interactive ritual, including Touch ID on both machines.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_SSH_STDERR_BYTES: u64 = 256 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// Variant meanings (the macro does not accept per-variant doc comments):
//   Protocol       frame/handshake violation (bad tag order, truncation, oversize)
//   ProtoMismatch  peer reported a version we do not speak
//   BadPubKey      a wire public key was not a valid 65-byte uncompressed SEC1 point
//   PeerAbort      the peer sent an ERROR frame (message logged, not retained typed)
//   NoSeAuthority  A has no Secure Enclave enrollment, so it cannot authorize headless
//   DekOpenFailed  sealed-DEK AEAD open failed (wrong key / tamper / relay); nothing saved
//   Ssh            the ssh child could not be spawned or exited non-zero
//   SshTimeout     the complete SSH bootstrap ritual exceeded its wall-clock deadline
create_err_with_impls!(
    #[derive(Debug)]
    pub BootstrapErr,
    Protocol,
    ProtoMismatch,
    BadPubKey,
    PeerAbort,
    NoSeAuthority,
    DekOpenFailed,
    Ssh,
    SshTimeout,
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error),
    Passphrase(crate::PassphraseErr),
    Config(hc_core::config::ConfigErr),
    SshTarget(hc_core::config::SshTargetErr),
    Keyring(hc_core::keyring::KeyringErr),
    Unlock(hc_core::unlock::UnlockErr),
    Envelope(hc_core::crypto::envelope::EnvErr),
    Policy(hc_sign::policy::PolicyErr),
    Se(hc_core::mac::secure_enclave::SeErr),
    P256(p256::elliptic_curve::Error)
    ;
    UnsafeFileName { name: String },
    DuplicateFile { name: String },
    TooManyFiles { found: usize, max: usize },
    FileTooLarge { name: String, size: u64, max: u64 },
    StoreTooLarge { size: u64, max: u64 },
    ManifestMismatch { expected: String, found: String },
    DestinationExists { path: PathBuf },
);

// ---------------------------------------------------------------------------
// ECDH abstraction (decoupled from the Secure Enclave for testing)
// ---------------------------------------------------------------------------

/// "Do an ECDH using MY private key against a peer's public key", abstracted over
/// where the private key lives. This is the single seam that lets the full handshake
/// run in tests with software P-256 keys standing in for both SE endpoints, while
/// production uses the Touch-ID-gated Secure Enclave.
pub enum EcdhKey {
    /// Private key held in the Secure Enclave under this keychain label. Each
    /// [`EcdhKey::ecdh`] call triggers Touch ID via [`secure_enclave::se_ecdh`].
    SecureEnclave(String),
    /// Software P-256 private key (tests, and authority machines without an SE).
    /// The held [`SecretKey`] is zeroized on drop by `p256`.
    Software(SecretKey),
}

impl EcdhKey {
    /// This key's public point as 65-byte uncompressed SEC1 (`0x04 || X || Y`).
    fn public_sec1(&self) -> Result<Vec<u8>, BootstrapErr> {
        match self {
            EcdhKey::SecureEnclave(label) => Ok(secure_enclave::se_public_key(label)?),
            EcdhKey::Software(sk) => {
                // p256's NistP256 sets COMPRESS_POINTS = false, so this is uncompressed 65B.
                Ok(sk.public_key().to_sec1_bytes().into_vec())
            }
        }
    }

    /// 32-byte ECDH shared secret (the X-coordinate) against `peer_sec1`.
    /// Zeroized on drop. For the SE variant this requires a live Touch ID.
    fn ecdh(&self, peer_sec1: &[u8]) -> Result<Zeroizing<[u8; 32]>, BootstrapErr> {
        match self {
            EcdhKey::SecureEnclave(label) => Ok(secure_enclave::se_ecdh(
                label,
                peer_sec1,
                None,
                ECDH_REASON,
            )?),
            EcdhKey::Software(sk) => {
                let peer = PublicKey::from_sec1_bytes(peer_sec1)?;
                let shared = diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
                let bytes = shared.raw_secret_bytes();
                let mut out = [0u8; 32];
                out.copy_from_slice(bytes.as_slice());
                Ok(Zeroizing::new(out))
            }
        }
    }
}

/// `wrapKey = HKDF-SHA256(ikm = shared, info = HKDF_INFO)`. Zeroized on drop.
fn derive_wrap_key(shared: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, BootstrapErr> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, out.as_mut_slice())
        .map_err(|_| BootstrapErr::Protocol)?;
    Ok(out)
}

/// AAD binding the sealed DEK to both endpoints: `b_se_pub ++ E_pub`.
fn bind_aad(b_se_pub: &[u8], eph_pub: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(b_se_pub.len() + eph_pub.len());
    aad.extend_from_slice(b_se_pub);
    aad.extend_from_slice(eph_pub);
    aad
}

fn check_sec1(b: &[u8]) -> Result<(), BootstrapErr> {
    if b.len() == SEC1_LEN && b[0] == 0x04 {
        Ok(())
    } else {
        Err(BootstrapErr::BadPubKey)
    }
}

// ---------------------------------------------------------------------------
// Frame protocol: [u32 BE length][1 byte tag][JSON payload]
// `length` covers the tag byte plus the JSON payload.
// ---------------------------------------------------------------------------

/// Frame type tags. The wire order for a successful run is:
/// `HELLO → OFFER → FILE* → DONE → ACK`. Either side may send `ERROR` to abort.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Tag {
    Hello = 1,
    Offer = 2,
    File = 3,
    Done = 4,
    Ack = 5,
    Error = 6,
}

impl Tag {
    fn from_u8(b: u8) -> Result<Self, BootstrapErr> {
        match b {
            1 => Ok(Tag::Hello),
            2 => Ok(Tag::Offer),
            3 => Ok(Tag::File),
            4 => Ok(Tag::Done),
            5 => Ok(Tag::Ack),
            6 => Ok(Tag::Error),
            _ => Err(BootstrapErr::Protocol),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    proto: u32,
    #[serde(with = "hex::serde")]
    b_se_pub: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    #[serde(with = "hex::serde")]
    eph_pub: Vec<u8>,
    enc_dek: EncFile,
    /// Names of the keystore files that will follow as `FILE` frames.
    manifest: Vec<String>,
    /// A's vault id: B shares the DEK, so it shares the backup subtree too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vault_id: Option<VaultId>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileMsg {
    name: String,
    /// Raw on-disk bytes of the keystore `EncFile` JSON, shipped verbatim.
    #[serde(with = "hex::serde")]
    body: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Done {
    count: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    ok: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorMsg {
    msg: String,
}

/// Cancels the process-global authority deadline on every ordinary return. The hidden
/// `bootstrap-serve` command is a single-purpose process; the default SIGALRM action is a safe
/// last resort when a custom SSH caller stops mid-protocol while this process holds the store
/// claim. The client has its own independently enforced watchdog as well.
struct AuthorityAlarm;

impl AuthorityAlarm {
    fn start() -> Self {
        let seconds = u32::try_from(BOOTSTRAP_TIMEOUT.as_secs()).unwrap_or(u32::MAX);
        // SAFETY: `alarm` only schedules SIGALRM for this single-purpose process. No signal
        // handler or shared memory is installed, and Drop cancels it on every ordinary return.
        unsafe {
            libc::alarm(seconds);
        }
        Self
    }
}

impl Drop for AuthorityAlarm {
    fn drop(&mut self) {
        // SAFETY: cancelling a process alarm has no pointer or lifetime preconditions.
        unsafe {
            libc::alarm(0);
        }
    }
}

/// Serialize `payload` as JSON and write one framed message.
fn write_frame<W: Write, T: Serialize>(
    w: &mut W,
    tag: Tag,
    payload: &T,
) -> Result<(), BootstrapErr> {
    let body = serde_json::to_vec(payload)?;
    let len = (body.len() as u64) + 1; // +1 tag byte
    if len > MAX_FRAME as u64 {
        return Err(BootstrapErr::Protocol);
    }
    w.write_all(&(len as u32).to_be_bytes())?;
    w.write_all(&[tag as u8])?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Read one framed message: returns its tag and the raw JSON payload bytes.
fn read_frame<R: Read>(r: &mut R) -> Result<(Tag, Vec<u8>), BootstrapErr> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > MAX_FRAME {
        return Err(BootstrapErr::Protocol);
    }
    let mut tag_buf = [0u8; 1];
    r.read_exact(&mut tag_buf)?;
    let tag = Tag::from_u8(tag_buf[0])?;
    let mut body = vec![0u8; (len - 1) as usize];
    r.read_exact(&mut body)?;
    Ok((tag, body))
}

/// Read a frame, decode its JSON payload, and assert it carries `expect`.
/// If the peer sent an `ERROR`, surface it as [`BootstrapErr::PeerAbort`].
fn read_expect<R: Read, T: DeserializeOwned>(r: &mut R, expect: Tag) -> Result<T, BootstrapErr> {
    let (tag, body) = read_frame(r)?;
    if tag == Tag::Error {
        let e: ErrorMsg = hc_core::wire::strict_json_from_slice(&body)?;
        tracing::error!(peer_msg = %hc_core::safe_diagnostic_text(&e.msg), "bootstrap peer aborted");
        return Err(BootstrapErr::PeerAbort);
    }
    if tag != expect {
        return Err(BootstrapErr::Protocol);
    }
    Ok(hc_core::wire::strict_json_from_slice(&body)?)
}

/// Best-effort `ERROR` frame so the peer aborts cleanly instead of seeing a dropped
/// pipe. Failure to send is ignored — we are already on the error path.
fn send_error<W: Write>(w: &mut W, msg: &str) {
    let _ = write_frame(
        w,
        Tag::Error,
        &ErrorMsg {
            msg: msg.to_string(),
        },
    );
}

// ---------------------------------------------------------------------------
// Store-file enumeration
// ---------------------------------------------------------------------------

/// The only two relative path shapes bootstrap may carry. Keeping this grammar identical to
/// the backup tree prevents a peer-controlled name from escaping `store` at persistence time.
#[derive(Clone, Copy)]
enum StoreFile<'a> {
    Keystore(&'a str),
    Policy,
}

fn store_file(name: &str) -> Result<StoreFile<'_>, BootstrapErr> {
    if !name.contains('/') && is_valid_key_name(name) {
        return Ok(StoreFile::Keystore(name));
    }
    if let Some(file) = name.strip_prefix("policies/") {
        if !file.contains('/') {
            if let Some(key) = file.strip_suffix(".toml") {
                if is_valid_key_name(key) {
                    return Ok(StoreFile::Policy);
                }
            }
        }
    }
    Err(BootstrapErr::UnsafeFileName {
        name: hc_core::safe_diagnostic_text(name),
    })
}

fn max_file_bytes(name: &str) -> Result<u64, BootstrapErr> {
    Ok(match store_file(name)? {
        StoreFile::Keystore(_) => MAX_KEYSTORE_FILE_BYTES,
        StoreFile::Policy => MAX_POLICY_BYTES,
    })
}

/// Validate bytes before they are accepted from or sent to a peer. When `dek` is available,
/// opening a keystore also proves its AEAD, filename AAD, and DEK all agree.
fn validate_store_file(name: &str, body: &[u8], dek: Option<&Dek>) -> Result<(), BootstrapErr> {
    let max = max_file_bytes(name)?;
    if body.len() as u64 > max {
        return Err(BootstrapErr::FileTooLarge {
            name: name.to_string(),
            size: body.len() as u64,
            max,
        });
    }
    match store_file(name)? {
        StoreFile::Keystore(key) => {
            let parsed = envelope::parse_keystore(body)?;
            if let Some(dek) = dek {
                let _plaintext = parsed.open(key, dek)?;
            }
        }
        StoreFile::Policy => {
            Policy::parse(body)?;
        }
    }
    Ok(())
}

fn add_total(total: &mut u64, size: u64) -> Result<(), BootstrapErr> {
    *total = total.checked_add(size).ok_or(BootstrapErr::StoreTooLarge {
        size: u64::MAX,
        max: MAX_BOOTSTRAP_BYTES,
    })?;
    if *total > MAX_BOOTSTRAP_BYTES {
        return Err(BootstrapErr::StoreTooLarge {
            size: *total,
            max: MAX_BOOTSTRAP_BYTES,
        });
    }
    Ok(())
}

fn check_manifest(names: &[String]) -> Result<(), BootstrapErr> {
    if names.len() > MAX_BOOTSTRAP_FILES {
        return Err(BootstrapErr::TooManyFiles {
            found: names.len(),
            max: MAX_BOOTSTRAP_FILES,
        });
    }
    let mut previous: Option<&str> = None;
    for name in names {
        store_file(name)?;
        if previous.is_some_and(|prior| prior >= name.as_str()) {
            if previous == Some(name.as_str()) {
                return Err(BootstrapErr::DuplicateFile { name: name.clone() });
            }
            return Err(BootstrapErr::Protocol);
        }
        previous = Some(name.as_str());
    }
    Ok(())
}

/// Names A should ship: root keystores plus per-key policies. A's device-bound keyring is
/// rebuilt on B, transient writes and every unknown path are excluded. Sorted and bounded.
fn shippable_files(store: &Path) -> Result<Vec<String>, BootstrapErr> {
    let mut names = Vec::new();
    for (at, entry) in std::fs::read_dir(store)?.enumerate() {
        if at >= hc_core::MAX_STORE_ENUM_ENTRIES {
            return Err(BootstrapErr::TooManyFiles {
                found: at + 1,
                max: hc_core::MAX_STORE_ENUM_ENTRIES,
            });
        }
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str() {
            if is_valid_key_name(name) {
                names.push(name.to_string());
            }
        }
    }
    let policies = store.join("policies");
    if std::fs::symlink_metadata(&policies).is_ok_and(|m| m.file_type().is_dir()) {
        for (at, entry) in std::fs::read_dir(policies)?.enumerate() {
            if at >= hc_core::MAX_STORE_ENUM_ENTRIES {
                return Err(BootstrapErr::TooManyFiles {
                    found: at + 1,
                    max: hc_core::MAX_STORE_ENUM_ENTRIES,
                });
            }
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            if let Some(file) = entry.file_name().to_str() {
                if let Some(key) = file.strip_suffix(".toml") {
                    if is_valid_key_name(key) {
                        names.push(format!("policies/{file}"));
                    }
                }
            }
        }
    }
    names.sort();
    check_manifest(&names)?;

    let mut total = 0u64;
    for name in &names {
        let size = std::fs::metadata(store.join(name))?.len();
        let max = max_file_bytes(name)?;
        if size > max {
            return Err(BootstrapErr::FileTooLarge {
                name: name.clone(),
                size,
                max,
            });
        }
        add_total(&mut total, size)?;
    }
    Ok(names)
}

fn read_store_file(store: &Path, name: &str, dek: &Dek) -> Result<Vec<u8>, BootstrapErr> {
    let max = max_file_bytes(name)?;
    let mut body = Vec::new();
    hc_core::open_regular_file(&store.join(name))?
        .take(max + 1)
        .read_to_end(&mut body)?;
    validate_store_file(name, &body, Some(dek))?;
    Ok(body)
}

// ---------------------------------------------------------------------------
// Authority (A) side
// ---------------------------------------------------------------------------

/// Pick the unlocker A uses to authorize the transfer. A's stdin/stdout are busy
/// with the protocol, so an interactive passphrase prompt is impossible: the
/// supported path is a Secure Enclave enrollment (Touch ID on A). Returns
/// [`BootstrapErr::NoSeAuthority`] if the keyring has no SE enrollment.
fn select_authority_unlocker(keyring: &Keyring) -> Result<SecureEnclaveUnlocker, BootstrapErr> {
    use hc_core::keyring::EnrollParams;
    let has_se = keyring
        .enrollments
        .iter()
        .any(|e| matches!(e.params, EnrollParams::SecureEnclave { .. }));
    if has_se {
        Ok(SecureEnclaveUnlocker::new(LABEL))
    } else {
        Err(BootstrapErr::NoSeAuthority)
    }
}

/// Parse every public fact needed to identify a bootstrap recipient before the authority is asked
/// to unlock anything. Garbage, a version mismatch, and malformed SEC1 all fail without Touch ID.
fn receive_hello<R: Read, W: Write>(r: &mut R, w: &mut W) -> Result<Vec<u8>, BootstrapErr> {
    let hello: Hello = read_expect(r, Tag::Hello)?;
    if hello.proto != PROTO {
        send_error(w, "unsupported proto version");
        return Err(BootstrapErr::ProtoMismatch);
    }
    if let Err(error) = check_sec1(&hello.b_se_pub) {
        send_error(w, "bad b_se_pub");
        return Err(error);
    }
    // Parse the point now as well. A length/tag check is only framing; rejecting a point that is
    // not on P-256 before Touch ID keeps every deterministic refusal ahead of authorization.
    if let Err(error) = PublicKey::from_sec1_bytes(&hello.b_se_pub) {
        send_error(w, "invalid b_se_pub point");
        return Err(error.into());
    }
    Ok(hello.b_se_pub)
}

/// Authority handshake after a validated recipient has already been identified and authorized.
fn serve_after_hello<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    dek: &Dek,
    store: &Path,
    vault_id: Option<&VaultId>,
    b_se_pub: Vec<u8>,
) -> Result<(), BootstrapErr> {
    // 2. Ephemeral P-256 keypair E; seal the DEK to B under HKDF(ECDH(E, b_se_pub)).
    let eph = EcdhKey::Software(SecretKey::random(&mut rand::rngs::OsRng));
    let eph_pub = match eph.public_sec1() {
        Ok(p) => p,
        Err(e) => {
            send_error(w, "ephemeral key error");
            return Err(e);
        }
    };
    let shared = match eph.ecdh(&b_se_pub) {
        Ok(s) => s,
        Err(e) => {
            send_error(w, "ecdh failed");
            return Err(e);
        }
    };
    let wrap_key = match derive_wrap_key(&shared) {
        Ok(k) => k,
        Err(e) => {
            send_error(w, "hkdf failed");
            return Err(e);
        }
    };
    let aad = bind_aad(&b_se_pub, &eph_pub);
    let enc_dek = match envelope::seal(&wrap_key, &aad, dek.expose()) {
        Ok(f) => f,
        Err(e) => {
            send_error(w, "seal failed");
            return Err(e.into());
        }
    };

    // 3. OFFER, then each keystore file verbatim, then DONE.
    let names = match shippable_files(store) {
        Ok(n) => n,
        Err(e) => {
            send_error(w, "store read failed");
            return Err(e);
        }
    };
    write_frame(
        w,
        Tag::Offer,
        &Offer {
            eph_pub,
            enc_dek,
            manifest: names.clone(),
            vault_id: vault_id.cloned(),
        },
    )?;

    let mut count: u32 = 0;
    let mut total = 0u64;
    for name in &names {
        let body = read_store_file(store, name, dek)?;
        add_total(&mut total, body.len() as u64)?;
        write_frame(
            w,
            Tag::File,
            &FileMsg {
                name: name.clone(),
                body,
            },
        )?;
        count += 1;
    }
    write_frame(w, Tag::Done, &Done { count })?;

    // 4. Await B's ACK. Anything else is a failed transfer.
    let ack: Ack = read_expect(r, Tag::Ack)?;
    if !ack.ok {
        return Err(BootstrapErr::Protocol);
    }
    tracing::info!(files = count, "bootstrap: DEK delivered and store shipped");
    Ok(())
}

/// Authority handshake over an arbitrary transport. `dek` is already available in tests; the
/// production entry point performs the public HELLO preflight before unlocking it.
#[cfg(test)]
fn serve<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    dek: &Dek,
    store: &Path,
    vault_id: Option<&VaultId>,
) -> Result<(), BootstrapErr> {
    let b_se_pub = receive_hello(r, w)?;
    serve_after_hello(r, w, dek, store, vault_id, b_se_pub)
}

/// Run on the AUTHORITY machine (invoked over SSH as `hot_cheese bootstrap-serve`):
/// serve the handshake over this process's own stdin/stdout.
pub fn bootstrap_serve() -> Result<(), BootstrapErr> {
    let _deadline = AuthorityAlarm::start();
    let config = Config::load()?;
    let store: PathBuf = config.store_path();
    let keyring = Keyring::load(&store.join(KEYRING_FILE))?;

    let unlocker = select_authority_unlocker(&keyring)?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut r = stdin.lock();
    let mut w = stdout.lock();
    let b_se_pub = receive_hello(&mut r, &mut w)?;
    let fingerprint = hex::encode(&Sha256::digest(&b_se_pub)[..8]);
    tracing::warn!(recipient_key_sha256 = %fingerprint, "authorizing bootstrap recipient");
    // Touch ID on A authorizes the transfer only after the sheet can name B's key fingerprint.
    let dek = unlocker.unlock(
        &format!("authorize bootstrap to recipient {fingerprint}"),
        &keyring,
        None,
    )?;

    let res = serve_after_hello(
        &mut r,
        &mut w,
        &dek,
        &store,
        keyring.vault_id.as_ref(),
        b_se_pub,
    );
    if let Err(ref e) = res {
        tracing::error!(error = %hc_core::safe_diagnostic_text(&e.to_string()), "bootstrap serve failed");
    }
    res
}

// ---------------------------------------------------------------------------
// Client (B) side
// ---------------------------------------------------------------------------

/// Outcome of a successful client handshake: the recovered DEK plus the staged
/// keystore files (name, raw bytes). The caller decides where to persist them.
struct Received {
    dek: Dek,
    files: Vec<(String, Vec<u8>)>,
    /// A's vault id, recorded in B's keyring so both back up to the same subtree.
    vault_id: Option<VaultId>,
}

/// Client handshake over an arbitrary transport. `my_key` does the ECDH that
/// recovers the DEK (Secure Enclave in production, software in tests); `b_se_pub`
/// is `my_key`'s public point as sent in `HELLO`. Persists NOTHING — on any failure
/// (including AEAD open) it returns an error and the caller writes nothing.
/// Separated from [`bootstrap_from`] so tests can drive it over an in-memory pipe.
fn client<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    my_key: &EcdhKey,
    b_se_pub: &[u8],
) -> Result<Received, BootstrapErr> {
    // 1. HELLO with B's SE public key.
    write_frame(
        w,
        Tag::Hello,
        &Hello {
            proto: PROTO,
            b_se_pub: b_se_pub.to_vec(),
        },
    )?;

    // 2. OFFER → recover the DEK via ECDH on B's key.
    let offer: Offer = read_expect(r, Tag::Offer)?;
    check_manifest(&offer.manifest)?;
    if let Err(e) = check_sec1(&offer.eph_pub) {
        send_error(w, "bad eph_pub");
        return Err(e);
    }
    let shared = match my_key.ecdh(&offer.eph_pub) {
        Ok(s) => s,
        Err(e) => {
            send_error(w, "ecdh failed");
            return Err(e);
        }
    };
    let wrap_key = derive_wrap_key(&shared)?;
    let aad = bind_aad(b_se_pub, &offer.eph_pub);
    let dek_bytes = match envelope::open(&wrap_key, &aad, &offer.enc_dek) {
        Ok(b) => b,
        Err(_) => {
            // AEAD failure: wrong key, tamper, or relayed offer. Abort, persist nothing.
            send_error(w, "sealed DEK failed to open");
            return Err(BootstrapErr::DekOpenFailed);
        }
    };
    let dek = {
        let arr: [u8; 32] = match dek_bytes.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => {
                let mut z = dek_bytes;
                z.zeroize();
                send_error(w, "bad DEK length");
                return Err(BootstrapErr::Protocol);
            }
        };
        let mut z = dek_bytes;
        z.zeroize();
        Dek::from_bytes(arr)
    };

    // 3. Collect FILE frames into memory until DONE.
    let mut files: Vec<(String, Vec<u8>)> = Vec::with_capacity(offer.manifest.len());
    let mut total = 0u64;
    loop {
        let (tag, body) = read_frame(r)?;
        match tag {
            Tag::File => {
                let f: FileMsg = hc_core::wire::strict_json_from_slice(&body)?;
                let Some(expected) = offer.manifest.get(files.len()) else {
                    send_error(w, "more files than manifest entries");
                    return Err(BootstrapErr::Protocol);
                };
                if &f.name != expected {
                    send_error(w, "file does not match manifest order");
                    return Err(BootstrapErr::ManifestMismatch {
                        expected: expected.clone(),
                        found: hc_core::safe_diagnostic_text(&f.name),
                    });
                }
                validate_store_file(expected, &f.body, Some(&dek))?;
                add_total(&mut total, f.body.len() as u64)?;
                files.push((f.name, f.body));
            }
            Tag::Done => {
                let done: Done = hc_core::wire::strict_json_from_slice(&body)?;
                if done.count as usize != files.len() || files.len() != offer.manifest.len() {
                    send_error(w, "file count mismatch");
                    return Err(BootstrapErr::Protocol);
                }
                break;
            }
            Tag::Error => {
                let e: ErrorMsg = hc_core::wire::strict_json_from_slice(&body)?;
                tracing::error!(peer_msg = %hc_core::safe_diagnostic_text(&e.msg), "bootstrap authority aborted");
                return Err(BootstrapErr::PeerAbort);
            }
            _ => {
                send_error(w, "unexpected frame");
                return Err(BootstrapErr::Protocol);
            }
        }
    }

    Ok(Received {
        dek,
        files,
        vault_id: offer.vault_id,
    })
}

/// The recovery passphrase `--recovery-passphrase` enrolls on B: a masked, confirmed prompt on a
/// terminal, and stdin otherwise, so automation never puts this KEK in argv or the environment
/// where any same-uid process reads it back out.
fn read_new_passphrase() -> Result<Zeroizing<String>, crate::PassphraseErr> {
    if std::io::stdin().is_terminal() {
        return crate::prompt_new_passphrase();
    }
    let piped = passphrase_from_reader(std::io::stdin().lock())?;
    crate::check_new_passphrase(&piped)?;
    Ok(piped)
}

/// One passphrase, bounded, minus a single trailing newline. An empty read is a refusal, never
/// an empty passphrase.
fn passphrase_from_reader<R: Read>(reader: R) -> Result<Zeroizing<String>, crate::PassphraseErr> {
    let bytes = Zeroizing::new(hc_core::read_bounded(reader, MAX_PIPED_PASSPHRASE_BYTES)?);
    let text = std::str::from_utf8(&bytes)?;
    let text = match text.strip_suffix('\n') {
        Some(stripped) => stripped.strip_suffix('\r').unwrap_or(stripped),
        None => text,
    };
    if text.is_empty() {
        return Err(crate::PassphraseErr::Empty);
    }
    Ok(Zeroizing::new(text.to_string()))
}

/// Write each staged keystore file into `store` (atomically), build a FRESH keyring
/// enrolling the DEK under B's own SE (plus an optional recovery passphrase), and
/// save it to `<store>/keyring.json`. A's `keyring.json` is intentionally NOT copied.
fn persist<F>(
    store: &Path,
    received: &Received,
    passphrase: Option<Zeroizing<String>>,
    enroll_se: F,
) -> Result<(), BootstrapErr>
where
    F: Fn(&Dek) -> Result<hc_core::keyring::Enrollment, BootstrapErr>,
{
    // Bootstrap is a provisioning operation, not a merge. Refuse a mixed store before enrolling
    // or prompting on this machine; otherwise an unlisted local ciphertext could survive beside
    // a keyring for a different DEK and fail only when somebody later tries to use it.
    preflight_empty_destination(store)?;

    // Build the keyring FIRST: enrolling under B's Secure Enclave prompts Touch ID and can
    // fail, so do it before writing any keystore file — a failure then leaves the store
    // untouched rather than orphaning unkeyed ciphertext.
    let mut keyring = Keyring::new();
    keyring.vault_id = received.vault_id.clone();
    keyring.add(enroll_se(&received.dek)?);
    if let Some(passphrase) = passphrase {
        keyring.add(
            PassphraseUnlocker::from_secret(passphrase)
                .enroll("bootstrap recovery", &received.dek)?,
        );
    }

    // Every destination is created exclusively. A pre-existing key, policy, keyring or symlink
    // is never replaced, even if another process races this bootstrap after its preflight.
    std::fs::create_dir_all(store)?;
    write_store_and_keyring(store, received, &keyring)
}

fn preflight_empty_destination(store: &Path) -> Result<(), BootstrapErr> {
    match std::fs::symlink_metadata(store) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(BootstrapErr::DestinationExists {
                path: store.to_path_buf(),
            })
        }
    }
    if let Some(entry) = std::fs::read_dir(store)?.next() {
        return Err(BootstrapErr::DestinationExists {
            path: entry?.path(),
        });
    }
    Ok(())
}

fn destination_absent(path: &Path) -> Result<(), BootstrapErr> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(BootstrapErr::DestinationExists {
            path: path.to_path_buf(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Validate the complete set before any write, then create every file atomically and
/// exclusively. On failure, remove only paths this invocation successfully created.
struct CreatedFile {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl CreatedFile {
    fn record(path: PathBuf) -> Result<Self, std::io::Error> {
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "new bootstrap destination is not a regular file",
            ));
        }
        Ok(Self {
            path,
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    fn remove(self) {
        let ours = std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_file()
                && metadata.dev() == self.dev
                && metadata.ino() == self.ino
        });
        if ours {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

fn write_store_and_keyring(
    store: &Path,
    received: &Received,
    keyring: &Keyring,
) -> Result<(), BootstrapErr> {
    if received.files.len() > MAX_BOOTSTRAP_FILES {
        return Err(BootstrapErr::TooManyFiles {
            found: received.files.len(),
            max: MAX_BOOTSTRAP_FILES,
        });
    }
    let mut names = Vec::with_capacity(received.files.len());
    let mut total = 0u64;
    for (name, body) in &received.files {
        validate_store_file(name, body, Some(&received.dek))?;
        add_total(&mut total, body.len() as u64)?;
        names.push(name.clone());
    }
    names.sort();
    check_manifest(&names)?;
    let mut created_policies = false;
    if names.iter().any(|name| name.starts_with("policies/")) {
        let policies = store.join("policies");
        match std::fs::symlink_metadata(&policies) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => return Err(BootstrapErr::DestinationExists { path: policies }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&policies)?;
                created_policies = true;
            }
            Err(e) => return Err(e.into()),
        }
    }
    for name in &names {
        destination_absent(&store.join(name))?;
    }
    let keyring_path = store.join(KEYRING_FILE);
    destination_absent(&keyring_path)?;

    keyring.validate()?;
    let keyring_json = serde_json::to_vec_pretty(keyring)?;
    let mut created: Vec<CreatedFile> = Vec::with_capacity(received.files.len() + 1);
    let result: Result<(), BootstrapErr> = (|| {
        for (name, body) in &received.files {
            let path = store.join(name);
            atomic_write_new(&path, body)?;
            created.push(CreatedFile::record(path)?);
        }
        atomic_write_new(&keyring_path, &keyring_json)?;
        created.push(CreatedFile::record(keyring_path)?);
        enforce_store_modes(store)?;
        Ok(())
    })();
    if let Err(error) = result {
        for path in created.into_iter().rev() {
            path.remove();
        }
        if created_policies {
            let _ = std::fs::remove_dir(store.join("policies"));
        }
        return Err(error);
    }
    Ok(())
}

/// Result produced by the thread that exclusively owns and reaps the SSH child. The child joins
/// the watchdog sentinel's live process group, so the sentinel keeps that group identity reserved
/// while this thread waits and can terminate every descendant without a reused numeric PID.
enum ManagedExit {
    Exited(std::io::Result<ExitStatus>),
    TimedOut,
    Aborted,
}

#[derive(Clone, Copy)]
enum ManagerControl {
    Complete,
    Abort,
}

fn kill_child_group(child: &mut Child, watchdog: &mut hc_core::ParentDeathGuard) {
    let _ = watchdog.terminate_group();
    let _ = child.kill();
    let _ = child.wait();
}

fn manage_ssh_child(
    mut child: Child,
    mut watchdog: hc_core::ParentDeathGuard,
    control: mpsc::Receiver<ManagerControl>,
    timeout: Duration,
) -> ManagedExit {
    let started = Instant::now();
    let mut completed = false;
    let mut status = None;
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(exit)) => status = Some(exit),
                Err(error) => {
                    kill_child_group(&mut child, &mut watchdog);
                    return ManagedExit::Exited(Err(error));
                }
                Ok(None) => {}
            }
        }
        if completed {
            if let Some(status) = status.take() {
                // The protocol owner has closed its pipe handles and the direct ssh process has
                // exited. No descendant is still part of the operation; kill any process-group
                // residue so inherited stderr/stdout descriptors cannot block cleanup.
                kill_child_group(&mut child, &mut watchdog);
                return ManagedExit::Exited(Ok(status));
            }
        }

        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            kill_child_group(&mut child, &mut watchdog);
            return ManagedExit::TimedOut;
        }
        match control.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(ManagerControl::Complete) => completed = true,
            Ok(ManagerControl::Abort) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                kill_child_group(&mut child, &mut watchdog);
                return ManagedExit::Aborted;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

/// Render remote diagnostics without allowing control bytes, newlines, or terminal escape
/// sequences into the operator's terminal. The retained stderr itself is already bounded.
fn ssh_stderr_for_log(bytes: &[u8]) -> String {
    hc_core::safe_diagnostic(bytes)
}

/// Owns the SSH manager and stderr-drain threads. Dropping it on any early protocol or
/// persistence error aborts the complete child process group and reaps it.
struct BootstrapSsh {
    control: Option<mpsc::Sender<ManagerControl>>,
    manager: Option<JoinHandle<ManagedExit>>,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl BootstrapSsh {
    fn spawn(target: &str) -> Result<(Self, ChildStdin, ChildStdout), BootstrapErr> {
        let mut command = Command::new("/usr/bin/ssh");
        // `ssh` resolves `~` from the passwd database, not $HOME.
        command.env_clear();
        if let Some(agent) = std::env::var_os("SSH_AUTH_SOCK") {
            command.env("SSH_AUTH_SOCK", agent);
        }
        command
            .arg("-T")
            .arg("-F")
            .arg("/dev/null")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg("UserKnownHostsFile=~/.ssh/known_hosts")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ClearAllForwardings=yes")
            .arg("-o")
            .arg("PermitLocalCommand=no")
            .arg("-o")
            .arg("ForkAfterAuthentication=no")
            .arg("-o")
            .arg("ControlMaster=no")
            .arg("-o")
            .arg("ControlPath=none")
            .arg("-o")
            .arg("ConnectionAttempts=1")
            .arg("-o")
            .arg(format!("ConnectTimeout={SSH_CONNECT_TIMEOUT_SECS}"))
            .arg("-o")
            .arg(format!("ServerAliveInterval={SSH_ALIVE_INTERVAL_SECS}"))
            .arg("-o")
            .arg(format!("ServerAliveCountMax={SSH_ALIVE_COUNT_MAX}"))
            .arg(target)
            .arg("hot_cheese")
            .arg("bootstrap-serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut watchdog = hc_core::ParentDeathGuard::start().map_err(|_| BootstrapErr::Ssh)?;
        watchdog.configure(&mut command);
        let mut child = command.spawn().map_err(|_| BootstrapErr::Ssh)?;
        let Some(stdin) = child.stdin.take() else {
            kill_child_group(&mut child, &mut watchdog);
            return Err(BootstrapErr::Ssh);
        };
        let Some(stdout) = child.stdout.take() else {
            kill_child_group(&mut child, &mut watchdog);
            return Err(BootstrapErr::Ssh);
        };
        let Some(stderr) = child.stderr.take() else {
            kill_child_group(&mut child, &mut watchdog);
            return Err(BootstrapErr::Ssh);
        };

        let (control_tx, control_rx) = mpsc::channel();
        let manager = std::thread::spawn(move || {
            manage_ssh_child(child, watchdog, control_rx, BOOTSTRAP_TIMEOUT)
        });
        let stderr =
            std::thread::spawn(move || hc_core::read_bounded(stderr, MAX_SSH_STDERR_BYTES));
        Ok((
            Self {
                control: Some(control_tx),
                manager: Some(manager),
                stderr: Some(stderr),
            },
            stdin,
            stdout,
        ))
    }

    fn take_stderr(&mut self) -> Result<Vec<u8>, BootstrapErr> {
        let Some(reader) = self.stderr.take() else {
            return Err(BootstrapErr::Ssh);
        };
        reader.join().map_err(|_| BootstrapErr::Ssh)?.map_err(|error| {
            tracing::error!(%error, max = MAX_SSH_STDERR_BYTES, "ssh stderr exceeded its boundary");
            BootstrapErr::Ssh
        })
    }

    fn wait(mut self) -> Result<ExitStatus, BootstrapErr> {
        if let Some(control) = self.control.take() {
            let _ = control.send(ManagerControl::Complete);
        }
        let Some(manager) = self.manager.take() else {
            return Err(BootstrapErr::Ssh);
        };
        let outcome = manager.join().map_err(|_| BootstrapErr::Ssh)?;
        let stderr = self.take_stderr()?;
        if !stderr.is_empty() {
            tracing::warn!(stderr = %ssh_stderr_for_log(&stderr), "ssh bootstrap diagnostic");
        }
        match outcome {
            ManagedExit::Exited(status) => Ok(status.map_err(|_| BootstrapErr::Ssh)?),
            ManagedExit::TimedOut => Err(BootstrapErr::SshTimeout),
            ManagedExit::Aborted => Err(BootstrapErr::Ssh),
        }
    }
}

impl Drop for BootstrapSsh {
    fn drop(&mut self) {
        if let Some(control) = self.control.take() {
            let _ = control.send(ManagerControl::Abort);
        }
        if let Some(manager) = self.manager.take() {
            let _ = manager.join();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
    }
}

/// Run on the NEW machine: spawn `ssh <target> hot_cheese bootstrap-serve`, recover
/// the DEK (ECIES-sealed to this machine's SE key), receive the store, re-wrap the
/// DEK under this machine's own keyring, and persist everything.
pub fn bootstrap_from(target: &str, recovery_passphrase: bool) -> Result<(), BootstrapErr> {
    hc_core::config::validate_ssh_target(target)?;
    let config = Config::load()?;
    let store: PathBuf = config.store_path();
    preflight_empty_destination(&store)?;

    // Collected before the ritual opens, so a mistyped confirmation costs nobody a Touch ID.
    let passphrase = if recovery_passphrase {
        Some(read_new_passphrase()?)
    } else {
        None
    };

    // B's Secure Enclave key (created idempotently); its public point is the HELLO id.
    secure_enclave::ensure_se_key(LABEL)?;
    let b_se_pub = secure_enclave::se_public_key(LABEL)?;
    tracing::warn!(
        recipient_key_sha256 = %hex::encode(&Sha256::digest(&b_se_pub)[..8]),
        "bootstrap recipient key; compare this fingerprint with the authority's Touch ID prompt"
    );
    let my_key = EcdhKey::SecureEnclave(LABEL.to_string());

    // Keep both pipe halves alive for the whole ritual: we must send ACK back to A
    // over `w` only AFTER B has safely persisted the DEK.
    let (ssh, mut w, mut rd) = BootstrapSsh::spawn(target)?;
    let received = client(&mut rd, &mut w, &my_key, &b_se_pub)?;

    // Re-wrap under B's own SE and persist BEFORE acknowledging, so we only ACK once
    // the DEK is durably stored on B. The DEK is zeroized when `received` drops.
    match persist(&store, &received, passphrase, |dek| {
        Ok(SecureEnclaveUnlocker::new(LABEL).enroll("bootstrap (this machine SE)", dek)?)
    }) {
        Ok(()) => {
            write_frame(&mut w, Tag::Ack, &Ack { ok: true })?;
        }
        Err(e) => {
            send_error(&mut w, "failed to persist on new machine");
            return Err(e);
        }
    }
    drop(received); // DEK zeroized here
    drop(w); // close B→A so A's serve() reader unblocks after its ACK read
    drop(rd);

    let status = ssh.wait()?;
    if !status.success() {
        return Err(BootstrapErr::Ssh);
    }
    tracing::info!("bootstrap complete: DEK re-wrapped under this machine's keyring");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A software ECDH key plus its 65-byte SEC1 public point, standing in for a
    /// Secure Enclave endpoint in tests.
    fn sw_key() -> (EcdhKey, Vec<u8>) {
        let sk = SecretKey::random(&mut rand::rngs::OsRng);
        let pubp = sk.public_key().to_sec1_bytes().into_vec();
        (EcdhKey::Software(sk), pubp)
    }

    #[test]
    fn frame_roundtrips_tag_and_payload() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, Tag::Done, &Done { count: 7 }).unwrap();
        let mut cur = Cursor::new(buf);
        let (tag, body) = read_frame(&mut cur).unwrap();
        assert_eq!(tag, Tag::Done);
        let d: Done = serde_json::from_slice(&body).unwrap();
        assert_eq!(d.count, 7);
    }

    #[test]
    fn authority_rejects_an_invalid_curve_point_before_authorization() {
        // Correct SEC1 length and tag are not enough: this is not a valid P-256 point. The
        // public HELLO preflight must reject it and return an ERROR frame before callers unlock
        // the authority keyring or present a Touch ID sheet.
        let mut inbound = Vec::new();
        write_frame(
            &mut inbound,
            Tag::Hello,
            &Hello {
                proto: PROTO,
                b_se_pub: vec![0x04; SEC1_LEN],
            },
        )
        .unwrap();
        let mut outbound = Vec::new();
        assert!(matches!(
            receive_hello(&mut Cursor::new(inbound), &mut outbound),
            Err(BootstrapErr::P256(_))
        ));
        let (tag, _) = read_frame(&mut Cursor::new(outbound)).unwrap();
        assert_eq!(tag, Tag::Error);
    }

    #[test]
    fn ssh_manager_enforces_deadline_and_reaps_group() {
        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let watchdog = hc_core::ParentDeathGuard::start().unwrap();
        watchdog.configure(&mut command);
        let child = command.spawn().unwrap();
        let (_control_tx, control_rx) = mpsc::channel();
        let started = Instant::now();
        assert!(matches!(
            manage_ssh_child(child, watchdog, control_rx, Duration::from_millis(100)),
            ManagedExit::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn ssh_manager_keeps_deadline_after_direct_child_exits() {
        let mut command = Command::new("sh");
        command
            .args(["-c", "(sleep 30) & exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let watchdog = hc_core::ParentDeathGuard::start().unwrap();
        watchdog.configure(&mut command);
        let child = command.spawn().unwrap();
        let (_control_tx, control_rx) = mpsc::channel();
        let started = Instant::now();
        assert!(matches!(
            manage_ssh_child(child, watchdog, control_rx, Duration::from_millis(100)),
            ManagedExit::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn ssh_diagnostics_cannot_emit_terminal_controls() {
        let rendered = ssh_stderr_for_log(b"line one\n\x1b[31mred\x07");
        assert_eq!(rendered, "line one\\n\\u{1b}[31mred\\u{7}");
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\u{1b}'));
    }

    #[test]
    fn ecies_core_recovers_dek_across_software_keys() {
        // Simulate A sealing to B and B opening, without any transport.
        let (b_key, b_pub) = sw_key();
        let dek = Dek::random();

        let eph = EcdhKey::Software(SecretKey::random(&mut rand::rngs::OsRng));
        let eph_pub = eph.public_sec1().unwrap();
        let a_shared = eph.ecdh(&b_pub).unwrap();
        let a_wrap = derive_wrap_key(&a_shared).unwrap();
        let aad = bind_aad(&b_pub, &eph_pub);
        let enc = envelope::seal(&a_wrap, &aad, dek.expose()).unwrap();

        let b_shared = b_key.ecdh(&eph_pub).unwrap();
        let b_wrap = derive_wrap_key(&b_shared).unwrap();
        assert_eq!(a_wrap.as_slice(), b_wrap.as_slice(), "ECDH must agree");
        let got = envelope::open(&b_wrap, &aad, &enc).unwrap();
        assert_eq!(got.as_slice(), dek.expose());
    }

    #[test]
    fn wrong_aad_breaks_open() {
        // An OFFER bound to a different B (anti-relay) must not open.
        let (b_key, b_pub) = sw_key();
        let (_other_key, other_pub) = sw_key();
        let dek = Dek::random();

        let eph = EcdhKey::Software(SecretKey::random(&mut rand::rngs::OsRng));
        let eph_pub = eph.public_sec1().unwrap();
        let a_shared = eph.ecdh(&b_pub).unwrap();
        let a_wrap = derive_wrap_key(&a_shared).unwrap();
        let enc = envelope::seal(&a_wrap, &bind_aad(&b_pub, &eph_pub), dek.expose()).unwrap();

        let b_shared = b_key.ecdh(&eph_pub).unwrap();
        let b_wrap = derive_wrap_key(&b_shared).unwrap();
        // B uses the wrong identity in the AAD → AEAD rejects.
        assert!(envelope::open(&b_wrap, &bind_aad(&other_pub, &eph_pub), &enc).is_err());
    }

    /// A piped passphrase is the secret minus exactly one trailing newline, and nothing at all
    /// is a refusal rather than an empty KEK.
    #[test]
    fn piped_passphrase_keeps_the_secret_and_refuses_an_empty_pipe() {
        assert_eq!(
            passphrase_from_reader(&b"correct horse battery staple\n"[..])
                .unwrap()
                .as_str(),
            "correct horse battery staple"
        );
        assert_eq!(
            passphrase_from_reader(&b"no newline at all"[..])
                .unwrap()
                .as_str(),
            "no newline at all"
        );
        assert_eq!(
            passphrase_from_reader(&b"kept blank line\n\n"[..])
                .unwrap()
                .as_str(),
            "kept blank line\n"
        );
        assert_eq!(
            passphrase_from_reader(&b"written on windows\r\n"[..])
                .unwrap()
                .as_str(),
            "written on windows"
        );
        assert!(matches!(
            passphrase_from_reader(&b""[..]),
            Err(crate::PassphraseErr::Empty)
        ));
        assert!(matches!(
            passphrase_from_reader(&b"\n"[..]),
            Err(crate::PassphraseErr::Empty)
        ));
        let oversize = vec![b'x'; MAX_PIPED_PASSPHRASE_BYTES as usize + 1];
        assert!(matches!(
            passphrase_from_reader(&oversize[..]),
            Err(crate::PassphraseErr::StdIo(_))
        ));
    }

    #[test]
    fn bootstrap_paths_cannot_escape_the_store() {
        for name in [
            "../ESCAPE",
            "policies/../../ESCAPE.toml",
            "/tmp/ESCAPE",
            "policies/KEY/extra.toml",
            "keyring.json",
        ] {
            assert!(
                matches!(store_file(name), Err(BootstrapErr::UnsafeFileName { .. })),
                "accepted hostile bootstrap path {name}"
            );
        }
    }

    #[test]
    fn bootstrap_persistence_never_replaces_an_existing_key() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_bootstrap_existing_{}_{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("EVM_HOT"), b"keep-me").unwrap();

        let dek = Dek::random();
        let body = envelope::seal_keystore("EVM_HOT", &dek, envelope::KeyUse::SignOnly, &[7u8; 32])
            .unwrap();
        let mut keyring = Keyring::new();
        keyring.add(
            PassphraseUnlocker::new("test recovery phrase".to_string())
                .enroll("recovery", &dek)
                .unwrap(),
        );
        let received = Received {
            dek,
            files: vec![("EVM_HOT".to_string(), body)],
            vault_id: None,
        };

        assert!(matches!(
            write_store_and_keyring(&dir, &received, &keyring),
            Err(BootstrapErr::DestinationExists { .. })
        ));
        assert_eq!(std::fs::read(dir.join("EVM_HOT")).unwrap(), b"keep-me");
        assert!(!dir.join(KEYRING_FILE).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bootstrap_refuses_a_nonempty_destination_before_enrollment() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_bootstrap_nonempty_{}_{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("unlisted-ciphertext"), b"leave-me-alone").unwrap();

        let enrollment_attempted = AtomicBool::new(false);
        let received = Received {
            dek: Dek::random(),
            files: Vec::new(),
            vault_id: None,
        };
        let error = persist(&dir, &received, None, |_| {
            enrollment_attempted.store(true, Ordering::SeqCst);
            Err(BootstrapErr::Protocol)
        })
        .unwrap_err();

        assert!(matches!(error, BootstrapErr::DestinationExists { .. }));
        assert!(!enrollment_attempted.load(Ordering::SeqCst));
        assert_eq!(
            std::fs::read(dir.join("unlisted-ciphertext")).unwrap(),
            b"leave-me-alone"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Error rollback owns the inode it created, not an indefinitely reusable pathname. A
    /// same-uid replacement survives, while the unchanged create-only output is removed.
    #[test]
    fn bootstrap_rollback_removes_only_the_created_inode() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_bootstrap_rollback_{}_{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let unchanged = dir.join("unchanged");
        std::fs::write(&unchanged, b"created").unwrap();
        CreatedFile::record(unchanged.clone()).unwrap().remove();
        assert!(!unchanged.exists());

        let replaced = dir.join("replaced");
        let original = std::fs::File::create(&replaced).unwrap();
        let created = CreatedFile::record(replaced.clone()).unwrap();
        std::fs::remove_file(&replaced).unwrap();
        std::fs::write(&replaced, b"replacement").unwrap();
        created.remove();
        assert_eq!(std::fs::read(&replaced).unwrap(), b"replacement");
        drop(original);

        std::fs::remove_dir_all(dir).unwrap();
    }

    /// FULL handshake over two `std::io::pipe()` channels, A and B in separate
    /// threads, using SOFTWARE P-256 keys for both endpoints. Asserts B recovers
    /// A's exact DEK and vault id, and that every shipped FILE byte transfers intact.
    #[test]
    fn full_handshake_over_pipes_transfers_dek_and_files() {
        // A's store with two real envelope keystores and one validated policy.
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_bootstrap_test_{}_{}",
            std::process::id(),
            now_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dek = Dek::random();
        let file_a = envelope::seal_keystore(
            "SOLANA_MAIN",
            &dek,
            envelope::KeyUse::SignOnly,
            &[0xABu8; 64],
        )
        .unwrap();
        let file_b =
            envelope::seal_keystore("EVM_HOT", &dek, envelope::KeyUse::SignOnly, &[0xCDu8; 32])
                .unwrap();
        std::fs::write(dir.join("SOLANA_MAIN"), &file_a).unwrap();
        std::fs::write(dir.join("EVM_HOT"), &file_b).unwrap();
        std::fs::create_dir(dir.join("policies")).unwrap();
        let policy = b"safe = \"0x1111111111111111111111111111111111111111\"\nchain_id = 1\n";
        std::fs::write(dir.join("policies/EVM_HOT.toml"), policy).unwrap();
        // A decoy that must NOT be shipped.
        std::fs::write(dir.join("ignored.hctmp"), b"temp").unwrap();
        std::fs::write(dir.join("keyring.json"), b"{}").unwrap();

        let dek_expected = *dek.expose();

        // B's stand-in SE key.
        let (b_key, b_pub) = sw_key();

        // Two pipes: a2b carries A→B, b2a carries B→A.
        let (a2b_r, a2b_w) = std::io::pipe().unwrap();
        let (b2a_r, b2a_w) = std::io::pipe().unwrap();

        let vault = VaultId::random();
        let vault_expected = vault.clone();
        let dir_a = dir.clone();
        let authority = std::thread::spawn(move || {
            let mut r = b2a_r;
            let mut w = a2b_w;
            serve(&mut r, &mut w, &dek, &dir_a, Some(&vault))
        });

        // Client side (this thread).
        let mut r = a2b_r;
        let mut w = b2a_w;
        let received = client(&mut r, &mut w, &b_key, &b_pub).expect("client handshake");

        // B sends ACK so A's serve() returns Ok.
        write_frame(&mut w, Tag::Ack, &Ack { ok: true }).unwrap();
        drop(w); // close B→A so A's reader can't block

        let serve_res = authority.join().expect("authority thread panicked");
        assert!(serve_res.is_ok(), "serve failed: {:?}", serve_res.err());

        // B recovered A's exact DEK, and joins A's vault so both back up to one subtree.
        assert_eq!(received.dek.expose(), &dek_expected);
        assert_eq!(received.vault_id, Some(vault_expected));

        // Exactly the two real keystore files transferred, byte-for-byte.
        let mut got: std::collections::BTreeMap<String, Vec<u8>> =
            received.files.into_iter().collect();
        assert_eq!(
            got.remove("SOLANA_MAIN").as_deref(),
            Some(file_a.as_slice())
        );
        assert_eq!(got.remove("EVM_HOT").as_deref(), Some(file_b.as_slice()));
        assert_eq!(
            got.remove("policies/EVM_HOT.toml").as_deref(),
            Some(policy.as_slice())
        );
        assert!(
            got.is_empty(),
            "unexpected extra files shipped: {:?}",
            got.keys()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn now_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }
}
