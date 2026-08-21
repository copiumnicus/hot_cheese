//! Secure Enclave (Touch ID) KEK.
//!
//! The KEK is derived from an ECDH between this machine's Secure Enclave P-256 key
//! and a per-enrollment ephemeral P-256 key:
//!
//! ```text
//! shared = ECDH(se, eph)                              // raw P-256 X-coordinate, 32 B
//! kek    = HKDF-SHA256(ikm = shared,
//!                      salt = enrollment_id_bytes,
//!                      info = b"hotcheese/se-kek/v1") // 32 B wrap key
//! wrapped_dek = XChaCha20-Poly1305-seal(kek, aad = enrollment_id, plaintext = dek)
//! ```
//!
//! ## Why ECDH is computed two different ways
//!
//! Standard ECDH is symmetric: `ECDH(eph_priv, se_pub) == ECDH(se_priv, eph_pub)`.
//!
//! * **enroll** runs entirely on the host with the `p256` crate
//!   (`ECDH(eph_priv, se_pub)`). It only needs the SE *public* key — the proven one
//!   [`crate::mac::secure_enclave::ensure_se_key`] hands [`enroll_secure_enclave`] — so it
//!   triggers **no Touch ID** and can re-wrap a DEK at any time.
//! * **unlock** runs the mirror image inside the Secure Enclave
//!   (`ECDH(se_priv, eph_pub)`), which requires a live biometric. That biometric is the
//!   per-request gate: no Touch ID → no ECDH → no KEK → no DEK.
//!
//! Both paths must produce the identical 32 bytes or the DEK will not unwrap. The
//! cross-encoding equivalence is asserted host-side by [`tests`] below and discussed in
//! [`crate::mac::secure_enclave`].
//!
//! ## Salt choice
//!
//! The enrollment id doubles as the HKDF salt. This binds the derived KEK to the
//! specific record (alongside its use as the AEAD AAD) without having to widen the
//! shared [`crate::keyring::EnrollParams::SecureEnclave`] on-disk struct.
use super::{UnlockErr, Unlocker};
use crate::crypto::envelope::{self, Dek};
use crate::keyring::{self, EnrollParams, Enrollment, Keyring};
use crate::mac::secure_enclave;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Domain-separation string for the SE KEK derivation. Bump the version suffix if the
/// derivation ever changes so old and new wrappings can't be confused.
const HKDF_INFO: &[u8] = b"hotcheese/se-kek/v1";

pub struct SecureEnclaveUnlocker {
    /// Keychain label of this machine's SE key.
    label: String,
}

impl SecureEnclaveUnlocker {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }
}

/// Classify a Secure Enclave failure. Every one of them keeps the recovery route, because the
/// same DEK is wrapped under the recovery enrollment and `--unlock passphrase` re-enrolls
/// nothing; a key that is present but unproven or unreadable additionally refuses to point at a
/// re-enrollment, which is the step that would wrap this vault's DEK under a planted key.
fn se_failure(e: secure_enclave::SeErr) -> UnlockErr {
    use secure_enclave::SeErr;
    match e {
        SeErr::KeyNotFound => UnlockErr::SeKeyUnavailableTryUnlockPassphrase,
        source @ (SeErr::BadBlob
        | SeErr::UnrecordedEnclaveKeyAtKeyPath { .. }
        | SeErr::BlobNotOwnerOnly { .. }
        | SeErr::BlobNotAKeyFile { .. }) => {
            tracing::error!(
                ?source,
                "a Secure Enclave key is present at this machine's key path but this vault \
                 cannot prove it is the one it recorded; refusing to unlock and refusing to \
                 recommend re-enrollment, which would wrap the DEK under it. Your keys are still \
                 there: re-run with `--unlock passphrase`"
            );
            UnlockErr::SeKeyPresentButUnprovenTryUnlockPassphraseDoNotReenroll { source }
        }
        source => {
            tracing::error!(
                ?source,
                "this machine's Secure Enclave would not use the key it has, which an added or \
                 removed fingerprint alone is enough to cause; the DEK is unaffected, so re-run \
                 with `--unlock passphrase`"
            );
            UnlockErr::SeKeyUnusableTryUnlockPassphrase { source }
        }
    }
}

/// HKDF-SHA256 the 32-byte ECDH shared secret into a 32-byte wrap key, salted by the
/// enrollment id. The output is zeroized on drop; the caller must not log it.
fn derive_kek(shared: &[u8; 32], enrollment_id: &str) -> Result<Zeroizing<[u8; 32]>, UnlockErr> {
    let hk = Hkdf::<Sha256>::new(Some(enrollment_id.as_bytes()), shared);
    let mut kek = Zeroizing::new([0u8; 32]);
    // `expand` only fails if the requested length exceeds 255*HashLen; 32 never does.
    hk.expand(HKDF_INFO, kek.as_mut())
        .map_err(|_| UnlockErr::BadDekLen)?;
    Ok(kek)
}

impl Unlocker for SecureEnclaveUnlocker {
    /// Unwrap the DEK via the Secure Enclave. Triggers Touch ID (the per-request gate).
    fn unlock(
        &self,
        reason: &str,
        keyring: &Keyring,
        auth: Option<&crate::mac::local_auth::LaContext>,
    ) -> Result<Dek, UnlockErr> {
        use zeroize::Zeroize;

        // Use the first Secure Enclave enrollment whose `se_pub` matches this machine's
        // SE key. Other machines' enrollments (or stale ones after key rotation) are
        // skipped so we never prompt for a key we can't satisfy.
        let our_pub = secure_enclave::se_public_key(&self.label).map_err(se_failure)?;
        for e in &keyring.enrollments {
            let EnrollParams::SecureEnclave { se_pub, eph_pub } = &e.params else {
                continue;
            };
            if se_pub != &our_pub {
                continue;
            }
            tracing::debug!(reason = %reason, enrollment = %e.id, "Secure Enclave unlock");
            // ECDH(se_priv, eph_pub) inside the enclave — prompts Touch ID (or reuses `auth`).
            let shared =
                secure_enclave::se_ecdh(&self.label, eph_pub, auth, reason).map_err(se_failure)?;
            let kek = derive_kek(&shared, &e.id)?;
            let mut pt = match envelope::open(&kek, e.id.as_bytes(), &e.wrapped_dek) {
                Ok(pt) => pt,
                Err(envelope::EnvErr::Aead) => continue,
                Err(e) => return Err(e.into()),
            };
            if pt.len() != 32 {
                pt.zeroize();
                return Err(UnlockErr::BadDekLen);
            }
            let mut dek_bytes = [0u8; 32];
            dek_bytes.copy_from_slice(&pt);
            pt.zeroize();
            let dek = Dek::from_bytes(dek_bytes);
            dek_bytes.zeroize();
            return Ok(dek);
        }
        Err(UnlockErr::NoMatchingEnrollment)
    }
}

/// Wrap an existing DEK under a fresh ephemeral-key ECDH against `proven`, the enclave key
/// [`secure_enclave::ensure_se_key`] checked. The proof is the only way in, so the record names
/// the key that was checked and no re-read of the blob path can substitute another. Host-only
/// ECDH, so **no Touch ID** is required to enroll.
pub fn enroll_secure_enclave(
    label: &str,
    dek: &Dek,
    proven: &secure_enclave::ProvenEnclaveKey,
) -> Result<Enrollment, UnlockErr> {
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;
    use zeroize::Zeroize;

    let se_pub = proven.public_key().to_vec();
    let se_pub_key = p256::PublicKey::from_sec1_bytes(&se_pub)
        .map_err(|_| UnlockErr::Se(secure_enclave::SeErr::BadPubKeyLen(se_pub.len())))?;

    let eph_secret = EphemeralSecret::random(&mut OsRng);
    let eph_point = eph_secret.public_key().to_encoded_point(false);
    let eph_pub: Vec<u8> = eph_point.as_bytes().to_vec();

    let shared = eph_secret.diffie_hellman(&se_pub_key);
    let mut ikm = [0u8; 32];
    ikm.copy_from_slice(shared.raw_secret_bytes().as_slice());

    let id = keyring::new_id();
    let kek = derive_kek(&ikm, &id)?;
    ikm.zeroize();

    let wrapped_dek = envelope::seal(&kek, id.as_bytes(), dek.expose())?;

    Ok(Enrollment {
        id,
        label: label.into(),
        created_at: keyring::now_secs(),
        params: EnrollParams::SecureEnclave { se_pub, eph_pub },
        wrapped_dek,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole design rests on standard ECDH being symmetric *and* both crates
    /// agreeing on the raw-X encoding. This proves the host half end-to-end: derive a
    /// KEK from `ECDH(A_priv, B_pub)`, wrap a DEK, then independently re-derive the KEK
    /// from `ECDH(B_priv, A_pub)` (the SE's role) and recover the DEK. If the SE's
    /// `ECDHKeyExchangeStandard` matches p256's `raw_secret_bytes` (it does — both are
    /// the big-endian X-coordinate), the real unlock behaves exactly like the `b`-side
    /// here.
    #[test]
    fn ecdh_symmetric_and_dek_roundtrips_through_kek() {
        use p256::ecdh::{diffie_hellman, EphemeralSecret};
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use rand::rngs::OsRng;

        // "a" plays the host ephemeral key at enroll; "b" plays the SE device key.
        let a = EphemeralSecret::random(&mut OsRng);
        let b_secret = p256::SecretKey::random(&mut OsRng);
        let b_pub = b_secret.public_key();
        let a_pub = a.public_key();

        // enroll side: ECDH(a_priv, b_pub)
        let shared_enroll = a.diffie_hellman(&b_pub);
        // unlock side: ECDH(b_priv, a_pub) — what the Secure Enclave computes.
        let shared_unlock = diffie_hellman(b_secret.to_nonzero_scalar(), a_pub.as_affine());

        assert_eq!(
            shared_enroll.raw_secret_bytes().as_slice(),
            shared_unlock.raw_secret_bytes().as_slice(),
            "standard ECDH must be symmetric and raw-X encoded identically"
        );

        // Round-trip an actual DEK through the derived KEK, mirroring enroll→unlock.
        let id = "enr_testsalt_0123456789abcdef";
        let dek = Dek::from_bytes([42u8; 32]);

        let mut ikm_e = [0u8; 32];
        ikm_e.copy_from_slice(shared_enroll.raw_secret_bytes().as_slice());
        let kek_enroll = derive_kek(&ikm_e, id).unwrap();
        let wrapped = envelope::seal(&kek_enroll, id.as_bytes(), dek.expose()).unwrap();

        let mut ikm_u = [0u8; 32];
        ikm_u.copy_from_slice(shared_unlock.raw_secret_bytes().as_slice());
        let kek_unlock = derive_kek(&ikm_u, id).unwrap();
        let recovered = envelope::open(&kek_unlock, id.as_bytes(), &wrapped).unwrap();

        assert_eq!(recovered.as_slice(), dek.expose());

        // The ephemeral public key encodes as a 65-byte uncompressed SEC1 point, which
        // is exactly what `se_ecdh` expects as its peer input.
        let eph_pub = a_pub.to_encoded_point(false);
        assert_eq!(eph_pub.as_bytes().len(), 65);
        assert_eq!(eph_pub.as_bytes()[0], 0x04);
    }

    /// Every enclave failure the unlock path can raise names the recovery route, because the DEK
    /// is intact behind the recovery enrollment in all of them and an operator told only "ECDH
    /// failed" can reasonably conclude their keys are gone. The variant name IS the message here
    /// (`Display` is `Debug`), so the route has to survive in the name.
    #[test]
    fn every_enclave_unlock_failure_carries_the_passphrase_route() {
        use secure_enclave::SeErr;
        use std::path::PathBuf;

        let path = PathBuf::from("/nonexistent/se_kek_hotcheese.blob");
        let every_failure = [
            SeErr::Unavailable,
            SeErr::ScreenLocked,
            SeErr::KeyNotFound,
            SeErr::BadPubKeyLen(3),
            SeErr::BadPeerPoint,
            SeErr::SoftwareKey,
            SeErr::TouchIdDenied,
            SeErr::Ecdh,
            SeErr::GrantSign,
            SeErr::GrantSignatureInvalid,
            SeErr::BadBlob,
            SeErr::BufferTooSmall,
            SeErr::Shim(-99),
            SeErr::StdIo(std::io::Error::other("read")),
            SeErr::Create { code: -25308 },
            SeErr::AccessControl { code: -50 },
            SeErr::BadSignatureLen { len: 7 },
            SeErr::GrantReuseWindowExceeded {
                elapsed_ms: 40_000,
                window_ms: 10_000,
            },
            SeErr::InvalidLabel {
                label: "a_b".into(),
            },
            SeErr::UnrecordedEnclaveKeyAtKeyPath {
                path: path.clone(),
                found: "0123456789abcdef".into(),
                recorded: Vec::new(),
            },
            SeErr::EnclaveKeyPathOccupied { path: path.clone() },
            SeErr::BlobNotOwnerOnly { path: path.clone() },
            SeErr::BlobNotAKeyFile { path: path.clone() },
            SeErr::NoEnclaveKeyToDiscard { path: path.clone() },
            SeErr::RecordedEnclaveKeyNotDiscardable {
                path: path.clone(),
                se_key: "0123456789abcdef".into(),
            },
            SeErr::EnclaveKeyChangedUnderDiscard {
                path,
                shown: "0123456789abcdef".into(),
                found: "fedcba9876543210".into(),
            },
            SeErr::DiscardNotConfirmed {
                required: secure_enclave::DISCARD_UNRECORDED_KEY_PHRASE,
            },
        ];
        for failure in every_failure {
            let shown = se_failure(failure).to_string();
            assert!(
                shown.contains("TryUnlockPassphrase"),
                "an enclave failure that names no way back to the keys: {shown}"
            );
        }
    }

    /// A key that is present but unproven may be a planted one, so its refusal must keep saying
    /// so: re-enrolling is the step that would wrap this vault's DEK under it, and that is the
    /// one route no failure may point at.
    #[test]
    fn a_present_but_unproven_enclave_key_still_refuses_to_recommend_re_enrollment() {
        use secure_enclave::SeErr;
        use std::path::PathBuf;

        let path = PathBuf::from("/nonexistent/se_kek_hotcheese.blob");
        let present_but_unproven = [
            SeErr::BadBlob,
            SeErr::UnrecordedEnclaveKeyAtKeyPath {
                path: path.clone(),
                found: "0123456789abcdef".into(),
                recorded: vec!["fedcba9876543210".into()],
            },
            SeErr::BlobNotOwnerOnly { path: path.clone() },
            SeErr::BlobNotAKeyFile { path },
        ];
        for planted in present_but_unproven {
            let mapped = se_failure(planted);
            assert!(
                matches!(
                    &mapped,
                    UnlockErr::SeKeyPresentButUnprovenTryUnlockPassphraseDoNotReenroll { .. }
                ),
                "{mapped:?}"
            );
            assert!(mapped.to_string().contains("DoNotReenroll"), "{mapped:?}");
        }

        assert!(matches!(
            se_failure(SeErr::KeyNotFound),
            UnlockErr::SeKeyUnavailableTryUnlockPassphrase
        ));
        assert!(matches!(
            se_failure(SeErr::TouchIdDenied),
            UnlockErr::SeKeyUnusableTryUnlockPassphrase {
                source: SeErr::TouchIdDenied
            }
        ));
    }

    /// HKDF must depend on the salt (enrollment id): the same shared secret under two
    /// different ids yields different KEKs, so a wrapped DEK can't be replayed under a
    /// swapped record.
    #[test]
    fn kek_is_salted_by_enrollment_id() {
        let shared = [9u8; 32];
        let k1 = derive_kek(&shared, "enr_aaaaaaaaaaaaaaaa").unwrap();
        let k2 = derive_kek(&shared, "enr_bbbbbbbbbbbbbbbb").unwrap();
        assert_ne!(&*k1, &*k2);
        // And it's deterministic for a fixed (shared, id).
        let k1b = derive_kek(&shared, "enr_aaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(&*k1, &*k1b);
    }
}
