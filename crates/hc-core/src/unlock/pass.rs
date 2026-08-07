//! Recovery-passphrase KEK (Argon2id).
//!
//! This is the survivable backstop: it needs no Secure Enclave hardware, so it works on
//! any machine and is the only way to restore an envelope onto a fresh machine (Secure
//! Enclave keys are device-bound).
use super::{UnlockErr, Unlocker};
use crate::crypto::envelope::{open, seal, Dek};
use crate::keyring::{new_id, now_secs, EnrollParams, Enrollment, Keyring};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

// Argon2id parameters for an interactive secret (OWASP-aligned: 64 MiB, t=3, p=1).
const M_COST: u32 = 65536;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
const SALT_LEN: usize = 16;

pub struct PassphraseUnlocker {
    passphrase: Zeroizing<Vec<u8>>,
}

impl PassphraseUnlocker {
    pub fn new(passphrase: String) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase.into_bytes()),
        }
    }
}

/// Derive a 32-byte KEK from the passphrase via Argon2id. Output is zeroized on drop.
fn derive_kek(
    passphrase: &[u8],
    salt: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> Result<Zeroizing<[u8; 32]>, UnlockErr> {
    let params = Params::new(m, t, p, Some(32))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(passphrase, salt, &mut out[..])?;
    Ok(out)
}

impl Unlocker for PassphraseUnlocker {
    fn unlock(
        &self,
        _reason: &str,
        keyring: &Keyring,
        _auth: Option<&crate::mac::local_auth::LaContext>,
    ) -> Result<Dek, UnlockErr> {
        let mut saw_passphrase = false;
        for e in &keyring.enrollments {
            if let EnrollParams::Passphrase {
                salt,
                m_cost,
                t_cost,
                p_cost,
                ..
            } = &e.params
            {
                saw_passphrase = true;
                let kek = derive_kek(&self.passphrase, salt, *m_cost, *t_cost, *p_cost)?;
                // A failed open just means this record isn't ours — try the next one.
                if let Ok(bytes) = open(&kek, e.id.as_bytes(), &e.wrapped_dek) {
                    let arr: [u8; 32] = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| UnlockErr::BadDekLen)?;
                    return Ok(Dek::from_bytes(arr));
                }
            }
        }
        if saw_passphrase {
            Err(UnlockErr::WrongPassphrase)
        } else {
            Err(UnlockErr::NoMatchingEnrollment)
        }
    }

    fn enroll(&self, label: &str, dek: &Dek) -> Result<Enrollment, UnlockErr> {
        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let kek = derive_kek(&self.passphrase, &salt, M_COST, T_COST, P_COST)?;
        let id = new_id();
        let wrapped = seal(&kek, id.as_bytes(), dek.expose())?;
        Ok(Enrollment {
            id,
            label: label.to_string(),
            created_at: now_secs(),
            params: EnrollParams::Passphrase {
                kdf: "argon2id".to_string(),
                salt,
                m_cost: M_COST,
                t_cost: T_COST,
                p_cost: P_COST,
            },
            wrapped_dek: wrapped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::Keyring;

    #[test]
    fn enroll_then_unlock_recovers_dek() {
        let dek = Dek::random();
        let u = PassphraseUnlocker::new("correct horse battery staple".to_string());
        let mut kr = Keyring::new();
        kr.add(u.enroll("recovery", &dek).unwrap());
        let got = u.unlock("test", &kr, None).unwrap();
        assert_eq!(got.expose(), dek.expose());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dek = Dek::random();
        let good = PassphraseUnlocker::new("right".to_string());
        let mut kr = Keyring::new();
        kr.add(good.enroll("recovery", &dek).unwrap());
        let bad = PassphraseUnlocker::new("wrong".to_string());
        assert!(matches!(
            bad.unlock("test", &kr, None),
            Err(UnlockErr::WrongPassphrase)
        ));
    }

    #[test]
    fn two_passphrase_enrollments_both_recover_same_dek() {
        let dek = Dek::random();
        let a = PassphraseUnlocker::new("alpha".to_string());
        let b = PassphraseUnlocker::new("bravo".to_string());
        let mut kr = Keyring::new();
        kr.add(a.enroll("a", &dek).unwrap());
        kr.add(b.enroll("b", &dek).unwrap());
        assert_eq!(a.unlock("t", &kr, None).unwrap().expose(), dek.expose());
        assert_eq!(b.unlock("t", &kr, None).unwrap().expose(), dek.expose());
    }
}
