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
use zeroize::{Zeroize, Zeroizing};

// Argon2id parameters for an interactive secret (OWASP-aligned: 64 MiB, t=3, p=1).
const M_COST: u32 = 65536;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
const SALT_LEN: usize = 16;
/// Current single-factor baseline. Existing shorter enrollments remain unlockable; this applies
/// only when creating a new recovery route.
pub const MIN_NEW_PASSPHRASE_CHARS: usize = 20;
/// Entropy floor beneath the length: a repeated character or a tiny alphabet is refused.
pub const MIN_NEW_PASSPHRASE_DISTINCT_CHARS: usize = 8;
/// Generous enough for generated word lists while bounding an accidentally pasted document.
pub const MAX_NEW_PASSPHRASE_BYTES: usize = 1024;

pub struct PassphraseUnlocker {
    passphrase: Zeroizing<String>,
}

impl PassphraseUnlocker {
    pub fn new(passphrase: String) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase),
        }
    }

    /// Take ownership of a prompt buffer that was protected from the instant it was read. This
    /// checks nothing, so a caller that treats a prompt as accepted must [`Unlocker::unlock`] it.
    pub fn from_secret(passphrase: Zeroizing<String>) -> Self {
        Self { passphrase }
    }

    fn validate_new(&self) -> Result<(), UnlockErr> {
        let chars = self.passphrase.chars().count();
        if chars < MIN_NEW_PASSPHRASE_CHARS {
            return Err(UnlockErr::PassphraseTooShort {
                found: chars,
                min: MIN_NEW_PASSPHRASE_CHARS,
            });
        }
        let bytes = self.passphrase.len();
        if bytes > MAX_NEW_PASSPHRASE_BYTES {
            return Err(UnlockErr::PassphraseTooLong {
                found: bytes,
                max: MAX_NEW_PASSPHRASE_BYTES,
            });
        }
        let mut seen = Zeroizing::new([0u32; MIN_NEW_PASSPHRASE_DISTINCT_CHARS]);
        let mut distinct = 0usize;
        for c in self.passphrase.chars() {
            let code = u32::from(c);
            if seen[..distinct].contains(&code) {
                continue;
            }
            seen[distinct] = code;
            distinct += 1;
            if distinct == MIN_NEW_PASSPHRASE_DISTINCT_CHARS {
                break;
            }
        }
        if distinct < MIN_NEW_PASSPHRASE_DISTINCT_CHARS {
            return Err(UnlockErr::PassphraseTooSimple {
                distinct,
                min: MIN_NEW_PASSPHRASE_DISTINCT_CHARS,
            });
        }
        Ok(())
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
                let kek = derive_kek(self.passphrase.as_bytes(), salt, *m_cost, *t_cost, *p_cost)?;
                let Ok(mut pt) = open(&kek, e.id.as_bytes(), &e.wrapped_dek) else {
                    continue;
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
        }
        if saw_passphrase {
            Err(UnlockErr::WrongPassphrase)
        } else {
            Err(UnlockErr::NoMatchingEnrollment)
        }
    }
}

impl PassphraseUnlocker {
    /// Wrap an existing DEK under this passphrase, producing an enrollment record to add to the
    /// keyring.
    pub fn enroll(&self, label: &str, dek: &Dek) -> Result<Enrollment, UnlockErr> {
        self.validate_new()?;
        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let kek = derive_kek(self.passphrase.as_bytes(), &salt, M_COST, T_COST, P_COST)?;
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
        let good = PassphraseUnlocker::new("right but deliberately long".to_string());
        let mut kr = Keyring::new();
        kr.add(good.enroll("recovery", &dek).unwrap());
        let bad = PassphraseUnlocker::new("wrong but deliberately long".to_string());
        assert!(matches!(
            bad.unlock("test", &kr, None),
            Err(UnlockErr::WrongPassphrase)
        ));
    }

    #[test]
    fn two_passphrase_enrollments_both_recover_same_dek() {
        let dek = Dek::random();
        let a = PassphraseUnlocker::new("alpha recovery phrase".to_string());
        let b = PassphraseUnlocker::new("bravo recovery phrase".to_string());
        let mut kr = Keyring::new();
        kr.add(a.enroll("a", &dek).unwrap());
        kr.add(b.enroll("b", &dek).unwrap());
        assert_eq!(a.unlock("t", &kr, None).unwrap().expose(), dek.expose());
        assert_eq!(b.unlock("t", &kr, None).unwrap().expose(), dek.expose());
    }

    #[test]
    fn new_recovery_passphrases_have_length_boundaries() {
        let dek = Dek::random();
        assert!(matches!(
            PassphraseUnlocker::new("too short".to_string()).enroll("recovery", &dek),
            Err(UnlockErr::PassphraseTooShort {
                min: MIN_NEW_PASSPHRASE_CHARS,
                ..
            })
        ));
        assert!(PassphraseUnlocker::new("abcdefghij".repeat(2))
            .enroll("recovery", &dek)
            .is_ok());
        assert!(matches!(
            PassphraseUnlocker::new("x".repeat(MAX_NEW_PASSPHRASE_BYTES + 1))
                .enroll("recovery", &dek),
            Err(UnlockErr::PassphraseTooLong {
                max: MAX_NEW_PASSPHRASE_BYTES,
                ..
            })
        ));
    }

    /// A long-but-repetitive passphrase is the offline attacker's easiest target, so the length
    /// floor alone must not admit it: distinct characters are counted independently.
    #[test]
    fn new_recovery_passphrases_need_distinct_characters() {
        let dek = Dek::random();
        assert!(matches!(
            PassphraseUnlocker::new("x".repeat(MIN_NEW_PASSPHRASE_CHARS)).enroll("recovery", &dek),
            Err(UnlockErr::PassphraseTooSimple {
                distinct: 1,
                min: MIN_NEW_PASSPHRASE_DISTINCT_CHARS
            })
        ));
        assert!(matches!(
            PassphraseUnlocker::new("abababab".repeat(4)).enroll("recovery", &dek),
            Err(UnlockErr::PassphraseTooSimple { distinct: 2, .. })
        ));
        let one_short = "abcdefg".repeat(4);
        assert!(one_short.chars().count() > MIN_NEW_PASSPHRASE_CHARS);
        assert!(matches!(
            PassphraseUnlocker::new(one_short).enroll("recovery", &dek),
            Err(UnlockErr::PassphraseTooSimple {
                distinct: 7,
                min: MIN_NEW_PASSPHRASE_DISTINCT_CHARS
            })
        ));
        assert!(PassphraseUnlocker::new("abcdefgh".repeat(3))
            .enroll("recovery", &dek)
            .is_ok());
    }

    /// Unlocking must never re-apply the new-passphrase rules: an enrollment written before those
    /// rules existed is the only copy of that DEK on a fresh machine, and refusing it at the
    /// prompt would lock its owner out for good.
    #[test]
    fn a_passphrase_below_the_new_minimum_still_unlocks_an_older_enrollment() {
        let dek = Dek::random();
        let legacy = "short pass";
        assert!(legacy.chars().count() < MIN_NEW_PASSPHRASE_CHARS);
        let unlocker = PassphraseUnlocker::new(legacy.to_string());
        assert!(matches!(
            unlocker.enroll("recovery", &dek),
            Err(UnlockErr::PassphraseTooShort { .. })
        ));

        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let kek =
            derive_kek(legacy.as_bytes(), &salt, M_COST, T_COST, P_COST).expect("derive the KEK");
        let id = new_id();
        let wrapped_dek = seal(&kek, id.as_bytes(), dek.expose()).expect("wrap the DEK");
        let mut kr = Keyring::new();
        kr.add(Enrollment {
            id,
            label: "recovery".to_string(),
            created_at: now_secs(),
            params: EnrollParams::Passphrase {
                kdf: "argon2id".to_string(),
                salt,
                m_cost: M_COST,
                t_cost: T_COST,
                p_cost: P_COST,
            },
            wrapped_dek,
        });
        assert_eq!(
            unlocker
                .unlock("t", &kr, None)
                .expect("the older enrollment still opens")
                .expose(),
            dek.expose()
        );
    }

    /// The costs this file writes must land inside the window `Keyring::validate` accepts, or
    /// every freshly enrolled recovery route would fail to load.
    #[test]
    fn a_fresh_enrollment_satisfies_the_keyring_validator() {
        let dek = Dek::random();
        let mut kr = Keyring::new();
        kr.add(
            PassphraseUnlocker::new("correct horse battery staple".to_string())
                .enroll("recovery", &dek)
                .expect("enroll"),
        );
        kr.validate()
            .expect("a freshly written enrollment validates");
    }
}
