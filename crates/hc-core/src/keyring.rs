//! The `keyring.json` envelope: the DEK wrapped once per enrolled KEK.
//!
//! Each [`Enrollment`] is an independent way to unwrap the same DEK (a Secure
//! Enclave key, or a recovery passphrase). The DEK itself never appears here in
//! plaintext, so `keyring.json` is safe to back up to untrusted storage. It lives
//! in the store dir so it travels with the encrypted keystores.
use crate::crypto::envelope::{atomic_write, EncFile, EnvErr};
use err_mac::create_err_with_impls;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// The keyring's file name inside the store dir.
pub const KEYRING_FILE: &str = "keyring.json";
const KEYRING_VERSION: u32 = 1;
pub const MAX_KEYRING_BYTES: u64 = 256 * 1024;
const MAX_ENROLLMENTS: usize = 32;
const ENROLLMENT_ID_BYTES: usize = 16;
const MAX_LABEL_CHARS: usize = 64;
const PASSPHRASE_KDF: &str = "argon2id";
const PASSPHRASE_SALT_BYTES: usize = 16;
const PASSPHRASE_MIN_M_COST: u32 = 65_536;
const PASSPHRASE_MAX_M_COST: u32 = 131_072;
const PASSPHRASE_MIN_T_COST: u32 = 3;
const PASSPHRASE_MAX_T_COST: u32 = 5;
const PASSPHRASE_MIN_P_COST: u32 = 1;
const PASSPHRASE_MAX_P_COST: u32 = 4;
const P256_PUBLIC_KEY_BYTES: usize = 65;
const WRAPPED_DEK_BYTES: usize = 32 + 16;

/// Rendered prefix of a [`VaultId`].
const VAULT_PREFIX: &str = "v_";

create_err_with_impls!(
    #[derive(Debug)]
    pub VaultIdErr,
    Hex(hex::FromHexError)
    ;
    MissingPrefix { value: String }
);

impl std::error::Error for VaultIdErr {}

/// Backup namespace of one install: a random 16-byte label rendered `v_<32 hex>`.
///
/// Cleartext in `keyring.json`, so a push never has to unlock anything. Two installs
/// with different DEKs get different ids and therefore different remote subtrees.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VaultId([u8; 16]);

impl VaultId {
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }
}

impl std::fmt::Display for VaultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", VAULT_PREFIX, hex::encode(self.0))
    }
}

impl std::fmt::Debug for VaultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl FromStr for VaultId {
    type Err = VaultIdErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s
            .strip_prefix(VAULT_PREFIX)
            .ok_or_else(|| VaultIdErr::MissingPrefix {
                value: s.to_string(),
            })?;
        let mut out = [0u8; 16];
        hex::decode_to_slice(digits, &mut out)?;
        Ok(Self(out))
    }
}

impl TryFrom<String> for VaultId {
    type Error = VaultIdErr;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<VaultId> for String {
    fn from(v: VaultId) -> Self {
        v.to_string()
    }
}

/// Per-enrollment KEK parameters. The `kind` tag selects the unlock mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollParams {
    /// Secure Enclave: KEK = HKDF(ECDH(SE_priv, eph_pub)). `se_pub` identifies the
    /// device key; `eph_pub` is the stored ephemeral public point ECDH'd against.
    SecureEnclave {
        #[serde(with = "hex::serde")]
        se_pub: Vec<u8>,
        #[serde(with = "hex::serde")]
        eph_pub: Vec<u8>,
    },
    /// Recovery passphrase: KEK = Argon2id(passphrase, salt).
    Passphrase {
        kdf: String,
        #[serde(with = "hex::serde")]
        salt: Vec<u8>,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    },
}

/// One way to unwrap the DEK.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub id: String,
    pub label: String,
    pub created_at: u64,
    pub params: EnrollParams,
    pub wrapped_dek: EncFile,
}

/// The envelope file: every enrollment wraps the same DEK.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keyring {
    pub v: u32,
    /// Backup namespace; absent in keyrings written before vault ids existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<VaultId>,
    pub enrollments: Vec<Enrollment>,
}

create_err_with_impls!(
    #[derive(Debug)]
    pub KeyringErr,
    NoEnrollments,
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error),
    Envelope(EnvErr)
    ;
    UnsupportedVersion { found: u32 },
    TooLarge { size: u64, max: u64 },
    TooManyEnrollments { found: usize, max: usize },
    InvalidEnrollmentId { id: String },
    DuplicateEnrollmentId { id: String },
    InvalidLabel { id: String, label: String },
    UnsupportedKdf { id: String, kdf: String },
    InvalidPassphraseParams { id: String, salt_len: usize, m_cost: u32, t_cost: u32, p_cost: u32 },
    InvalidSecureEnclavePoint { id: String, field: String, len: usize },
    InvalidWrappedDek { id: String, len: usize }
);

impl Default for Keyring {
    fn default() -> Self {
        Self {
            v: KEYRING_VERSION,
            vault_id: None,
            enrollments: Vec::new(),
        }
    }
}

impl Keyring {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn load(path: &Path) -> Result<Self, KeyringErr> {
        let mut bytes = Vec::new();
        crate::open_regular_file(path)?
            .take(MAX_KEYRING_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_KEYRING_BYTES {
            return Err(KeyringErr::TooLarge {
                size: bytes.len() as u64,
                max: MAX_KEYRING_BYTES,
            });
        }
        let keyring: Self = crate::wire::strict_json_from_slice(&bytes)?;
        keyring.validate()?;
        Ok(keyring)
    }
    pub fn save(&self, path: &Path) -> Result<(), KeyringErr> {
        self.validate()?;
        let json = serde_json::to_vec_pretty(self)?;
        atomic_write(path, &json)?;
        Ok(())
    }
    pub fn add(&mut self, e: Enrollment) {
        self.enrollments.push(e);
    }
    /// True if at least one passphrase enrollment exists (the recovery backstop and
    /// the only cross-machine restore path, since SE keys are device-bound).
    pub fn has_passphrase(&self) -> bool {
        self.enrollments
            .iter()
            .any(|e| matches!(e.params, EnrollParams::Passphrase { .. }))
    }

    pub fn validate(&self) -> Result<(), KeyringErr> {
        if self.v != KEYRING_VERSION {
            return Err(KeyringErr::UnsupportedVersion { found: self.v });
        }
        if self.enrollments.is_empty() {
            return Err(KeyringErr::NoEnrollments);
        }
        if self.enrollments.len() > MAX_ENROLLMENTS {
            return Err(KeyringErr::TooManyEnrollments {
                found: self.enrollments.len(),
                max: MAX_ENROLLMENTS,
            });
        }
        for (at, enrollment) in self.enrollments.iter().enumerate() {
            let id_ok = enrollment.id.strip_prefix("enr_").is_some_and(|hex| {
                hex.len() == ENROLLMENT_ID_BYTES * 2 && hex::decode(hex).is_ok()
            });
            if !id_ok {
                return Err(KeyringErr::InvalidEnrollmentId {
                    id: enrollment.id.clone(),
                });
            }
            if self.enrollments[at + 1..]
                .iter()
                .any(|other| other.id == enrollment.id)
            {
                return Err(KeyringErr::DuplicateEnrollmentId {
                    id: enrollment.id.clone(),
                });
            }
            let label_ok = !enrollment.label.is_empty()
                && enrollment.label.chars().count() <= MAX_LABEL_CHARS
                && enrollment
                    .label
                    .chars()
                    .all(|c| c.is_ascii_graphic() || c == ' ');
            if !label_ok {
                return Err(KeyringErr::InvalidLabel {
                    id: enrollment.id.clone(),
                    label: enrollment.label.clone(),
                });
            }
            enrollment.wrapped_dek.validate()?;
            if enrollment.wrapped_dek.ct.len() != WRAPPED_DEK_BYTES {
                return Err(KeyringErr::InvalidWrappedDek {
                    id: enrollment.id.clone(),
                    len: enrollment.wrapped_dek.ct.len(),
                });
            }
            match &enrollment.params {
                EnrollParams::Passphrase {
                    kdf,
                    salt,
                    m_cost,
                    t_cost,
                    p_cost,
                } => {
                    if kdf != PASSPHRASE_KDF {
                        return Err(KeyringErr::UnsupportedKdf {
                            id: enrollment.id.clone(),
                            kdf: kdf.clone(),
                        });
                    }
                    let costs_ok = (PASSPHRASE_MIN_M_COST..=PASSPHRASE_MAX_M_COST)
                        .contains(m_cost)
                        && (PASSPHRASE_MIN_T_COST..=PASSPHRASE_MAX_T_COST).contains(t_cost)
                        && (PASSPHRASE_MIN_P_COST..=PASSPHRASE_MAX_P_COST).contains(p_cost);
                    if salt.len() != PASSPHRASE_SALT_BYTES || !costs_ok {
                        return Err(KeyringErr::InvalidPassphraseParams {
                            id: enrollment.id.clone(),
                            salt_len: salt.len(),
                            m_cost: *m_cost,
                            t_cost: *t_cost,
                            p_cost: *p_cost,
                        });
                    }
                }
                EnrollParams::SecureEnclave { se_pub, eph_pub } => {
                    for (field, point) in [("se_pub", se_pub), ("eph_pub", eph_pub)] {
                        let valid = point.len() == P256_PUBLIC_KEY_BYTES
                            && point.first() == Some(&0x04)
                            && p256::PublicKey::from_sec1_bytes(point).is_ok();
                        if !valid {
                            return Err(KeyringErr::InvalidSecureEnclavePoint {
                                id: enrollment.id.clone(),
                                field: field.to_string(),
                                len: point.len(),
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Random enrollment id (`enr_<hex>`). Also used as AEAD AAD to bind a wrapped DEK
/// to its record, preventing record-swapping within a keyring.
pub(crate) fn new_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    format!("enr_{}", hex::encode(b))
}

/// Seconds since the Unix epoch (0 on clock error — only used as a display label).
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `keyring.json` written before vault ids must keep loading, report no vault,
    /// and never gain one just by being read and written back.
    #[test]
    fn keyring_written_before_vault_ids_stays_unnamespaced() {
        const LEGACY: &str = r#"{
          "v": 1,
          "enrollments": [
            {
              "id": "enr_0f1e2d3c4b5a69788796a5b4c3d2e1f0",
              "label": "recovery",
              "created_at": 1750000000,
              "params": {
                "kind": "passphrase",
                "kdf": "argon2id",
                "salt": "00112233445566778899aabbccddeeff",
                "m_cost": 65536,
                "t_cost": 3,
                "p_cost": 1
              },
              "wrapped_dek": {
                "v": 1,
                "cipher": "chacha20poly1305",
                "nonce": "000102030405060708090a0b",
                "ct": "aabbccddeeff"
              }
            }
          ]
        }"#;
        let keyring: Keyring = serde_json::from_str(LEGACY).expect("legacy keyring parses");
        assert!(keyring.vault_id.is_none());
        assert!(keyring.has_passphrase());
        let written = serde_json::to_string(&keyring).expect("re-serialize");
        assert!(
            !written.contains("vault_id"),
            "load must not mint a vault id"
        );
    }

    fn passphrase_keyring(m_cost: u32, t_cost: u32, p_cost: u32) -> Keyring {
        Keyring {
            v: KEYRING_VERSION,
            vault_id: None,
            enrollments: vec![Enrollment {
                id: "enr_0f1e2d3c4b5a69788796a5b4c3d2e1f0".to_string(),
                label: "recovery".to_string(),
                created_at: 1_750_000_000,
                params: EnrollParams::Passphrase {
                    kdf: PASSPHRASE_KDF.to_string(),
                    salt: vec![0u8; PASSPHRASE_SALT_BYTES],
                    m_cost,
                    t_cost,
                    p_cost,
                },
                wrapped_dek: crate::crypto::envelope::seal(&[0u8; 32], b"aad", &[0u8; 32])
                    .expect("seal a 32-byte DEK"),
            }],
        }
    }

    /// Argon2id costs are an acceptance window, not an equality: raising them later must not
    /// brick a vault, while anything below the compiled-in floor stays a rejected downgrade and
    /// an absurd cost stays a rejected memory bomb.
    #[test]
    fn argon2_costs_accept_at_or_above_the_floor_and_reject_outside_the_window() {
        assert!(passphrase_keyring(
            PASSPHRASE_MIN_M_COST,
            PASSPHRASE_MIN_T_COST,
            PASSPHRASE_MIN_P_COST
        )
        .validate()
        .is_ok());
        assert!(passphrase_keyring(
            PASSPHRASE_MAX_M_COST,
            PASSPHRASE_MIN_T_COST + 1,
            PASSPHRASE_MIN_P_COST + 1
        )
        .validate()
        .is_ok());

        for (m_cost, t_cost, p_cost) in [
            (PASSPHRASE_MIN_M_COST - 1, PASSPHRASE_MIN_T_COST, PASSPHRASE_MIN_P_COST),
            (PASSPHRASE_MIN_M_COST, PASSPHRASE_MIN_T_COST - 1, PASSPHRASE_MIN_P_COST),
            (PASSPHRASE_MIN_M_COST, PASSPHRASE_MIN_T_COST, PASSPHRASE_MIN_P_COST - 1),
            (PASSPHRASE_MAX_M_COST + 1, PASSPHRASE_MIN_T_COST, PASSPHRASE_MIN_P_COST),
            (PASSPHRASE_MIN_M_COST, PASSPHRASE_MAX_T_COST + 1, PASSPHRASE_MIN_P_COST),
            (PASSPHRASE_MIN_M_COST, PASSPHRASE_MIN_T_COST, PASSPHRASE_MAX_P_COST + 1),
            (u32::MAX, u32::MAX, u32::MAX),
        ] {
            assert!(
                matches!(
                    passphrase_keyring(m_cost, t_cost, p_cost).validate(),
                    Err(KeyringErr::InvalidPassphraseParams { .. })
                ),
                "accepted out-of-window costs {m_cost}/{t_cost}/{p_cost}"
            );
        }
    }

    /// The `v_<32 hex>` rendering is the only accepted form: a bare hex id, a wrong
    /// prefix, or the wrong number of digits must all be rejected.
    #[test]
    fn vault_id_parses_only_prefixed_16_byte_hex() {
        let id = VaultId::random();
        let text = id.to_string();
        assert_eq!(text.len(), 34);
        assert_eq!(text.parse::<VaultId>().expect("round trip"), id);
        assert!(text[2..].parse::<VaultId>().is_err());
        assert!("vault_0f1e2d3c4b5a69788796a5b4c3d2e1f0"
            .parse::<VaultId>()
            .is_err());
        assert!("v_0f1e".parse::<VaultId>().is_err());
        assert!("v_zz1e2d3c4b5a69788796a5b4c3d2e1f0"
            .parse::<VaultId>()
            .is_err());
    }
}
