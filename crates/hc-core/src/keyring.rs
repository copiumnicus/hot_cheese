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
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// The keyring's file name inside the store dir.
pub const KEYRING_FILE: &str = "keyring.json";

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
#[serde(tag = "kind", rename_all = "snake_case")]
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
pub struct Enrollment {
    pub id: String,
    pub label: String,
    pub created_at: u64,
    pub params: EnrollParams,
    pub wrapped_dek: EncFile,
}

/// The envelope file: every enrollment wraps the same DEK.
#[derive(Debug, Serialize, Deserialize)]
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
);

impl Default for Keyring {
    fn default() -> Self {
        Self {
            v: 1,
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
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
    pub fn save(&self, path: &Path) -> Result<(), KeyringErr> {
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
