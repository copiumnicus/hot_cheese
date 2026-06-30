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
use std::time::{SystemTime, UNIX_EPOCH};

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
