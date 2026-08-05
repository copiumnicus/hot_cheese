//! Envelope encryption primitives.
//!
//! A 32-byte [`Dek`] (Data Encryption Key) encrypts every keystore file with
//! XChaCha20-Poly1305. The same [`seal`]/[`open`] primitive is reused to wrap
//! the DEK under a KEK (Key Encryption Key) inside the keyring. XChaCha20's
//! 192-bit nonce makes per-write random nonces safe without a counter.
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use err_mac::create_err_with_impls;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

const CIPHER: &str = "xchacha20poly1305";
const NONCE_LEN: usize = 24;

/// 32-byte Data Encryption Key. Encrypts every keystore file; only ever persisted
/// in wrapped form (see the keyring). Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek([u8; 32]);

impl Dek {
    /// Fresh random DEK from the OS CSPRNG.
    pub fn random() -> Self {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    /// Borrow the raw key bytes (for AEAD keying). Never log or persist these.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// On-disk AEAD container — one per keystore file, and one per wrapped-DEK record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncFile {
    pub v: u32,
    pub cipher: String,
    #[serde(with = "hex::serde")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub ct: Vec<u8>,
}

create_err_with_impls!(
    #[derive(Debug)]
    pub EnvErr,
    Aead,
    BadNonce,
    UnsupportedCipher,
    UnsupportedVersion,
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error)
    ;
);

/// AEAD-seal `plaintext` under a raw 32-byte key, binding `aad`.
pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<EncFile, EnvErr> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| EnvErr::Aead)?;
    Ok(EncFile {
        v: 1,
        cipher: CIPHER.to_string(),
        nonce: nonce.to_vec(),
        ct,
    })
}

/// AEAD-open a container produced by [`seal`] with the same key and `aad`.
pub fn open(key: &[u8; 32], aad: &[u8], f: &EncFile) -> Result<Vec<u8>, EnvErr> {
    if f.v != 1 {
        return Err(EnvErr::UnsupportedVersion);
    }
    if f.cipher != CIPHER {
        return Err(EnvErr::UnsupportedCipher);
    }
    if f.nonce.len() != NONCE_LEN {
        return Err(EnvErr::BadNonce);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(&f.nonce), Payload { msg: &f.ct, aad })
        .map_err(|_| EnvErr::Aead)
}

/// Encrypt `plaintext` under the DEK and write `<dir>/<name>` atomically. AAD = name,
/// so a copied/renamed file fails to open.
pub fn encrypt_file(dir: &Path, name: &str, dek: &Dek, plaintext: &[u8]) -> Result<(), EnvErr> {
    let f = seal(dek.expose(), name.as_bytes(), plaintext)?;
    let json = serde_json::to_vec(&f)?;
    atomic_write(&dir.join(name), &json)
}

/// Read and decrypt a keystore file written by [`encrypt_file`]. AAD = name.
pub fn decrypt_file(path: &Path, name: &str, dek: &Dek) -> Result<Vec<u8>, EnvErr> {
    let bytes = fs::read(path)?;
    let f: EncFile = serde_json::from_slice(&bytes)?;
    open(dek.expose(), name.as_bytes(), &f)
}

/// Write `bytes` to `path` as an owner-only (0600) file, creating the parent dir if needed
/// and forcing the mode on a pre-existing file too. For key material: the Secure Enclave
/// blob, the demo software key, and the TLS private key.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(bytes)
}

/// Write `bytes` to `path` via temp-file + rename so a crash can't leave a partial file.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), EnvErr> {
    let tmp = path.with_extension("hctmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_binds_key_and_aad() {
        let key = [7u8; 32];
        let f = seal(&key, b"MY_KEY", b"secret-bytes").unwrap();
        assert_eq!(open(&key, b"MY_KEY", &f).unwrap(), b"secret-bytes");
        // wrong AAD (file renamed) is rejected
        assert!(open(&key, b"OTHER", &f).is_err());
        // wrong key is rejected
        assert!(open(&[8u8; 32], b"MY_KEY", &f).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = [1u8; 32];
        let mut f = seal(&key, b"k", b"abcdef").unwrap();
        f.ct[0] ^= 0xff;
        assert!(open(&key, b"k", &f).is_err());
    }

    #[test]
    fn file_roundtrip_preserves_solana_sized_secret() {
        let dir = std::env::temp_dir().join("hot_cheese_env_test");
        let _ = std::fs::create_dir_all(&dir);
        let dek = Dek::from_bytes([3u8; 32]);
        let secret = vec![9u8; 64]; // Solana keypairs are 64 bytes
        encrypt_file(&dir, "SOLANA_X", &dek, &secret).unwrap();
        let got = decrypt_file(&dir.join("SOLANA_X"), "SOLANA_X", &dek).unwrap();
        assert_eq!(got, secret);
        let _ = std::fs::remove_file(dir.join("SOLANA_X"));
    }
}
