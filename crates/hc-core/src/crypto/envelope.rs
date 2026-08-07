//! Envelope encryption primitives.
//!
//! A 32-byte [`Dek`] (Data Encryption Key) encrypts every keystore file with
//! XChaCha20-Poly1305. The same [`seal`]/[`open`] primitive is reused to wrap
//! the DEK under a KEK (Key Encryption Key) inside the keyring. XChaCha20's
//! 192-bit nonce makes per-write random nonces safe without a counter.
//!
//! A keystore file is a [`SealedKeystore`]: a cleartext [`KeyUse`] header over an
//! [`EncFile`] whose AAD binds that same header, so rewriting the header on disk
//! only makes the file undecryptable. Only a [`KeyUse::Shareable`] file yields the
//! [`ExportPermit`] the export path demands.
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use err_mac::create_err_with_impls;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

const CIPHER: &str = "xchacha20poly1305";
const NONCE_LEN: usize = 24;
/// Container version written by [`seal_keystore`].
const KEYSTORE_V2: u32 = 2;
/// Domain separator opening every v2 keystore AAD.
const KEYSTORE_AAD_DOMAIN: &[u8] = b"hotcheese/keystore/v2";

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

/// On-disk AEAD container — one per keystore body, and one per wrapped-DEK record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncFile {
    pub v: u32,
    pub cipher: String,
    #[serde(with = "hex::serde")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub ct: Vec<u8>,
}

/// Whether a key may ever leave the daemon. Declared at creation and unchangeable
/// afterwards in the loosening direction, because loosening would require exporting the key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyUse {
    /// May be handed to a client over `/read`.
    Shareable,
    /// May only be used inside the daemon; no path can export it.
    #[default]
    SignOnly,
}

impl KeyUse {
    /// Both uses, tightest first.
    pub const ALL: [KeyUse; 2] = [KeyUse::SignOnly, KeyUse::Shareable];

    /// The label `list` prints, identical to the serde representation.
    pub fn label(self) -> &'static str {
        match self {
            KeyUse::Shareable => "shareable",
            KeyUse::SignOnly => "sign_only",
        }
    }

    /// AAD tag byte, never 0 so a zeroed byte is not a valid use.
    fn tag(self) -> u8 {
        match self {
            KeyUse::SignOnly => 1,
            KeyUse::Shareable => 2,
        }
    }
}

impl fmt::Display for KeyUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A v2 keystore file: the use declared in cleartext, and bound into the body's AAD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKeystore {
    /// Container version, always [`KEYSTORE_V2`].
    pub v: u32,
    /// Whether this key may ever leave the daemon.
    pub key_use: KeyUse,
    /// The AEAD container holding the secret.
    pub body: EncFile,
}

/// What a keystore file on disk parses as. Only [`seal_keystore`] writes one, so this is
/// read-only: the untagged shapes are tried in order, and a v1 file matches only `Unsealed`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum KeystoreFile {
    /// A v2 file, written by [`seal_keystore`].
    Sealed(SealedKeystore),
    /// A pre-v2 file, whose AAD is the bare key name and which declares no use.
    Unsealed(EncFile),
}

/// Proof that a keystore's cleartext header declared it [`KeyUse::Shareable`]. Minted only by
/// [`KeystoreFile::export_permit`], so the export path — which takes one by value — cannot be
/// entered for any other key.
pub struct ExportPermit(SealedKeystore);

create_err_with_impls!(
    #[derive(Debug)]
    pub EnvErr,
    Aead,
    BadNonce,
    UnsupportedCipher,
    UnsupportedVersion,
    UnsupportedKeystoreVersion,
    NotSealed,
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error)
    ;
    ExportRefused { key_use: KeyUse }
);

/// `DOMAIN ‖ 0x00 ‖ name ‖ 0x00 ‖ tag`, unambiguous because a key name is `[A-Za-z0-9_]` and
/// so never contains the separator, and every other element is fixed length.
fn keystore_aad(name: &str, key_use: KeyUse) -> Vec<u8> {
    let mut aad = Vec::with_capacity(KEYSTORE_AAD_DOMAIN.len() + name.len() + 3);
    aad.extend_from_slice(KEYSTORE_AAD_DOMAIN);
    aad.push(0);
    aad.extend_from_slice(name.as_bytes());
    aad.push(0);
    aad.push(key_use.tag());
    aad
}

fn open_sealed(sealed: &SealedKeystore, name: &str, dek: &Dek) -> Result<Vec<u8>, EnvErr> {
    if sealed.v != KEYSTORE_V2 {
        return Err(EnvErr::UnsupportedKeystoreVersion);
    }
    open(
        dek.expose(),
        &keystore_aad(name, sealed.key_use),
        &sealed.body,
    )
}

impl ExportPermit {
    /// Decrypt the shareable keystore this permit was minted from.
    pub fn open(self, name: &str, dek: &Dek) -> Result<Vec<u8>, EnvErr> {
        open_sealed(&self.0, name, dek)
    }
}

impl KeystoreFile {
    /// Decrypt under whichever AAD this container's format binds.
    pub fn open(&self, name: &str, dek: &Dek) -> Result<Vec<u8>, EnvErr> {
        match self {
            KeystoreFile::Sealed(sealed) => open_sealed(sealed, name, dek),
            KeystoreFile::Unsealed(body) => open(dek.expose(), name.as_bytes(), body),
        }
    }

    /// Mint the permit the export path demands, from the cleartext header alone: no DEK, no
    /// unlock, no prompt. A rewritten header buys nothing — it only breaks the AAD.
    pub fn export_permit(self) -> Result<ExportPermit, EnvErr> {
        let KeystoreFile::Sealed(sealed) = self else {
            return Err(EnvErr::NotSealed);
        };
        if sealed.v != KEYSTORE_V2 {
            return Err(EnvErr::UnsupportedKeystoreVersion);
        }
        if sealed.key_use != KeyUse::Shareable {
            return Err(EnvErr::ExportRefused {
                key_use: sealed.key_use,
            });
        }
        Ok(ExportPermit(sealed))
    }

    /// `shareable`, `sign_only` or `unsealed`, straight from the cleartext header.
    pub fn use_label(&self) -> &'static str {
        match self {
            KeystoreFile::Sealed(sealed) => sealed.key_use.label(),
            KeystoreFile::Unsealed(_) => "unsealed",
        }
    }
}

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

/// Seal `plaintext` for `name` under `key_use` and return the v2 keystore file bytes. The AAD
/// binds both, so a copied, renamed or re-flagged file fails to open.
pub fn seal_keystore(
    name: &str,
    dek: &Dek,
    key_use: KeyUse,
    plaintext: &[u8],
) -> Result<Vec<u8>, EnvErr> {
    let sealed = SealedKeystore {
        v: KEYSTORE_V2,
        key_use,
        body: seal(dek.expose(), &keystore_aad(name, key_use), plaintext)?,
    };
    Ok(serde_json::to_vec(&sealed)?)
}

/// Seal `plaintext` and write `<dir>/<name>` atomically as a v2 keystore.
pub fn encrypt_file(
    dir: &Path,
    name: &str,
    dek: &Dek,
    key_use: KeyUse,
    plaintext: &[u8],
) -> Result<(), EnvErr> {
    atomic_write(
        &dir.join(name),
        &seal_keystore(name, dek, key_use, plaintext)?,
    )
}

/// Parse a keystore container from its on-disk bytes.
pub fn parse_keystore(bytes: &[u8]) -> Result<KeystoreFile, EnvErr> {
    Ok(serde_json::from_slice(bytes)?)
}

/// Read a keystore container: no decryption, no unlock, no prompt.
pub fn read_keystore(path: &Path) -> Result<KeystoreFile, EnvErr> {
    parse_keystore(&fs::read(path)?)
}

/// Read and decrypt a keystore file, in either on-disk format.
pub fn decrypt_file(path: &Path, name: &str, dek: &Dek) -> Result<Vec<u8>, EnvErr> {
    read_keystore(path)?.open(name, dek)
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
        encrypt_file(&dir, "SOLANA_X", &dek, KeyUse::SignOnly, &secret).unwrap();
        let got = decrypt_file(&dir.join("SOLANA_X"), "SOLANA_X", &dek).unwrap();
        assert_eq!(got, secret);
        let _ = std::fs::remove_file(dir.join("SOLANA_X"));
    }

    /// The whole feature rests on this: the cleartext `key_use` header is inside the AAD, so
    /// promoting a sign-only key to shareable on disk yields a file nothing can decrypt —
    /// not even through the permit its own rewritten header now mints.
    #[test]
    fn rewriting_the_use_header_destroys_the_keystore() {
        let dir = std::env::temp_dir().join("hot_cheese_env_bind_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("BOUND");
        let dek = Dek::from_bytes([5u8; 32]);
        encrypt_file(&dir, "BOUND", &dek, KeyUse::SignOnly, b"never-leaves").unwrap();
        assert_eq!(
            read_keystore(&path).unwrap().open("BOUND", &dek).unwrap(),
            b"never-leaves"
        );

        let honest = std::fs::read_to_string(&path).unwrap();
        assert!(honest.contains("\"key_use\":\"sign_only\""), "{honest}");
        let forged = honest.replace("\"sign_only\"", "\"shareable\"");
        std::fs::write(&path, &forged).unwrap();

        let file = read_keystore(&path).unwrap();
        assert_eq!(file.use_label(), "shareable", "the header now lies");
        assert!(matches!(file.open("BOUND", &dek), Err(EnvErr::Aead)));
        let permit = file
            .export_permit()
            .expect("the forged header mints a permit");
        assert!(matches!(permit.open("BOUND", &dek), Err(EnvErr::Aead)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every store written before sealing existed is a bare `EncFile` under the bare-name AAD.
    /// That format is permanent compatibility code: it must still parse, still decrypt, and
    /// still be refused an export permit.
    #[test]
    fn a_v1_keystore_still_parses_and_decrypts() {
        let dir = std::env::temp_dir().join("hot_cheese_env_legacy_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("LEGACY");
        let dek = Dek::from_bytes([3u8; 32]);

        // Byte-for-byte what the pre-v2 writer produced: `seal` under AAD = name, as JSON.
        let v1 =
            serde_json::to_vec(&seal(dek.expose(), b"LEGACY", b"legacy-secret").unwrap()).unwrap();
        let fields: serde_json::Value = serde_json::from_slice(&v1).unwrap();
        let object = fields.as_object().expect("a v1 file is a JSON object");
        assert_eq!(object.len(), 4);
        for key in ["v", "cipher", "nonce", "ct"] {
            assert!(object.contains_key(key), "missing {key}");
        }
        std::fs::write(&path, &v1).unwrap();

        let file = read_keystore(&path).unwrap();
        assert!(matches!(file, KeystoreFile::Unsealed(_)));
        assert_eq!(file.use_label(), "unsealed");
        assert_eq!(file.open("LEGACY", &dek).unwrap(), b"legacy-secret");
        assert_eq!(
            decrypt_file(&path, "LEGACY", &dek).unwrap(),
            b"legacy-secret"
        );
        assert!(matches!(file.export_permit(), Err(EnvErr::NotSealed)));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
