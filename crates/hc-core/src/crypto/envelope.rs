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
use std::io::{Read, Write};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const CIPHER: &str = "xchacha20poly1305";
const NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = MAX_SECRET_BYTES + AEAD_TAG_LEN;
pub const MAX_KEYSTORE_FILE_BYTES: u64 = (MAX_SECRET_BYTES * 2 + 4096) as u64;
/// Container version written by [`seal_keystore`].
const KEYSTORE_V2: u32 = 2;
/// Domain separator opening every v2 keystore AAD.
const KEYSTORE_AAD_DOMAIN: &[u8] = b"hotcheese/keystore/v2";

/// 32-byte Data Encryption Key. Encrypts every keystore file; only ever persisted
/// in wrapped form (see the keyring). Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek([u8; 32]);

impl Dek {
    /// Fresh random DEK from the OS CSPRNG, filled in place so no unwiped copy is left behind.
    pub fn random() -> Self {
        let mut dek = Self([0u8; 32]);
        OsRng.fill_bytes(&mut dek.0);
        dek
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    InvalidName,
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error)
    ;
    ExportRefused { key_use: KeyUse },
    PlaintextTooLarge { size: usize, max: usize },
    CiphertextTooShort { size: usize, min: usize },
    CiphertextTooLarge { size: usize, max: usize },
    FileTooLarge { size: u64, max: u64 }
);

impl EncFile {
    pub(crate) fn validate(&self) -> Result<(), EnvErr> {
        if self.v != 1 {
            return Err(EnvErr::UnsupportedVersion);
        }
        if self.cipher != CIPHER {
            return Err(EnvErr::UnsupportedCipher);
        }
        if self.nonce.len() != NONCE_LEN {
            return Err(EnvErr::BadNonce);
        }
        if self.ct.len() < AEAD_TAG_LEN {
            return Err(EnvErr::CiphertextTooShort {
                size: self.ct.len(),
                min: AEAD_TAG_LEN,
            });
        }
        if self.ct.len() > MAX_CIPHERTEXT_BYTES {
            return Err(EnvErr::CiphertextTooLarge {
                size: self.ct.len(),
                max: MAX_CIPHERTEXT_BYTES,
            });
        }
        Ok(())
    }
}

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

fn validate_keystore_name(name: &str) -> Result<(), EnvErr> {
    if crate::is_valid_key_name(name) {
        Ok(())
    } else {
        Err(EnvErr::InvalidName)
    }
}

fn open_sealed(
    sealed: &SealedKeystore,
    name: &str,
    dek: &Dek,
) -> Result<Zeroizing<Vec<u8>>, EnvErr> {
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
    pub fn open(self, name: &str, dek: &Dek) -> Result<Zeroizing<Vec<u8>>, EnvErr> {
        validate_keystore_name(name)?;
        open_sealed(&self.0, name, dek)
    }
}

impl KeystoreFile {
    /// Validate the complete cleartext container before an operation prompts or decrypts it.
    pub fn validate(&self) -> Result<(), EnvErr> {
        match self {
            KeystoreFile::Sealed(sealed) => {
                if sealed.v != KEYSTORE_V2 {
                    return Err(EnvErr::UnsupportedKeystoreVersion);
                }
                sealed.body.validate()
            }
            KeystoreFile::Unsealed(body) => body.validate(),
        }
    }

    /// Decrypt under whichever AAD this container's format binds.
    pub fn open(&self, name: &str, dek: &Dek) -> Result<Zeroizing<Vec<u8>>, EnvErr> {
        validate_keystore_name(name)?;
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
    if plaintext.len() > MAX_SECRET_BYTES {
        return Err(EnvErr::PlaintextTooLarge {
            size: plaintext.len(),
            max: MAX_SECRET_BYTES,
        });
    }
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
pub fn open(key: &[u8; 32], aad: &[u8], f: &EncFile) -> Result<Zeroizing<Vec<u8>>, EnvErr> {
    f.validate()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(&f.nonce), Payload { msg: &f.ct, aad })
        .map(Zeroizing::new)
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
    validate_keystore_name(name)?;
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

/// Seal a brand-new keystore and atomically claim its name without replacing any existing file
/// or symlink. Name-existence checks remain useful for early errors, but this is the commit point
/// that closes their race.
pub fn encrypt_file_new(
    dir: &Path,
    name: &str,
    dek: &Dek,
    key_use: KeyUse,
    plaintext: &[u8],
) -> Result<(), EnvErr> {
    atomic_write_new(
        &dir.join(name),
        &seal_keystore(name, dek, key_use, plaintext)?,
    )
}

/// Parse a keystore container from its on-disk bytes.
pub fn parse_keystore(bytes: &[u8]) -> Result<KeystoreFile, EnvErr> {
    if bytes.len() as u64 > MAX_KEYSTORE_FILE_BYTES {
        return Err(EnvErr::FileTooLarge {
            size: bytes.len() as u64,
            max: MAX_KEYSTORE_FILE_BYTES,
        });
    }
    let parsed: KeystoreFile = crate::wire::strict_json_from_slice(bytes)?;
    parsed.validate()?;
    Ok(parsed)
}

/// Read a keystore container: no decryption, no unlock, no prompt.
pub fn read_keystore(path: &Path) -> Result<KeystoreFile, EnvErr> {
    let mut bytes = Vec::new();
    crate::open_regular_file(path)?
        .take(MAX_KEYSTORE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_KEYSTORE_FILE_BYTES {
        return Err(EnvErr::FileTooLarge {
            size: bytes.len() as u64,
            max: MAX_KEYSTORE_FILE_BYTES,
        });
    }
    parse_keystore(&bytes)
}

/// Read and decrypt a keystore file, in either on-disk format.
pub fn decrypt_file(path: &Path, name: &str, dek: &Dek) -> Result<Zeroizing<Vec<u8>>, EnvErr> {
    read_keystore(path)?.open(name, dek)
}

/// Write `bytes` to `path` as an owner-only (0600) file, creating the parent dir if needed
/// and forcing the mode on a pre-existing file too. For key material: the Secure Enclave
/// blob, the demo software key, and the TLS private key.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    atomic_write_io(path, bytes, true)
}

/// Create an owner-only file atomically without replacing any existing path, including a
/// symlink. Used for machine-bound private material, where a racing second creator must lose
/// rather than silently rotate the first creator's key.
pub fn write_private_file_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    atomic_write_io(path, bytes, false)
}

/// The store's git repository directory: git owns every mode inside it, and a chmod sweep that
/// descended into it would fight `core.fileMode` and dirty a clean checkout.
pub const GIT_DIR: &str = ".git";

/// Tighten the whole store to owner-only: `0700` on the store dir and every directory under it,
/// `0600` on every regular file, and [`GIT_DIR`] left entirely alone. Symlinks are skipped, so
/// a link planted in the store cannot redirect the sweep outside it.
pub fn enforce_store_modes(store: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut dirs = vec![store.to_path_buf()];
    let mut inspected = 0usize;
    while let Some(dir) = dirs.pop() {
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(&dir)? {
            inspected = inspected.saturating_add(1);
            if inspected > crate::MAX_STORE_ENUM_ENTRIES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "store contains more than {} directory entries",
                        crate::MAX_STORE_ENUM_ENTRIES
                    ),
                ));
            }
            let entry = entry?;
            if entry.file_name() == GIT_DIR {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                dirs.push(entry.path());
            } else if kind.is_file() {
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    Ok(())
}

/// Write `bytes` to `path` via temp-file + rename so a crash can't leave a partial file.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), EnvErr> {
    atomic_write_io(path, bytes, true)?;
    Ok(())
}

/// Write `bytes` atomically, but refuse if `path` already exists. This is for imports and
/// bootstrap operations where replacing even one pre-existing key would be data loss.
pub fn atomic_write_new(path: &Path, bytes: &[u8]) -> Result<(), EnvErr> {
    atomic_write_io(path, bytes, false)?;
    Ok(())
}

fn atomic_write_io(path: &Path, bytes: &[u8], replace: bool) -> std::io::Result<()> {
    use std::ffi::OsString;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let base = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("hot_cheese"));
    let mut opened = None;
    for _ in 0..8 {
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let mut name = base.clone();
        name.push(format!(".{}.hctmp", hex::encode(random)));
        let temp = parent.join(name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
        {
            Ok(file) => {
                opened = Some((temp, file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    let Some((temp, mut file)) = opened else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate an atomic-write temporary file",
        ));
    };
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if replace {
            fs::rename(&temp, path)?;
        } else {
            // `hard_link` is an atomic create-if-absent on the same filesystem. Unlike rename,
            // it cannot replace an existing path (including a symlink) between our check and
            // commit. The random temporary file is then unlinked, leaving its inode at `path`.
            fs::hard_link(&temp, path)?;
            fs::remove_file(&temp)?;
        }
        fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_binds_key_and_aad() {
        let key = [7u8; 32];
        let f = seal(&key, b"MY_KEY", b"secret-bytes").unwrap();
        assert_eq!(
            open(&key, b"MY_KEY", &f).unwrap().as_slice(),
            b"secret-bytes"
        );
        // wrong AAD (file renamed) is rejected
        assert!(open(&key, b"OTHER", &f).is_err());
        // wrong key is rejected
        assert!(open(&[8u8; 32], b"MY_KEY", &f).is_err());
    }

    #[test]
    fn structurally_short_ciphertext_is_rejected_before_open() {
        let malformed = EncFile {
            v: 1,
            cipher: CIPHER.to_string(),
            nonce: vec![0u8; NONCE_LEN],
            ct: vec![0u8; AEAD_TAG_LEN - 1],
        };
        assert!(matches!(
            malformed.validate(),
            Err(EnvErr::CiphertextTooShort {
                min: AEAD_TAG_LEN,
                ..
            })
        ));
    }

    #[test]
    fn atomic_write_new_never_replaces_an_existing_file() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_atomic_new_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("KEY");
        atomic_write_new(&path, b"first").unwrap();
        assert!(atomic_write_new(&path, b"second").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_keystore_names_cannot_escape_the_store() {
        let root = std::env::temp_dir().join(format!(
            "hot_cheese_invalid_name_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = root.join("store");
        std::fs::create_dir_all(&store).unwrap();
        let dek = Dek::from_bytes([4u8; 32]);

        assert!(matches!(
            encrypt_file_new(&store, "../ESCAPE", &dek, KeyUse::SignOnly, b"secret"),
            Err(EnvErr::InvalidName)
        ));
        assert!(!root.join("ESCAPE").exists());
        assert!(matches!(
            seal_keystore("bad/name", &dek, KeyUse::SignOnly, b"secret"),
            Err(EnvErr::InvalidName)
        ));

        std::fs::remove_dir_all(root).unwrap();
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
        let dir = std::env::temp_dir().join(format!("hot_cheese_env_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let dek = Dek::from_bytes([3u8; 32]);
        let secret = vec![9u8; 64]; // Solana keypairs are 64 bytes
        encrypt_file(&dir, "SOLANA_X", &dek, KeyUse::SignOnly, &secret).unwrap();
        let got = decrypt_file(&dir.join("SOLANA_X"), "SOLANA_X", &dek).unwrap();
        assert_eq!(got.as_slice(), secret.as_slice());
        let _ = std::fs::remove_file(dir.join("SOLANA_X"));
    }

    /// The whole feature rests on this: the cleartext `key_use` header is inside the AAD, so
    /// promoting a sign-only key to shareable on disk yields a file nothing can decrypt —
    /// not even through the permit its own rewritten header now mints.
    #[test]
    fn rewriting_the_use_header_destroys_the_keystore() {
        let dir =
            std::env::temp_dir().join(format!("hot_cheese_env_bind_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("BOUND");
        let dek = Dek::from_bytes([5u8; 32]);
        encrypt_file(&dir, "BOUND", &dek, KeyUse::SignOnly, b"never-leaves").unwrap();
        assert_eq!(
            read_keystore(&path)
                .unwrap()
                .open("BOUND", &dek)
                .unwrap()
                .as_slice(),
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
        let dir =
            std::env::temp_dir().join(format!("hot_cheese_env_legacy_test_{}", std::process::id()));
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
        assert_eq!(
            file.open("LEGACY", &dek).unwrap().as_slice(),
            b"legacy-secret"
        );
        assert_eq!(
            decrypt_file(&path, "LEGACY", &dek).unwrap().as_slice(),
            b"legacy-secret"
        );
        assert!(matches!(file.export_permit(), Err(EnvErr::NotSealed)));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
