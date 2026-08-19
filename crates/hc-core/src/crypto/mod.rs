//! yeeted and refactored from https://github.com/roynalnaruto/eth-keystore-rs
//! EVEN MORE MINIMALIST
//! A minimalist library to interact with encrypted JSON keystores as per the
//! [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).
use aes::{
    cipher::{self, InnerIvInit, KeyInit, StreamCipherCore},
    Aes128,
};
use err_mac::create_err_with_impls;
use k256::ecdsa::SigningKey;
use rand::{CryptoRng, Rng};
use scrypt::{scrypt, Params as ScryptParams};
use std::{array::TryFromSliceError, io::Read, path::Path};
use subtle::ConstantTimeEq;
use tiny_keccak::{Hasher, Keccak};
use zeroize::Zeroizing;
mod bytes_hex;
pub mod envelope;
mod keystore;
#[cfg(any(test, feature = "test-util"))]
use keystore::{CipherparamsJson, CryptoJson};
pub use keystore::{EthKeystore, KdfparamsType};
#[cfg(any(test, feature = "test-util"))]
use std::fs::File;
#[cfg(any(test, feature = "test-util"))]
use std::io::Write;

pub fn random_pk<R: Rng + CryptoRng>(rng: &mut R) -> SigningKey {
    SigningKey::random(rng)
}

/// convert hex str to a vec of bytes; returns None on odd length or any non-hex digit
/// (never panics — reachable from deserializing untrusted legacy keystore JSON in migration)
pub fn to_vec(s: &str) -> Option<Vec<u8>> {
    let digits = s.strip_prefix("0x").unwrap_or(s);
    // `hex::decode` works over bytes and rejects non-ASCII input. The previous implementation
    // indexed the UTF-8 string at two-byte offsets, which could panic on a crafted legacy
    // keystore field whose character boundaries did not happen to land on those offsets.
    hex::decode(digits).ok()
}

pub fn keccak256<B: AsRef<[u8]>>(slice: B) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(slice.as_ref());
    let mut first_key = [0; 32];
    h.finalize(&mut first_key);
    first_key
}

pub const MAX_LEGACY_KEYSTORE_BYTES: u64 = 1024 * 1024;
const LEGACY_DKLEN: u8 = 32;
const LEGACY_IV_BYTES: usize = 16;
const LEGACY_MAC_BYTES: usize = 32;
const MIN_LEGACY_SALT_BYTES: usize = 16;
const MAX_LEGACY_SALT_BYTES: usize = 64;
const MAX_LEGACY_SECRET_BYTES: usize = envelope::MAX_SECRET_BYTES;
const MAX_SCRYPT_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SCRYPT_WORK: u64 = 16 * 1024 * 1024;

create_err_with_impls!(
    #[derive(Debug)]
    pub CryptoErr,
    MacMismatch,
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error),
    ScryptInvalidParams(scrypt::errors::InvalidParams),
    ScryptInvalidOuputLen(scrypt::errors::InvalidOutputLen),
    AesInvalidKeyNonceLength(aes::cipher::InvalidLength),
    Ecdsa(k256::ecdsa::Error),
    InvalidSlice(TryFromSliceError)
    ;
    FileTooLarge { size: u64, max: u64 },
    UnsupportedVersion { found: u8 },
    UnsupportedCipher { found: String },
    UnsupportedKdf { found: String },
    InvalidDklen { found: u8 },
    InvalidIvLength { found: usize },
    InvalidMacLength { found: usize },
    InvalidSaltLength { found: usize },
    InvalidScryptN { found: u32 },
    ScryptCostTooHigh { memory: u64, work: u64 },
    InvalidCiphertextLength { found: usize, max: usize },
);

/// Decrypts an encrypted JSON keystore at the provided `path` using the provided `password`.
/// Decryption supports the [Scrypt](https://tools.ietf.org/html/rfc7914.html) and
/// [PBKDF2](https://ietf.org/rfc/rfc2898.txt) key derivation functions.
pub fn decrypt_key<P, S>(path: P, password: S) -> Result<Zeroizing<Vec<u8>>, CryptoErr>
where
    P: AsRef<Path>,
    S: AsRef<[u8]>,
{
    // The legacy store is an import boundary too: do not follow a key pathname that was
    // exchanged for a symlink (or FIFO) after directory enumeration.
    let file = crate::open_regular_file(path.as_ref())?;
    let size = file.metadata()?.len();
    if size > MAX_LEGACY_KEYSTORE_BYTES {
        return Err(CryptoErr::FileTooLarge {
            size,
            max: MAX_LEGACY_KEYSTORE_BYTES,
        });
    }
    let mut contents = String::new();
    file.take(MAX_LEGACY_KEYSTORE_BYTES + 1)
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_LEGACY_KEYSTORE_BYTES {
        return Err(CryptoErr::FileTooLarge {
            size: contents.len() as u64,
            max: MAX_LEGACY_KEYSTORE_BYTES,
        });
    }
    let keystore: EthKeystore = crate::wire::strict_json_from_str(&contents)?;

    if keystore.version != 3 {
        return Err(CryptoErr::UnsupportedVersion {
            found: keystore.version,
        });
    }
    if keystore.crypto.cipher != "aes-128-ctr" {
        return Err(CryptoErr::UnsupportedCipher {
            found: keystore.crypto.cipher,
        });
    }
    if keystore.crypto.kdf != "scrypt" {
        return Err(CryptoErr::UnsupportedKdf {
            found: keystore.crypto.kdf,
        });
    }
    if keystore.crypto.cipherparams.iv.len() != LEGACY_IV_BYTES {
        return Err(CryptoErr::InvalidIvLength {
            found: keystore.crypto.cipherparams.iv.len(),
        });
    }
    if keystore.crypto.mac.len() != LEGACY_MAC_BYTES {
        return Err(CryptoErr::InvalidMacLength {
            found: keystore.crypto.mac.len(),
        });
    }
    if keystore.crypto.ciphertext.is_empty()
        || keystore.crypto.ciphertext.len() > MAX_LEGACY_SECRET_BYTES
    {
        return Err(CryptoErr::InvalidCiphertextLength {
            found: keystore.crypto.ciphertext.len(),
            max: MAX_LEGACY_SECRET_BYTES,
        });
    }

    // Derive the key.
    let key = match keystore.crypto.kdfparams {
        KdfparamsType {
            dklen,
            n,
            p,
            r,
            salt,
        } => {
            if dklen != LEGACY_DKLEN {
                return Err(CryptoErr::InvalidDklen { found: dklen });
            }
            if !(MIN_LEGACY_SALT_BYTES..=MAX_LEGACY_SALT_BYTES).contains(&salt.len()) {
                return Err(CryptoErr::InvalidSaltLength { found: salt.len() });
            }
            if n < 2 || !n.is_power_of_two() {
                return Err(CryptoErr::InvalidScryptN { found: n });
            }
            let memory = 128u64
                .saturating_mul(u64::from(n))
                .saturating_mul(u64::from(r));
            let work = u64::from(n)
                .saturating_mul(u64::from(r))
                .saturating_mul(u64::from(p));
            if memory > MAX_SCRYPT_MEMORY_BYTES || work > MAX_SCRYPT_WORK {
                return Err(CryptoErr::ScryptCostTooHigh { memory, work });
            }
            let mut key = Zeroizing::new(vec![0u8; usize::from(dklen)]);
            let log_n = n.trailing_zeros() as u8;
            let scrypt_params = ScryptParams::new(log_n, r, p)?;
            scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;
            key
        }
    };

    // Derive the MAC from the derived key and ciphertext.
    let mut pld = Zeroizing::new(Vec::new());
    pld.extend(&key[16..32]);
    pld.extend(&keystore.crypto.ciphertext);
    let derived_mac = keccak256(pld);

    if !bool::from(derived_mac.as_slice().ct_eq(keystore.crypto.mac.as_slice())) {
        return Err(CryptoErr::MacMismatch);
    }

    // Decrypt the private key bytes using AES-128-CTR
    let decryptor = Aes128Ctr::new(&key[..16], &keystore.crypto.cipherparams.iv)?;

    let mut pk = keystore.crypto.ciphertext;
    decryptor.apply_keystream(&mut pk);

    Ok(Zeroizing::new(pk))
}

/// Encrypts the given private key using the [Scrypt](https://tools.ietf.org/html/rfc7914.html)
/// password-based key derivation function, and stores it in the provided directory. On success, it
/// returns the `id` (Uuid) generated for this keystore.
#[cfg(any(test, feature = "test-util"))]
pub fn encrypt_key<P, R, B, S>(
    dir: P,
    rng: &mut R,
    pk: B,
    password: S,
    name: &str,
) -> Result<(), CryptoErr>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    B: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    const DEFAULT_CIPHER: &str = "aes-128-ctr";
    const DEFAULT_KEY_SIZE: usize = 32usize;
    const DEFAULT_IV_SIZE: usize = 16usize;
    const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
    const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
    const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
    const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

    // Generate a random salt.
    let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
    rng.fill_bytes(salt.as_mut_slice());

    // Derive the key.
    let mut key = Zeroizing::new(vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize]);
    let scrypt_params = ScryptParams::new(
        DEFAULT_KDF_PARAMS_LOG_N,
        DEFAULT_KDF_PARAMS_R,
        DEFAULT_KDF_PARAMS_P,
    )?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    // Encrypt the private key using AES-128-CTR.
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    rng.fill_bytes(iv.as_mut_slice());

    let encryptor = Aes128Ctr::new(&key[..16], &iv[..16])?;

    let mut ciphertext = pk.as_ref().to_vec();
    encryptor.apply_keystream(&mut ciphertext);

    // Calculate the MAC.
    let mut pld = Zeroizing::new(Vec::new());
    pld.extend(&key[16..32]);
    pld.extend(&ciphertext);
    let mac = keccak256(pld);

    let name = name.to_string();

    // Construct and serialize the encrypted JSON keystore.
    let keystore = EthKeystore {
        version: 3,
        crypto: CryptoJson {
            cipher: String::from(DEFAULT_CIPHER),
            cipherparams: CipherparamsJson { iv },
            ciphertext: ciphertext.to_vec(),
            kdf: "scrypt".to_string(),
            kdfparams: KdfparamsType {
                dklen: DEFAULT_KDF_PARAMS_DKLEN,
                n: 2u32.pow(DEFAULT_KDF_PARAMS_LOG_N as u32),
                p: DEFAULT_KDF_PARAMS_P,
                r: DEFAULT_KDF_PARAMS_R,
                salt,
            },
            mac: mac.to_vec(),
        },
    };
    let contents = serde_json::to_string(&keystore)?;

    // Create a file in write-only mode, to store the encrypted JSON keystore.
    let mut file = File::create(dir.as_ref().join(name))?;
    file.write_all(contents.as_bytes())?;

    Ok(())
}

struct Aes128Ctr {
    inner: ctr::CtrCore<Aes128, ctr::flavors::Ctr128BE>,
}

impl Aes128Ctr {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self, cipher::InvalidLength> {
        let cipher = aes::Aes128::new_from_slice(key)?;
        let inner = ctr::CtrCore::inner_iv_slice_init(cipher, iv)?;
        Ok(Self { inner })
    }

    fn apply_keystream(self, buf: &mut [u8]) {
        self.inner.apply_keystream_partial(buf.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::PathBuf;

    fn mutated_keystore(tag: &str, mutate: impl FnOnce(&mut Value)) -> PathBuf {
        let fixture = std::fs::read_to_string("./test-keys/key-scrypt.json").unwrap();
        let mut value: Value = serde_json::from_str(&fixture).unwrap();
        mutate(&mut value);
        let path = std::env::temp_dir().join(format!(
            "hot_cheese_legacy_{tag}_{}_{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    }

    #[test]
    fn test_decrypt_scrypt() {
        let secret =
            to_vec("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829").unwrap();
        let keypath = Path::new("./test-keys/key-scrypt.json");
        assert_eq!(
            decrypt_key(keypath, "grOQ8QDnGHvpYJf").unwrap().as_slice(),
            secret.as_slice()
        );
        assert!(decrypt_key(keypath, "thisisnotrandom").is_err());
    }

    #[test]
    fn malformed_non_ascii_hex_is_rejected_without_panicking() {
        for text in ["€€", "𐀀", "00€0"] {
            assert!(
                to_vec(text).is_none(),
                "non-hex input must be rejected: {text:?}"
            );
        }

        let path = mutated_keystore("unicode_hex", |value| {
            value["crypto"]["cipherparams"]["iv"] = "€€".into();
        });
        assert!(decrypt_key(&path, "unused").is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_encrypt_decrypt_key() {
        let secret =
            to_vec("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d").unwrap();
        let dir = Path::new("./test-keys");
        let mut rng = rand::thread_rng();
        let name = "hehe";
        encrypt_key(dir, &mut rng, &secret, "newpassword", name).unwrap();

        let keypath = dir.join(name);
        assert_eq!(
            decrypt_key(&keypath, "newpassword").unwrap().as_slice(),
            secret.as_slice()
        );
        assert!(decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn malformed_legacy_lengths_are_rejected_without_panicking() {
        let cases: &[(&str, fn(&mut Value), fn(&CryptoErr) -> bool)] = &[
            (
                "dklen",
                |v| v["crypto"]["kdfparams"]["dklen"] = 16.into(),
                |e| matches!(e, CryptoErr::InvalidDklen { found: 16 }),
            ),
            (
                "iv",
                |v| v["crypto"]["cipherparams"]["iv"] = "00".into(),
                |e| matches!(e, CryptoErr::InvalidIvLength { found: 1 }),
            ),
            (
                "mac",
                |v| v["crypto"]["mac"] = "00".into(),
                |e| matches!(e, CryptoErr::InvalidMacLength { found: 1 }),
            ),
            (
                "empty_ciphertext",
                |v| v["crypto"]["ciphertext"] = "".into(),
                |e| matches!(e, CryptoErr::InvalidCiphertextLength { found: 0, .. }),
            ),
        ];

        for (tag, mutate, expected) in cases {
            let path = mutated_keystore(tag, *mutate);
            let err = decrypt_key(&path, "unused").unwrap_err();
            std::fs::remove_file(path).unwrap();
            assert!(expected(&err), "unexpected error for {tag}: {err:?}");
        }
    }

    #[test]
    fn hostile_scrypt_cost_is_rejected_before_derivation() {
        let path = mutated_keystore("scrypt_cost", |v| {
            v["crypto"]["kdfparams"]["n"] = (1u64 << 31).into();
        });
        let err = decrypt_key(&path, "unused").unwrap_err();
        std::fs::remove_file(path).unwrap();
        assert!(matches!(err, CryptoErr::ScryptCostTooHigh { .. }));
    }

    #[test]
    fn unsupported_legacy_algorithms_and_versions_are_rejected() {
        for (tag, mutate) in [
            (
                "version",
                (|v: &mut Value| v["version"] = 4.into()) as fn(&mut Value),
            ),
            ("cipher", |v: &mut Value| {
                v["crypto"]["cipher"] = "aes-256-ctr".into()
            }),
            ("kdf", |v: &mut Value| v["crypto"]["kdf"] = "pbkdf2".into()),
        ] {
            let path = mutated_keystore(tag, mutate);
            assert!(decrypt_key(&path, "unused").is_err());
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn oversized_legacy_file_is_rejected_before_json_parsing() {
        let path = std::env::temp_dir().join(format!(
            "hot_cheese_legacy_oversized_{}.json",
            std::process::id()
        ));
        std::fs::write(&path, vec![b' '; MAX_LEGACY_KEYSTORE_BYTES as usize + 1]).unwrap();
        let err = decrypt_key(&path, "unused").unwrap_err();
        std::fs::remove_file(path).unwrap();
        assert!(matches!(err, CryptoErr::FileTooLarge { .. }));
    }
}
