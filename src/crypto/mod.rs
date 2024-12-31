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
use std::{
    array::TryFromSliceError,
    fs::File,
    io::{Read, Write},
    path::Path,
};
use tiny_keccak::{Hasher, Keccak};
mod bytes_hex;
mod keystore;
pub use keystore::{CipherparamsJson, CryptoJson, EthKeystore, KdfparamsType};

pub fn random_pk<R: Rng + CryptoRng>(rng: &mut R) -> SigningKey {
    SigningKey::random(rng)
}

/// convert hex str to a vec of bytes
pub fn to_vec(mut s: &str) -> Option<Vec<u8>> {
    if s.starts_with("0x") {
        s = &s[2..]
    }
    if s.len() % 2 != 0 {
        return None;
    }
    Some(
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect(),
    )
}

pub fn keccak256(slice: Vec<u8>) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(slice.as_slice());
    let mut first_key = [0; 32];
    h.finalize(&mut first_key);
    first_key
}

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
);

const DEFAULT_CIPHER: &str = "aes-128-ctr";
const DEFAULT_KEY_SIZE: usize = 32usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

/// Decrypts an encrypted JSON keystore at the provided `path` using the provided `password`.
/// Decryption supports the [Scrypt](https://tools.ietf.org/html/rfc7914.html) and
/// [PBKDF2](https://ietf.org/rfc/rfc2898.txt) key derivation functions.
pub fn decrypt_key<P, S>(path: P, password: S) -> Result<Vec<u8>, CryptoErr>
where
    P: AsRef<Path>,
    S: AsRef<[u8]>,
{
    // Read the file contents as string and deserialize it.
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let keystore: EthKeystore = serde_json::from_str(&contents)?;

    // Derive the key.
    let key = match keystore.crypto.kdfparams {
        KdfparamsType {
            dklen,
            n,
            p,
            r,
            salt,
        } => {
            let mut key = vec![0u8; dklen as usize];
            // TODO: use int_log https://github.com/rust-lang/rust/issues/70887
            // TODO: when it is stable
            let log_n = (n as f32).log2().ceil() as u8;
            let scrypt_params = ScryptParams::new(log_n, r, p)?;
            scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;
            key
        }
    };

    // Derive the MAC from the derived key and ciphertext.
    let mut pld = Vec::new();
    pld.extend(&key[16..32]);
    pld.extend(&keystore.crypto.ciphertext);
    let derived_mac = keccak256(pld);

    if derived_mac.as_slice() != keystore.crypto.mac.as_slice() {
        return Err(CryptoErr::MacMismatch);
    }

    // Decrypt the private key bytes using AES-128-CTR
    let decryptor =
        Aes128Ctr::new(&key[..16], &keystore.crypto.cipherparams.iv[..16]).expect("invalid length");

    let mut pk = keystore.crypto.ciphertext;
    decryptor.apply_keystream(&mut pk);

    Ok(pk)
}

/// Encrypts the given private key using the [Scrypt](https://tools.ietf.org/html/rfc7914.html)
/// password-based key derivation function, and stores it in the provided directory. On success, it
/// returns the `id` (Uuid) generated for this keystore.
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
    // Generate a random salt.
    let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
    rng.fill_bytes(salt.as_mut_slice());

    // Derive the key.
    let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
    let scrypt_params = ScryptParams::new(
        DEFAULT_KDF_PARAMS_LOG_N,
        DEFAULT_KDF_PARAMS_R,
        DEFAULT_KDF_PARAMS_P,
    )?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    // Encrypt the private key using AES-128-CTR.
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    rng.fill_bytes(iv.as_mut_slice());

    let encryptor = Aes128Ctr::new(&key[..16], &iv[..16]).expect("invalid length");

    let mut ciphertext = pk.as_ref().to_vec();
    encryptor.apply_keystream(&mut ciphertext);

    // Calculate the MAC.
    let mut pld = Vec::new();
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
        let cipher = aes::Aes128::new_from_slice(key).unwrap();
        let inner = ctr::CtrCore::inner_iv_slice_init(cipher, iv).unwrap();
        Ok(Self { inner })
    }

    fn apply_keystream(self, buf: &mut [u8]) {
        self.inner.apply_keystream_partial(buf.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_scrypt() {
        let secret =
            to_vec("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829").unwrap();
        let keypath = Path::new("./test-keys/key-scrypt.json");
        assert_eq!(decrypt_key(keypath, "grOQ8QDnGHvpYJf").unwrap(), secret);
        assert!(decrypt_key(keypath, "thisisnotrandom").is_err());
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
        assert_eq!(decrypt_key(&keypath, "newpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }
}
