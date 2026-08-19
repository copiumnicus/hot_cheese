use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use err_mac::create_err_with_impls;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

const PUBLIC_KEY_LEN: usize = 65;
const PUBLIC_KEY_TAG: u8 = 0x04;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const PROTOCOL_VERSION: u8 = 1;
const HKDF_INFO_DOMAIN: &[u8] = b"hotcheese/share/v1/hkdf";
const AAD_DOMAIN: &[u8] = b"hotcheese/share";
const MAX_SHARED_SECRET_BYTES: usize = crate::crypto::envelope::MAX_SECRET_BYTES;
const MAX_CIPHERTEXT_BYTES: usize = MAX_SHARED_SECRET_BYTES + 16;

create_err_with_impls!(
    #[derive(Debug)]
    pub ShareErr,
    Aead(aes_gcm::Error),
    Kdf
    ;
    BadPeerPublicKey { len: usize },
    InvalidKeyName { name: String },
    PlaintextTooLarge { size: usize, max: usize },
    CiphertextTooLarge { size: usize, max: usize }
);

struct EphemeralKeyPair {
    secret: EphemeralSecret,
    public: Vec<u8>,
}

impl EphemeralKeyPair {
    fn new() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self { secret, public }
    }
}

pub struct EphemeralClient {
    pair: EphemeralKeyPair,
}

impl EphemeralClient {
    pub fn new() -> Self {
        Self {
            pair: EphemeralKeyPair::new(),
        }
    }

    pub fn sendable(self) -> (ClientReq, ResponseDecryptor) {
        let EphemeralKeyPair { secret, public } = self.pair;
        (
            ClientReq {
                pubk: public.clone(),
            },
            ResponseDecryptor { secret, public },
        )
    }
}

pub struct ResponseDecryptor {
    secret: EphemeralSecret,
    public: Vec<u8>,
}

impl ResponseDecryptor {
    /// Decrypt the release of keystore `name`; the AAD makes any other name fail to open.
    pub fn decrypt(
        self,
        name: &str,
        response: &ServerEncryptedRes,
    ) -> Result<Zeroizing<Vec<u8>>, ShareErr> {
        if response.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(ShareErr::CiphertextTooLarge {
                size: response.ciphertext.len(),
                max: MAX_CIPHERTEXT_BYTES,
            });
        }
        let aad = share_aad(name)?;
        let shared = shared_secret(self.secret, &response.pubk)?;
        let key = derive_key(&response.salt, shared.as_ref(), &self.public, &response.pubk)?;
        let cipher = Aes256Gcm::new((&*key).into());
        Ok(Zeroizing::new(cipher.decrypt(
            Nonce::from_slice(&response.nonce),
            Payload {
                msg: &response.ciphertext,
                aad: &aad,
            },
        )?))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientReq {
    #[serde(with = "public_key_hex")]
    pub pubk: Vec<u8>,
}

pub struct EphemeralServer {
    pair: EphemeralKeyPair,
}

impl EphemeralServer {
    pub fn new() -> Self {
        Self {
            pair: EphemeralKeyPair::new(),
        }
    }

    /// Encrypt the release of keystore `name` to the requesting client only.
    pub fn encrypt_secret(
        self,
        request: &ClientReq,
        name: &str,
        plaintext: &[u8],
    ) -> Result<ServerEncryptedRes, ShareErr> {
        if plaintext.len() > MAX_SHARED_SECRET_BYTES {
            return Err(ShareErr::PlaintextTooLarge {
                size: plaintext.len(),
                max: MAX_SHARED_SECRET_BYTES,
            });
        }
        let aad = share_aad(name)?;
        let EphemeralKeyPair { secret, public } = self.pair;
        let shared = shared_secret(secret, &request.pubk)?;
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(&salt, shared.as_ref(), &request.pubk, &public)?;
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new((&*key).into());
        let ciphertext = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )?;
        Ok(ServerEncryptedRes {
            ciphertext,
            pubk: public,
            nonce,
            salt,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerEncryptedRes {
    #[serde(with = "bytes_hex")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "public_key_hex")]
    pub pubk: Vec<u8>,
    #[serde(with = "hex_12")]
    pub nonce: [u8; NONCE_LEN],
    #[serde(with = "hex_16")]
    pub salt: [u8; SALT_LEN],
}

fn shared_secret(secret: EphemeralSecret, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>, ShareErr> {
    validate_public_key(peer)?;
    let public = p256::PublicKey::from_sec1_bytes(peer)
        .map_err(|_| ShareErr::BadPeerPublicKey { len: peer.len() })?;
    let shared = secret.diffie_hellman(&public);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    Ok(out)
}

fn validate_public_key(bytes: &[u8]) -> Result<(), ShareErr> {
    if bytes.len() != PUBLIC_KEY_LEN || bytes.first() != Some(&PUBLIC_KEY_TAG) {
        return Err(ShareErr::BadPeerPublicKey { len: bytes.len() });
    }
    p256::PublicKey::from_sec1_bytes(bytes)
        .map(|_| ())
        .map_err(|_| ShareErr::BadPeerPublicKey { len: bytes.len() })
}

/// `DOMAIN ‖ 0x00 ‖ name ‖ 0x00 ‖ version`, unambiguous because a key name is `[A-Za-z0-9_]`.
fn share_aad(name: &str) -> Result<Vec<u8>, ShareErr> {
    if !crate::is_valid_key_name(name) {
        return Err(ShareErr::InvalidKeyName {
            name: name.to_string(),
        });
    }
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + name.len() + 3);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.push(0);
    aad.extend_from_slice(name.as_bytes());
    aad.push(0);
    aad.push(PROTOCOL_VERSION);
    Ok(aad)
}

/// HKDF `info` is `DOMAIN ‖ client_pub ‖ server_pub`; both points are validated 65-byte SEC1,
/// so the concatenation binds the whole exchange to exactly one pair of ephemeral keys.
fn derive_key(
    salt: &[u8; SALT_LEN],
    shared: &[u8],
    client_pub: &[u8],
    server_pub: &[u8],
) -> Result<Zeroizing<[u8; 32]>, ShareErr> {
    validate_public_key(client_pub)?;
    validate_public_key(server_pub)?;
    let mut info = Vec::with_capacity(HKDF_INFO_DOMAIN.len() + PUBLIC_KEY_LEN * 2);
    info.extend_from_slice(HKDF_INFO_DOMAIN);
    info.extend_from_slice(client_pub);
    info.extend_from_slice(server_pub);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| ShareErr::Kdf)?;
    Ok(key)
}

fn decode_hex(text: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(
        text.strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text),
    )
}

mod bytes_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        let prefix = usize::from(text.starts_with("0x") || text.starts_with("0X")) * 2;
        if text.len().saturating_sub(prefix) > super::MAX_CIPHERTEXT_BYTES.saturating_mul(2) {
            return Err(serde::de::Error::custom("ciphertext exceeds limit"));
        }
        let bytes = super::decode_hex(&text).map_err(serde::de::Error::custom)?;
        if bytes.len() > super::MAX_CIPHERTEXT_BYTES {
            return Err(serde::de::Error::custom("ciphertext exceeds limit"));
        }
        Ok(bytes)
    }
}

mod public_key_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        super::validate_public_key(bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = super::decode_hex(&text).map_err(serde::de::Error::custom)?;
        super::validate_public_key(&bytes).map_err(serde::de::Error::custom)?;
        Ok(bytes)
    }
}

macro_rules! fixed_hex {
    ($module:ident, $len:expr) => {
        mod $module {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(
                bytes: &[u8; $len],
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<[u8; $len], D::Error> {
                let text = String::deserialize(deserializer)?;
                let bytes = super::decode_hex(&text).map_err(serde::de::Error::custom)?;
                bytes.try_into().map_err(|bytes: Vec<u8>| {
                    serde::de::Error::custom(format!(
                        "expected {} bytes, got {}",
                        $len,
                        bytes.len()
                    ))
                })
            }
        }
    };
}

fixed_hex!(hex_12, 12);
fixed_hex!(hex_16, 16);

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_NAME: &str = "ALPHA";

    #[test]
    fn exchange_roundtrips_and_tampering_is_an_error() {
        let (request, decryptor) = EphemeralClient::new().sendable();
        let response = EphemeralServer::new()
            .encrypt_secret(&request, KEY_NAME, b"secret")
            .expect("encrypt");
        assert_eq!(
            decryptor
                .decrypt(KEY_NAME, &response)
                .expect("decrypt")
                .as_slice(),
            b"secret"
        );

        let (request, decryptor) = EphemeralClient::new().sendable();
        let mut response = EphemeralServer::new()
            .encrypt_secret(&request, KEY_NAME, b"secret")
            .expect("encrypt");
        response.ciphertext[0] ^= 1;
        assert!(decryptor.decrypt(KEY_NAME, &response).is_err());
    }

    /// The AAD binds the requested keystore name, so a release obtained for one key cannot be
    /// replayed to a client that asked for another.
    #[test]
    fn released_secret_is_bound_to_the_requested_key_name() {
        let (request, decryptor) = EphemeralClient::new().sendable();
        let response = EphemeralServer::new()
            .encrypt_secret(&request, KEY_NAME, b"secret")
            .expect("encrypt");
        assert!(matches!(
            decryptor.decrypt("BRAVO", &response),
            Err(ShareErr::Aead(_))
        ));

        let (request, _) = EphemeralClient::new().sendable();
        assert!(matches!(
            EphemeralServer::new().encrypt_secret(&request, "../escape", b"secret"),
            Err(ShareErr::InvalidKeyName { .. })
        ));
    }

    /// HKDF `info` carries both ephemeral public keys in a fixed order, so neither substituting a
    /// public key nor swapping the two roles yields the key the honest exchange derived.
    #[test]
    fn derived_key_binds_both_public_keys_in_order() {
        let salt = [3u8; SALT_LEN];
        let shared = [9u8; 32];
        let client = EphemeralKeyPair::new().public;
        let server = EphemeralKeyPair::new().public;
        let other = EphemeralKeyPair::new().public;

        let honest = derive_key(&salt, &shared, &client, &server).expect("derive");
        assert_eq!(
            &*honest,
            &*derive_key(&salt, &shared, &client, &server).expect("derive")
        );
        assert_ne!(
            &*honest,
            &*derive_key(&salt, &shared, &server, &client).expect("derive")
        );
        assert_ne!(
            &*honest,
            &*derive_key(&salt, &shared, &other, &server).expect("derive")
        );
        assert_ne!(
            &*honest,
            &*derive_key(&salt, &shared, &client, &other).expect("derive")
        );
    }

    #[test]
    fn malformed_hex_and_public_keys_are_refused_without_panicking() {
        for body in [r#"{"pubk":"zz"}"#, r#"{"pubk":"0x00"}"#] {
            assert!(serde_json::from_str::<ClientReq>(body).is_err());
        }
        let (request, _) = EphemeralClient::new().sendable();
        let mut value = serde_json::to_value(request).expect("serialize");
        value["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ClientReq>(value).is_err());
    }

    #[test]
    fn shared_secret_payloads_are_bounded_in_both_directions() {
        let (request, _) = EphemeralClient::new().sendable();
        assert!(matches!(
            EphemeralServer::new().encrypt_secret(
                &request,
                KEY_NAME,
                &vec![0u8; MAX_SHARED_SECRET_BYTES + 1]
            ),
            Err(ShareErr::PlaintextTooLarge { .. })
        ));

        let (_, decryptor) = EphemeralClient::new().sendable();
        let response = ServerEncryptedRes {
            ciphertext: vec![0u8; MAX_CIPHERTEXT_BYTES + 1],
            pubk: EphemeralKeyPair::new().public,
            nonce: [0u8; NONCE_LEN],
            salt: [0u8; SALT_LEN],
        };
        assert!(matches!(
            decryptor.decrypt(KEY_NAME, &response),
            Err(ShareErr::CiphertextTooLarge { .. })
        ));

        let json = format!(
            "{{\"ciphertext\":\"0x{}\",\"pubk\":\"0x{}\",\"nonce\":\"0x{}\",\"salt\":\"0x{}\"}}",
            "00".repeat(MAX_CIPHERTEXT_BYTES + 1),
            hex::encode(EphemeralKeyPair::new().public),
            "00".repeat(NONCE_LEN),
            "00".repeat(SALT_LEN),
        );
        assert!(serde_json::from_str::<ServerEncryptedRes>(&json).is_err());
    }
}
