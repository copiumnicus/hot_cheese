use super::bytes_hex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
/// This struct represents the deserialized form of an encrypted JSON keystore based on the
/// [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).
pub struct EthKeystore {
    pub crypto: CryptoJson,
    pub version: u8,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "crypto" part of an encrypted JSON keystore.
pub struct CryptoJson {
    pub cipher: String,
    pub cipherparams: CipherparamsJson,
    #[serde(with = "bytes_hex")]
    pub ciphertext: Vec<u8>,
    pub kdfparams: KdfparamsType,
    #[serde(with = "bytes_hex")]
    pub mac: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "cipherparams" part of an encrypted JSON keystore.
pub struct CipherparamsJson {
    #[serde(with = "bytes_hex")]
    pub iv: Vec<u8>,
}

// ONLY SCRYPT
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Defines the various parameters used in the supported KDFs.
pub struct KdfparamsType {
    pub dklen: u8,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    #[serde(with = "bytes_hex")]
    pub salt: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::to_vec;

    #[test]
    fn test_deserialize_scrypt() {
        let data = r#"
        {
            "crypto" : {
                "cipher" : "aes-128-ctr",
                "cipherparams" : {
                    "iv" : "83dbcc02d8ccb40e466191a123791e0e"
                },
                "ciphertext" : "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
                "kdfparams" : {
                    "dklen" : 32,
                    "n" : 262144,
                    "p" : 8,
                    "r" : 1,
                    "salt" : "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                },
                "mac" : "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
            },
            "version" : 3
        }"#;
        let keystore: EthKeystore = serde_json::from_str(data).unwrap();
        assert_eq!(keystore.version, 3);
        assert_eq!(keystore.crypto.cipher, "aes-128-ctr");
        assert_eq!(
            keystore.crypto.cipherparams.iv,
            to_vec("83dbcc02d8ccb40e466191a123791e0e").unwrap()
        );
        assert_eq!(
            keystore.crypto.ciphertext,
            to_vec("d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c").unwrap()
        );
        assert_eq!(
            keystore.crypto.kdfparams,
            KdfparamsType {
                dklen: 32,
                n: 262144,
                p: 8,
                r: 1,
                salt: to_vec("ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19")
                    .unwrap(),
            }
        );
        assert_eq!(
            keystore.crypto.mac,
            to_vec("2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097").unwrap()
        );
    }
}
