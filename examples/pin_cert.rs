//! Reference pinned client: `cargo run --release --example pin_cert -- <base_url> <key_name>`.
//!
//! Copy [`HotCheeseAgent`] into your own key consumers. Every `/read` costs the owner a
//! Touch ID approval, so this reads ONE key and never prints its bytes.
use df_share::*;
use err_mac::create_err_with_impls;
use error::Unspecified;
use hot_cheese::config::cert_paths;
use hot_cheese::server::{sk_to_adr, ApiBackendErr};
use pki_types::pem::PemObject;
use pki_types::CertificateDer;
use rand::{rngs::OsRng, RngCore};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use ureq::{self, Agent};
use zeroize::Zeroize;

const DEFAULT_BASE_URL: &str = "https://localhost:5555";
const DEFAULT_KEY: &str = "opcode_solver";
/// A 32-byte secret is a secp256k1 key, so its EVM address can be re-derived locally.
const EVM_SECRET_LEN: usize = 32;

/// Random bytes prepended to the proof digest, drawn fresh for every read. An imported
/// secret may be a low-entropy passphrase, and a bare hash of one is guessable offline.
const PROOF_SALT_LEN: usize = 16;

/// Digest bytes kept for the operator's proof, hex-encoded to twice as many characters.
const PROOF_DIGEST_LEN: usize = 4;

pub struct HotCheeseAgent {
    agent: Agent,
    base: String,
}
impl HotCheeseAgent {
    /// Pin the cert `hot_cheese init` generated, read at runtime from the daemon's home dir
    /// (`$HOT_CHEESE_HOME`, else `~/.config/hot_cheese`) — verify the printed SHA-256
    /// fingerprint out-of-band the first time.
    pub fn new(base: impl ToString) -> Result<Self, HotAgentErr> {
        let (cert_path, _key_path) = cert_paths();
        let cert_bytes = std::fs::read(&cert_path)?;
        let pinned_cert = CertificateDer::from_pem_slice(&cert_bytes)?;

        let mut root_store = RootCertStore::empty();
        root_store.add(pinned_cert)?;

        let tls_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        Ok(Self {
            base: base.to_string(),
            agent: ureq::builder()
                .https_only(true)
                .tls_config(tls_config)
                .build(),
        })
    }

    pub fn health(&self) -> Result<String, HotAgentErr> {
        let res = self
            .agent
            .get(format!("{}{}", self.base, "/health").as_str())
            .call()?;
        Ok(res.into_string()?)
    }
    pub fn generate(&self, name: &str) -> Result<String, HotAgentErr> {
        let res = self
            .agent
            .get(format!("{}{}{}", self.base, "/evm_generate/", name).as_str())
            .call()?;
        Ok(res.into_string()?)
    }
    pub fn address(&self, name: &str) -> Result<String, HotAgentErr> {
        let res = self
            .agent
            .get(format!("{}{}{}", self.base, "/evm_address/", name).as_str())
            .call()?;
        Ok(res.into_string()?)
    }
    pub fn solana_address(&self, name: &str) -> Result<String, HotAgentErr> {
        let res = self
            .agent
            .get(format!("{}{}{}", self.base, "/solana_address/", name).as_str())
            .call()?;
        Ok(res.into_string()?)
    }
    /// df-share DH read: the secret is encrypted for this process only. Costs one Touch ID.
    pub fn read(&self, name: &str) -> Result<Vec<u8>, HotAgentErr> {
        let client = EphemeralClient::new()?;
        let (to_send, decryptor) = client.sendable();
        let res = self
            .agent
            .get(format!("{}{}{}", self.base, "/read/", name).as_str())
            .send_bytes(&serde_json::to_vec(&to_send)?)?;
        let enc_res: ServerEncryptedRes = serde_json::from_reader(res.into_reader())?;
        Ok(decryptor.decrypt(&enc_res)?)
    }
}

create_err_with_impls!(
    #[derive(Debug)]
    pub HotAgentErr,
    Ureq(ureq::Error),
    Unspecified(Unspecified),
    Serde(serde_json::Error),
    Pem(pki_types::pem::Error),
    Rustls(rustls::Error),
    Address(ApiBackendErr),
    IO(std::io::Error)
    ;
);

fn main() -> Result<(), HotAgentErr> {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    let name = args.next().unwrap_or_else(|| DEFAULT_KEY.to_string());

    let agent = HotCheeseAgent::new(&base)?;
    println!("health={}", agent.health()?);

    let mut secret = agent.read(&name)?;
    let secret_len = secret.len();
    let mut salt = [0u8; PROOF_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(&secret);
    let digest = hex::encode(&hasher.finalize()[..PROOF_DIGEST_LEN]);
    let derived = if secret_len == EVM_SECRET_LEN {
        Some(sk_to_adr(&secret))
    } else {
        None
    };
    secret.zeroize();

    println!("len={secret_len}");
    println!("digest={digest}");
    if let Some(address) = derived.transpose()? {
        println!("evm_address={address}");
    }
    Ok(())
}
