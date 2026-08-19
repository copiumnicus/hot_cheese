//! Reference pinned client: `cargo run --release --example pin_cert -- <base_url> <key_name>`.
//!
//! Copy [`HotCheeseAgent`] into your own key consumers. Every `/read` costs the owner a
//! Touch ID approval, so this reads ONE key and never prints its bytes.
use err_mac::create_err_with_impls;
use hc_core::config::cert_paths;
use hc_core::crypto::envelope::write_private_file;
use hc_core::share::{EphemeralClient, ServerEncryptedRes, ShareErr};
use hc_daemon::{sk_to_adr, ApiBackendErr};
use pki_types::pem::PemObject;
use pki_types::CertificateDer;
use rand::{rngs::OsRng, RngCore};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use ureq::{self, Agent};
use zeroize::Zeroizing;

const DEFAULT_BASE_URL: &str = "https://localhost:5555";
const DEFAULT_KEY: &str = "opcode_solver";
const MAX_CERT_PEM_BYTES: u64 = 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;
const PIN_HEX_BYTES: u64 = 128;

/// Fingerprint an integrator verified out of band, as 64 hex characters.
const PIN_ENV: &str = "HOT_CHEESE_CERT_SHA256";

/// Where this client keeps its own first-use record, when it has no configured fingerprint.
const PIN_FILE_ENV: &str = "HOT_CHEESE_CLIENT_PIN";

/// Default for [`PIN_FILE_ENV`], under the CLIENT's home rather than the daemon's, because the
/// daemon rewrites everything in its own.
const PIN_FILE: &str = ".hot_cheese_client_pin";
/// A 32-byte secret is a secp256k1 key, so its EVM address can be re-derived locally.
const EVM_SECRET_LEN: usize = 32;

/// Random bytes prepended to the proof digest, drawn fresh for every read. An imported
/// secret may be a low-entropy passphrase, and a bare hash of one is guessable offline.
const PROOF_SALT_LEN: usize = 16;

/// Digest bytes kept for the operator's proof, hex-encoded to twice as many characters.
const PROOF_DIGEST_LEN: usize = 4;

/// The fingerprint this client demands of the daemon's leaf certificate. The daemon's own
/// `cert.pem` cannot be the anchor — the daemon rewrites it — so the anchor is either a value an
/// integrator verified out of band or the record this client wrote the first time it connected.
enum Pin {
    /// [`PIN_ENV`], decoded.
    Configured([u8; 32]),
    /// A file only this client writes, holding the fingerprint of the first certificate seen.
    FirstUse(PathBuf),
}

impl Pin {
    fn from_env() -> Result<Self, HotAgentErr> {
        if let Ok(configured) = std::env::var(PIN_ENV) {
            let mut pinned = [0u8; 32];
            hex::decode_to_slice(configured.trim(), &mut pinned)?;
            return Ok(Pin::Configured(pinned));
        }
        let path = match std::env::var(PIN_FILE_ENV) {
            Ok(path) => PathBuf::from(path),
            Err(_) => PathBuf::from(std::env::var("HOME").map_err(|_| HotAgentErr::NoPinLocation)?)
                .join(PIN_FILE),
        };
        Ok(Pin::FirstUse(path))
    }

    /// Fail closed on anything but the pinned fingerprint. A first use records what it saw and
    /// prints it to be checked out of band; every run after that compares, so a rotated — or
    /// substituted — certificate stops the client instead of being trusted silently.
    fn check(&self, found: [u8; 32]) -> Result<(), HotAgentErr> {
        let pinned = match self {
            Pin::Configured(pinned) => *pinned,
            Pin::FirstUse(path) => match hc_core::read_regular_file_bounded(path, PIN_HEX_BYTES) {
                Ok(recorded) => {
                    let mut pinned = [0u8; 32];
                    hex::decode_to_slice(String::from_utf8(recorded)?.trim(), &mut pinned)?;
                    pinned
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    write_private_file(path, hex::encode(found).as_bytes())?;
                    println!("pinned={} at {}", hex::encode(found), path.display());
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            },
        };
        match bool::from(pinned[..].ct_eq(&found[..])) {
            true => Ok(()),
            false => Err(HotAgentErr::PinMismatch {
                pinned: hex::encode(pinned),
                found: hex::encode(found),
            }),
        }
    }
}

pub struct HotCheeseAgent {
    agent: Agent,
    base: String,
}
impl HotCheeseAgent {
    /// Trust exactly one certificate: the daemon's leaf is read from its home dir
    /// (`$HOT_CHEESE_HOME`, else `~/.config/hot_cheese`) and is accepted only if its SHA-256
    /// matches [`Pin`]. Set [`PIN_ENV`] to the fingerprint you verified out of band; with
    /// nothing set, the first run records what it saw and every later run must match it.
    pub fn new(base: impl ToString) -> Result<Self, HotAgentErr> {
        let (cert_path, _key_path) = cert_paths();
        let cert_bytes = hc_core::read_regular_file_bounded(&cert_path, MAX_CERT_PEM_BYTES)?;
        let pinned_cert = CertificateDer::from_pem_slice(&cert_bytes)?;
        Pin::from_env()?.check(Sha256::digest(pinned_cert.as_ref()).into())?;

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
        response_text(res)
    }
    pub fn generate(&self, name: &str) -> Result<String, HotAgentErr> {
        let res = self
            .agent
            .post(format!("{}{}{}", self.base, "/evm_generate/", name).as_str())
            .set("Content-Type", "application/json")
            .send_bytes(&[])?;
        response_text(res)
    }
    pub fn address(&self, name: &str) -> Result<String, HotAgentErr> {
        let res = self
            .agent
            .post(format!("{}{}{}", self.base, "/evm_address/", name).as_str())
            .set("Content-Type", "application/json")
            .send_bytes(&[])?;
        response_text(res)
    }
    pub fn solana_address(&self, name: &str) -> Result<String, HotAgentErr> {
        let res = self
            .agent
            .post(format!("{}{}{}", self.base, "/solana_address/", name).as_str())
            .set("Content-Type", "application/json")
            .send_bytes(&[])?;
        response_text(res)
    }
    /// Ephemeral P-256 read: the secret is encrypted for this process only. Costs one Touch ID.
    pub fn read(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, HotAgentErr> {
        let client = EphemeralClient::new();
        let (to_send, decryptor) = client.sendable();
        let res = self
            .agent
            .post(format!("{}{}{}", self.base, "/read/", name).as_str())
            .set("Content-Type", "application/json")
            .send_bytes(&serde_json::to_vec(&to_send)?)?;
        let bytes = hc_core::read_bounded(res.into_reader(), MAX_RESPONSE_BYTES)?;
        let enc_res: ServerEncryptedRes = hc_core::wire::strict_json_from_slice(&bytes)?;
        Ok(decryptor.decrypt(name, &enc_res)?)
    }
}

fn response_text(res: ureq::Response) -> Result<String, HotAgentErr> {
    let bytes = hc_core::read_bounded(res.into_reader(), MAX_RESPONSE_BYTES)?;
    String::from_utf8(bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e).into())
}

create_err_with_impls!(
    #[derive(Debug)]
    pub HotAgentErr,
    NoPinLocation,
    Ureq(ureq::Error),
    Share(ShareErr),
    Serde(serde_json::Error),
    Pem(pki_types::pem::Error),
    Rustls(rustls::Error),
    Address(ApiBackendErr),
    Hex(hex::FromHexError),
    PinNotText(std::string::FromUtf8Error),
    IO(std::io::Error)
    ;
    PinMismatch { pinned: String, found: String }
);

fn main() -> Result<(), HotAgentErr> {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    let name = args.next().unwrap_or_else(|| DEFAULT_KEY.to_string());

    let agent = HotCheeseAgent::new(&base)?;
    println!("health={}", agent.health()?);

    let secret = agent.read(&name)?;
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
    println!("len={secret_len}");
    println!("digest={digest}");
    if let Some(address) = derived.transpose()? {
        println!("evm_address={address}");
    }
    Ok(())
}
