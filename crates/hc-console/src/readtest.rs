//! The console's own pinned `/read` client, proving the daemon really releases a key over the
//! same TLS route a remote consumer uses. It must run as a tokio task: on the main thread it
//! would block waiting for the approval only the main thread can grant.
use df_share::{EphemeralClient, ServerEncryptedRes};
use err_mac::create_err_with_impls;
use hc_core::config::cert_paths;
use hc_daemon::sk_to_adr;
use http::{header::HOST, Method, Request};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use pki_types::pem::PemObject;
use pki_types::{CertificateDer, ServerName};
use rand::{rngs::OsRng, RngCore};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use zeroize::Zeroize;

/// A 32-byte secret is a secp256k1 key, so its EVM address can be re-derived locally.
const EVM_SECRET_LEN: usize = 32;

/// Random bytes prepended to the proof digest, drawn fresh for every read test. An imported
/// secret may be a low-entropy passphrase, and a bare hash of one is guessable offline.
const PROOF_SALT_LEN: usize = 16;

/// Digest bytes kept for the operator's proof, hex-encoded to twice as many characters.
const PROOF_DIGEST_LEN: usize = 4;

create_err_with_impls!(
    #[derive(Debug)]
    pub ReadTestErr,
    Serde(serde_json::Error),
    Rustls(rustls::Error),
    Pem(pki_types::pem::Error),
    Http(http::Error),
    Hyper(hyper::Error),
    DfShare(df_share::error::Unspecified),
    Address(hc_daemon::ApiBackendErr),
    StdIo(std::io::Error)
    ;
    BadStatus { status: u16 }
);

/// What one read test proved. The secret itself is zeroized before this is built.
pub struct ReadProof {
    /// Key that was read.
    pub key: String,
    /// Length of the recovered secret.
    pub secret_len: usize,
    /// Salted, truncated SHA-256 of the recovered secret, hex; meaningful only within this read.
    pub digest: String,
    /// EVM address, present only when the secret is a 32-byte secp256k1 key.
    pub evm_address: Option<String>,
}

/// Put the read test on the runtime and hand the main thread a handle: it must keep
/// approving privileged ops while this is in flight, so it never holds the future itself.
pub fn spawn(
    runtime: &Handle,
    addr: SocketAddr,
    key: String,
) -> JoinHandle<Result<ReadProof, ReadTestErr>> {
    runtime.spawn(read_test(addr, key))
}

/// Run one df-share `/read` against `addr`, pinning the cert `init` wrote.
async fn read_test(addr: SocketAddr, key: String) -> Result<ReadProof, ReadTestErr> {
    let (cert_path, _key_path) = cert_paths();
    let pinned = CertificateDer::from_pem_slice(&std::fs::read(cert_path)?)?;
    let mut roots = RootCertStore::empty();
    roots.add(pinned)?;
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();

    let (client_req, decryptor) = EphemeralClient::new()?.sendable();
    let tcp = TcpStream::connect(addr).await?;
    let stream = TlsConnector::from(Arc::new(tls))
        .connect(ServerName::from(addr.ip()), tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "read test connection ended");
        }
    });

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/read/{key}"))
        .header(HOST, addr.to_string())
        .body(Full::new(Bytes::from(serde_json::to_vec(&client_req)?)))?;
    let res = sender.send_request(req).await?;
    let status = res.status();
    if !status.is_success() {
        return Err(ReadTestErr::BadStatus {
            status: status.as_u16(),
        });
    }
    let body = res.into_body().collect().await?.to_bytes();

    let encrypted: ServerEncryptedRes = serde_json::from_slice(&body)?;
    let mut secret = decryptor.decrypt(&encrypted)?;
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

    Ok(ReadProof {
        key,
        secret_len,
        digest,
        evm_address: derived.transpose()?,
    })
}
