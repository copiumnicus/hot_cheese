use crate::backup;
use crate::config::{cert_paths, Config};
use crate::crypto::envelope::{decrypt_file, encrypt_file, Dek};
use crate::crypto::{keccak256, random_pk};
use crate::unlock::UnlockErr;
use df_share::error::Unspecified;
use df_share::{to_hex_str, ClientReq, EphemeralServer};
use err_mac::create_err_with_impls;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs::create_dir_all;
use std::io;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroize;

pub fn resolve_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home_dir) = std::env::var("HOME") {
            return PathBuf::from(home_dir).join(path.trim_start_matches("~/"));
        }
    }
    PathBuf::from(path) // Fallback: return the path as-is
}

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(std::fs::File::open(path)?);
    rustls_pemfile::certs(&mut reader).collect()
}
fn load_private_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(std::fs::File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found in PEM"))
}

#[tokio::main]
pub async fn run_server(
    backend: Box<dyn BackendImpl>,
    config: Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (cert_path, key_path) = cert_paths();
    let certs = load_certs(&cert_path)?;
    let key = load_private_key(&key_path)?;

    let port = config.port();
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
    tracing::info!(%addr, "hot_cheese serving over https");

    // Create a TCP listener via tokio.
    let incoming = TcpListener::bind(&addr).await?;

    // Build TLS configuration.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let api = Arc::new(HotApi { inner: backend });
    let cfg = Arc::new(config);

    let wrapped = move |mut req: Request<_>| {
        let inner = api.clone();
        let cfg = cfg.clone();
        async move {
            req.extensions_mut().insert(inner);
            req.extensions_mut().insert(cfg);
            service_impl(req).await
        }
    };
    let service = service_fn(wrapped);

    loop {
        let (tcp_stream, _remote_addr) = incoming.accept().await?;

        let service = service.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => tls_stream,
                Err(err) => {
                    tracing::error!(error = %err, "tls handshake failed");
                    return;
                }
            };
            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls_stream), service)
                .await
            {
                tracing::error!(error = %err, "failed to serve connection");
            }
        });
    }
}

pub(crate) fn is_valid_string_name(name: &str) -> bool {
    // Check that all characters in the name are valid (a-z, A-Z, 0-9, _)
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

create_err_with_impls!(
    #[derive(Debug)]
    pub ApiBackendErr,
    KeyExists,
    FailReadKeypair,
    KeyNotExists,
    Serde(serde_json::Error),
    Unspecified(Unspecified),
    Unlock(UnlockErr),
    Envelope(crate::crypto::envelope::EnvErr),
    Ecdsa(k256::ecdsa::Error)
    ;
);

/// The backend supplies the Data Encryption Key (per request) and the store location.
/// Unlocking is where the Touch ID / Secure Enclave gate lives now — see `unlock_dek`.
pub trait BackendImpl: Send + Sync {
    /// Unwrap the DEK for a single operation. `reason` is surfaced to the user
    /// (e.g. the biometric prompt). The returned DEK is zeroized when dropped.
    fn unlock_dek(&self, reason: &str) -> Result<Dek, ApiBackendErr>;
    fn store(&self) -> &str;
    fn communicate_err(&self, e: String);

    fn store_path(&self) -> PathBuf {
        let buf = resolve_path(self.store());
        if !buf.exists() {
            if let Err(e) = create_dir_all(buf.clone()) {
                tracing::error!(error = %e, "failed to create keys dir");
            }
        }
        buf
    }
}

pub struct HotApi {
    inner: Box<dyn BackendImpl>,
}

pub(crate) fn sk_to_adr(key: &[u8]) -> Result<String, ApiBackendErr> {
    use k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    let sk = SigningKey::from_slice(key)?;
    let pubk = PublicKey::from_secret_scalar(sk.as_nonzero_scalar());
    let pubk = pubk.to_encoded_point(/* compress = */ false);
    let pubk = pubk.as_bytes();
    debug_assert_eq!(pubk[0], 0x04);
    let hash = keccak256(pubk[1..].to_vec());
    Ok(to_hex_str(&hash[12..]))
}

impl HotApi {
    pub fn new(inner: Box<dyn BackendImpl>) -> Self {
        Self { inner }
    }

    pub fn address(&self, name: &str) -> Result<String, ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(name);
        if !path.exists() {
            return Err(ApiBackendErr::KeyNotExists);
        }
        let dek = self.inner.unlock_dek(&format!("get address '{}'", name))?;
        let mut key = decrypt_file(&path, name, &dek)?;
        let addr = sk_to_adr(&key);
        key.zeroize();
        addr
    }
    pub fn address_solana(&self, name: &str) -> Result<String, ApiBackendErr> {
        use solana_signer::Signer;
        let path = Path::new(&self.inner.store_path()).join(name);
        if !path.exists() {
            return Err(ApiBackendErr::KeyNotExists);
        }
        let dek = self
            .inner
            .unlock_dek(&format!("get solana address '{}'", name))?;
        let mut key = decrypt_file(&path, name, &dek)?;
        let keypair = solana_keypair::Keypair::from_bytes(&key)
            .map_err(|_| ApiBackendErr::FailReadKeypair)?;
        let addr = keypair.pubkey();
        key.zeroize();
        Ok(addr.to_string())
    }
    pub fn generate_solana(&self, name: &str) -> Result<(), ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(name);
        if path.exists() {
            return Err(ApiBackendErr::KeyExists);
        }
        let mut pk = solana_keypair::Keypair::new().to_bytes();
        let dek = self
            .inner
            .unlock_dek(&format!("generate solana key '{}'", name))?;
        encrypt_file(&self.inner.store_path(), name, &dek, &pk)?;
        pk.zeroize();
        Ok(())
    }
    pub fn generate(&self, name: &str) -> Result<(), ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(name);
        if path.exists() {
            return Err(ApiBackendErr::KeyExists);
        }
        let mut rng = rand::rngs::OsRng;
        let mut pk = random_pk(&mut rng).to_bytes().to_vec();
        let dek = self.inner.unlock_dek(&format!("generate '{}'", name))?;
        encrypt_file(&self.inner.store_path(), name, &dek, &pk)?;
        pk.zeroize();
        Ok(())
    }
    /// read works for both solana/evm
    pub fn read(&self, body: &[u8], name: &str) -> Result<Vec<u8>, ApiBackendErr> {
        let req: ClientReq = serde_json::from_slice(body)?;
        let path = Path::new(&self.inner.store_path()).join(name);
        if !path.exists() {
            return Err(ApiBackendErr::KeyNotExists);
        }
        tracing::info!("client pubk:\n{}", df_share::generate_ascii_art(&req.pubk));
        let dek = self.inner.unlock_dek(&format!("read '{}'", name))?;
        let mut key = decrypt_file(&path, name, &dek)?;
        let server = EphemeralServer::new()?;
        let res = server.encrypt_secret(&req, &key)?;
        key.zeroize();
        Ok(serde_json::to_vec(&res)?)
    }
}

/// Best-effort backup push after a mutating HTTP request (key generation), offloaded to a
/// blocking task so rsync never blocks the async handler. No-op without configured remotes.
fn backup_after_mutation(cfg: &Option<Arc<Config>>) {
    if let Some(cfg) = cfg {
        if !cfg.backup_remotes.is_empty() {
            let cfg = cfg.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = backup::push_all(&cfg) {
                    tracing::warn!(error = %e, "post-generate backup push failed");
                }
            });
        }
    }
}

async fn service_impl(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = Response::new(Full::default());

    let hot = req.extensions().get::<Arc<HotApi>>().unwrap().clone();
    let cfg = req.extensions().get::<Arc<Config>>().cloned();

    let path = req.uri().path().to_string();
    tracing::debug!(path = %path, "request");
    if path.ends_with("/health") {
        *response.body_mut() = "ok".as_bytes().to_vec().into();
    }
    if let Some(name) = path.strip_prefix("/read/") {
        if is_valid_string_name(name) {
            let body = req.collect().await?.to_bytes();
            match hot.read(&body, name) {
                Ok(v) => {
                    *response.body_mut() = v.into();
                }
                Err(e) => {
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    hot.inner.communicate_err(format!("{:?}", e))
                }
            }
        }
    }
    if let Some(name) = path.strip_prefix("/evm_generate/") {
        if is_valid_string_name(name) {
            match hot.generate(name) {
                Ok(_) => {
                    *response.body_mut() = "success".as_bytes().to_vec().into();
                    backup_after_mutation(&cfg);
                }
                Err(e) => {
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    hot.inner.communicate_err(format!("{:?}", e));
                }
            }
        }
    }
    // useful for safely verifying that encryption process was successful
    if let Some(name) = path.strip_prefix("/evm_address/") {
        if is_valid_string_name(name) {
            match hot.address(name) {
                Ok(addr) => {
                    *response.body_mut() = addr.as_bytes().to_vec().into();
                }
                Err(e) => {
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    hot.inner.communicate_err(format!("{:?}", e));
                }
            }
        }
    }
    // solana
    if let Some(name) = path.strip_prefix("/solana_generate/") {
        if is_valid_string_name(name) {
            match hot.generate_solana(name) {
                Ok(_) => {
                    *response.body_mut() = "success".as_bytes().to_vec().into();
                    backup_after_mutation(&cfg);
                }
                Err(e) => {
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    hot.inner.communicate_err(format!("{:?}", e));
                }
            }
        }
    }
    if let Some(name) = path.strip_prefix("/solana_address/") {
        if is_valid_string_name(name) {
            match hot.address_solana(name) {
                Ok(addr) => {
                    *response.body_mut() = addr.as_bytes().to_vec().into();
                }
                Err(e) => {
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    hot.inner.communicate_err(format!("{:?}", e));
                }
            }
        }
    }
    Ok(response)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::envelope::Dek;

    struct TestBackend {
        store: String,
    }
    impl BackendImpl for TestBackend {
        fn unlock_dek(&self, _reason: &str) -> Result<Dek, ApiBackendErr> {
            Ok(Dek::from_bytes([42u8; 32]))
        }
        fn store(&self) -> &str {
            &self.store
        }
        fn communicate_err(&self, e: String) {
            tracing::error!("{e}");
        }
    }

    #[test]
    fn generate_then_address_roundtrips_through_envelope() {
        let dir = std::env::temp_dir().join("hot_cheese_server_test");
        let _ = std::fs::remove_dir_all(&dir);
        let api = HotApi {
            inner: Box::new(TestBackend {
                store: dir.to_string_lossy().to_string(),
            }),
        };
        api.generate("EVM_TEST").unwrap();
        let a1 = api.address("EVM_TEST").unwrap();
        let a2 = api.address("EVM_TEST").unwrap();
        assert_eq!(a1, a2, "address must be deterministic across decrypts");
        assert!(!a1.is_empty());
        // regenerate must refuse to overwrite an existing key
        assert!(matches!(
            api.generate("EVM_TEST"),
            Err(ApiBackendErr::KeyExists)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
