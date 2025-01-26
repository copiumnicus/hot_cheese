use crate::crypto::{decrypt_key, encrypt_key, keccak256, random_pk, CryptoErr};
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
use std::io::{BufReader, Cursor};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroize;

fn resolve_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home_dir) = std::env::var("HOME") {
            return PathBuf::from(home_dir).join(path.trim_start_matches("~/"));
        }
    }
    PathBuf::from(path) // Fallback: return the path as-is
}

fn load_certs() -> io::Result<Vec<CertificateDer<'static>>> {
    let cert = include_bytes!("ssl-cert.pem");
    let mut reader = BufReader::new(Cursor::new(cert));
    rustls_pemfile::certs(&mut reader).collect()
}
fn load_private_key() -> io::Result<PrivateKeyDer<'static>> {
    let key = include_bytes!("ssl-key.pem");
    let mut reader = BufReader::new(Cursor::new(key));
    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}
#[tokio::main]
pub async fn run_server(
    backend: Box<dyn BackendImpl>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // First parameter is port number (optional, defaults to 1337)
    let port = 5555;
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);

    let certs = load_certs()?;
    let key = load_private_key()?;

    println!("Starting to serve on https://{}", addr);

    // Create a TCP listener via tokio.
    let incoming = TcpListener::bind(&addr).await?;

    // Build TLS configuration.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let api = Arc::new(HotApi { inner: backend });

    let wrapped = move |mut req: Request<_>| {
        let inner = api.clone();
        async move {
            req.extensions_mut().insert(inner);
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
                    eprintln!("failed to perform tls handshake: {err:#}");
                    return;
                }
            };
            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls_stream), service)
                .await
            {
                eprintln!("failed to serve connection: {err:#}");
            }
        });
    }
}

fn is_valid_string_name(name: &str) -> bool {
    // Check that all characters in the name are valid (a-z, A-Z, _)
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

create_err_with_impls!(
    #[derive(Debug)]
    pub ApiBackendErr,
    KeyExists,
    FailCastToEvmKey(String),
    Serde(serde_json::Error),
    KeyNotExists,
    NotDeviceOwner,
    Unspecified(Unspecified),
    FailedToGetEncryptionKey,
    Crypto(CryptoErr)
    ;
);

pub trait BackendImpl: Send + Sync {
    fn is_device_owner(&self, reason: &str) -> bool;
    fn get_encryption_key(&self) -> Option<Vec<u8>>;
    fn store(&self) -> &str;
    fn communicate_err(&self, e: String);

    fn store_path(&self) -> PathBuf {
        let buf = resolve_path(self.store());
        if !buf.exists() {
            if let Err(e) = create_dir_all(buf.clone()) {
                eprintln!("failed create keys dir {}", e)
            }
        }
        buf
    }
    fn assert_owner_get_encryption_key(&self, reason: &str) -> Result<Vec<u8>, ApiBackendErr> {
        if !self.is_device_owner(reason) {
            return Err(ApiBackendErr::NotDeviceOwner);
        }
        self.get_encryption_key()
            .ok_or(ApiBackendErr::FailedToGetEncryptionKey)
    }
}

pub struct HotApi {
    inner: Box<dyn BackendImpl>,
}

fn sk_to_adr(key: &[u8]) -> Result<String, ApiBackendErr> {
    use k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    let sk =
        SigningKey::from_slice(key).map_err(|e| ApiBackendErr::FailCastToEvmKey(e.to_string()))?;
    let pubk = PublicKey::from_secret_scalar(sk.as_nonzero_scalar());
    let pubk = pubk.to_encoded_point(/* compress = */ false);
    let pubk = pubk.as_bytes();
    debug_assert_eq!(pubk[0], 0x04);
    let hash = keccak256(pubk[1..].to_vec());
    Ok(to_hex_str(&hash[12..]))
}

impl HotApi {
    pub fn address(&self, name: &str) -> Result<String, ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(name);
        if !path.exists() {
            return Err(ApiBackendErr::KeyNotExists);
        }
        let mut password = self.inner.assert_owner_get_encryption_key(
            format!("trying to get address '{}'", name).as_str(),
        )?;
        let mut key = decrypt_key(path, &password)?;
        let addr = sk_to_adr(&key)?;
        password.zeroize();
        key.zeroize();
        Ok(addr)
    }
    pub fn generate(&self, name: &str) -> Result<(), ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(name);
        if path.exists() {
            return Err(ApiBackendErr::KeyExists);
        }
        let mut rng = rand::rngs::OsRng;
        let mut pk = random_pk(&mut rng).to_bytes().to_vec();
        // SECURITY
        let mut password = self
            .inner
            .assert_owner_get_encryption_key(format!("trying to generate '{}'", name).as_str())?;
        encrypt_key(self.inner.store_path(), &mut rng, &pk, &password, name)?;
        pk.zeroize();
        password.zeroize();
        Ok(())
    }
    pub fn read(&self, body: &[u8], name: &str) -> Result<Vec<u8>, ApiBackendErr> {
        let req: ClientReq = serde_json::from_slice(body)?;
        let path = Path::new(&self.inner.store_path()).join(name);
        if !path.exists() {
            return Err(ApiBackendErr::KeyNotExists);
        }
        println!("client pubk {}", df_share::to_hex_str(&req.pubk));
        let mut password = self
            .inner
            .assert_owner_get_encryption_key(format!("trying to read '{}'", name).as_str())?;
        let mut key = decrypt_key(path, &password)?;
        let server = EphemeralServer::new()?;
        let res = server.encrypt_secret(&req, &key)?;
        password.zeroize();
        key.zeroize();
        Ok(serde_json::to_vec(&res)?)
    }
}

async fn service_impl(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = Response::new(Full::default());

    let hot = req.extensions().get::<Arc<HotApi>>().unwrap().clone();

    let path = req.uri().path().to_string();
    println!("req {}", path);
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
                    hot.inner.communicate_err(e.to_string())
                }
            }
        }
    }
    if let Some(name) = path.strip_prefix("/evm_generate/") {
        if is_valid_string_name(name) {
            match hot.generate(name) {
                Ok(_) => {
                    *response.body_mut() = "success".as_bytes().to_vec().into();
                }
                Err(e) => {
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    hot.inner.communicate_err(e.to_string());
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
                    hot.inner.communicate_err(e.to_string());
                }
            }
        }
    }
    Ok(response)
}

#[cfg(test)]
mod test {
    use super::*;

    struct TestBackend {}
    impl BackendImpl for TestBackend {
        fn communicate_err(&self, e: String) {
            eprintln!("{:?}", e)
        }
        fn get_encryption_key(&self) -> Option<Vec<u8>> {
            Some(
                "I_am_a_secret_that_should_not_be_In_memory"
                    .as_bytes()
                    .to_vec(),
            )
        }
        fn is_device_owner(&self, _: &str) -> bool {
            true
        }
        fn store(&self) -> &str {
            "~/HOT_CHEESE_TEST"
        }
    }

    #[test]
    fn encrypt_existing() {
        let inner = TestBackend {};

        // input
        let name = "encrypt_existing";
        let pk = vec![0, 0, 0];

        let mut rng = rand::rngs::OsRng;
        let password = inner.assert_owner_get_encryption_key("hi").unwrap();
        encrypt_key(inner.store_path(), &mut rng, &pk, &password, name).unwrap();
    }
}
