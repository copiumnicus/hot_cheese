use crate::crypto::{decrypt_key, encrypt_key, random_pk, to_str, CryptoErr};
use err_mac::create_err_with_impls;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Buf, Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::borrow::Cow;
use std::fmt::Display;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{env, fs, io};
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

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main]
pub async fn run_server(
    backend: Box<dyn BackendImpl>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // First parameter is port number (optional, defaults to 1337)
    let port = 5555;
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);

    // Load public certificate.
    let certs = load_certs("src/ssl-cert.pem")?;
    // Load private key.
    let key = load_private_key("src/ssl-key.pem")?;

    println!("Starting to serve on https://{}", addr);

    // Create a TCP listener via tokio.
    let incoming = TcpListener::bind(&addr).await?;

    // Build TLS configuration.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| error(e.to_string()))?;
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
    KeyNotExists,
    NotDeviceOwner,
    FailedToGetEncryptionKey,
    Crypto(CryptoErr)
    ;
);

pub trait BackendImpl: Send + Sync {
    fn is_device_owner(&self) -> bool;
    fn get_encryption_key(&self) -> Option<Vec<u8>>;
    fn store(&self) -> &str;
    fn communicate_err(&self, e: String);

    fn store_path(&self) -> PathBuf {
        resolve_path(self.store())
    }
}

pub struct HotApi {
    inner: Box<dyn BackendImpl>,
}

impl HotApi {
    pub fn generate(&self, name: &str) -> Result<(), ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(name);
        if path.exists() {
            return Err(ApiBackendErr::KeyExists);
        }
        let mut rng = rand::rngs::OsRng::default();
        let mut pk = random_pk(&mut rng).to_bytes().to_vec();
        // SECURITY
        let mut password = self.assert_owner_get_encryption_key()?;
        encrypt_key(self.inner.store_path(), &mut rng, &pk, &password, name)?;
        pk.zeroize();
        password.zeroize();
        Ok(())
    }
    pub fn read(&self, name: &str) -> Result<String, ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(name);
        if !path.exists() {
            return Err(ApiBackendErr::KeyNotExists);
        }
        let mut password = self.assert_owner_get_encryption_key()?;
        let key = decrypt_key(path, &password)?;
        password.zeroize();
        Ok(to_str(key))
    }
    fn assert_owner_get_encryption_key(&self) -> Result<Vec<u8>, ApiBackendErr> {
        if !self.inner.is_device_owner() {
            return Err(ApiBackendErr::NotDeviceOwner);
        }
        self.inner
            .get_encryption_key()
            .ok_or(ApiBackendErr::FailedToGetEncryptionKey)
    }
}

pub struct VecZeroize {
    v: Vec<u8>,
    pos: usize, // Track the position in the buffer
}
impl VecZeroize {
    fn new(v: Vec<u8>) -> Self {
        VecZeroize { v, pos: 0 }
    }
    fn zeroize_data(&mut self) {
        println!("zeroize");
        self.v.zeroize();
        self.pos = 0; // Reset position as well after zeroizing
    }
}
impl Drop for VecZeroize {
    fn drop(&mut self) {
        self.zeroize_data();
    }
}
impl Buf for VecZeroize {
    fn remaining(&self) -> usize {
        let a = self.v.len() - self.pos;
        println!("remaininig {}", a);
        a
    }
    fn chunk(&self) -> &[u8] {
        println!("chunk {}", self.pos);
        &self.v[self.pos..]
    }
    fn advance(&mut self, cnt: usize) {
        println!("advance {}", cnt);
        self.pos = self.pos.saturating_add(cnt);
        // You can zeroize data if you want to clear it when advancing:
        // This is optional depending on your security requirements.
        if self.pos >= self.v.len() {
            self.zeroize_data(); // If we reach the end, zeroize the data
        }
    }
}

async fn service_impl(req: Request<Incoming>) -> Result<Response<Full<VecZeroize>>, hyper::Error> {
    let mut response = Response::new(Full::default());

    let hot = req.extensions().get::<Arc<HotApi>>().unwrap();

    let path = req.uri().path();
    if let Some(name) = path.strip_prefix("/read/") {
        if is_valid_string_name(name) {
            println!("read");
            match hot.read(name) {
                Ok(mut v) => {
                    *response.body_mut() = Full::new(VecZeroize::new(v.as_bytes().to_vec()));
                    v.zeroize();
                }
                Err(e) => {
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    hot.inner.communicate_err(e.to_string())
                }
            }
        }
    }
    if let Some(name) = path.strip_prefix("/generate/") {
        if is_valid_string_name(name) {
            println!("generate");
            match hot.generate(name) {
                Ok(_) => {
                    *response.body_mut() =
                        Full::new(VecZeroize::new("success".as_bytes().to_vec()));
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

// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    // Open certificate file.
    let certfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    rustls_pemfile::certs(&mut reader).collect()
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
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
        fn is_device_owner(&self) -> bool {
            true
        }
        fn store(&self) -> &str {
            "~/HOT_CHEESE_TEST"
        }
    }

    #[test]
    fn test_run_local() {
        let _ = run_server(Box::new(TestBackend {}));
    }
}
