use crate::backup;
use crate::config::{cert_paths, Config};
use crate::crypto::envelope::{decrypt_file, encrypt_file, Dek};
use crate::crypto::{keccak256, random_pk};
use crate::mac::local_auth::LaContext;
use crate::sign::{self, SafeSignature, SignErr, SignResponse};
use crate::unlock::UnlockErr;
use alloy_primitives::{Address, Bytes as SafeBytes, B256};
use df_share::error::Unspecified;
use df_share::{to_hex_str, ClientReq, EphemeralServer};
use err_mac::create_err_with_impls;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fmt;
use std::fs::create_dir_all;
use std::io;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroize;

pub fn resolve_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home_dir) = std::env::var("HOME") {
            return PathBuf::from(home_dir).join(path.trim_start_matches("~/"));
        }
    }
    PathBuf::from(path)
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

create_err_with_impls!(
    #[derive(Debug)]
    pub ServeErr,
    StdIo(io::Error),
    Rustls(rustls::Error)
    ;
);

/// Install the ring provider, load the pinned cert/key `init` wrote, and build the acceptor.
pub fn tls_from_home() -> Result<TlsAcceptor, ServeErr> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert_path, key_path) = cert_paths();
    let certs = load_certs(&cert_path)?;
    let key = load_private_key(&key_path)?;
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// `hot_cheese serve`: bind loopback and unlock inside each connection task via the TTY approver.
#[tokio::main]
pub async fn run_server(backend: Box<dyn BackendImpl>, config: Config) -> Result<(), ServeErr> {
    let tls = tls_from_home()?;
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), config.port());
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "hot_cheese serving over https");

    let approval = Approval::Inline {
        api: Arc::new(HotApi::new(backend)),
        approver: Arc::new(crate::sign::approval::ServeApprover),
    };
    let (_shutdown, rx) = watch::channel(false);
    serve_loop(listener, tls, Arc::new(config), approval, rx).await
}

/// How long the accept loop waits after a failed `accept` before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Accept TLS connections until `shutdown` fires, serving each on its own task. A failed
/// `accept` (the peer vanished, descriptors ran out) is transient: it is logged and retried
/// after [`ACCEPT_BACKOFF`], never taken as the end of the listener.
pub async fn serve_loop(
    listener: TcpListener,
    tls: TlsAcceptor,
    config: Arc<Config>,
    approval: Approval,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServeErr> {
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = shutdown.changed() => return Ok(()),
        };
        let (tcp_stream, remote_addr) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed, retrying");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        tracing::debug!(%remote_addr, "accepted a connection");
        let tls = tls.clone();
        let config = config.clone();
        let approval = approval.clone();
        tokio::spawn(async move {
            let tls_stream = match tls.accept(tcp_stream).await {
                Ok(tls_stream) => tls_stream,
                Err(err) => {
                    tracing::error!(error = %err, "tls handshake failed");
                    return;
                }
            };
            let service = service_fn(move |req| {
                let config = config.clone();
                let approval = approval.clone();
                async move { service_impl(req, config, approval).await }
            });
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
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A route that costs the key owner one approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Read,
    Sign,
    EvmGenerate,
    SolanaGenerate,
    EvmAddress,
    SolanaAddress,
}

/// Where a request came from, as far as it can honestly be known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// A `hot_cheese` subcommand run by the owner in this terminal.
    Cli,
    /// A client that opened the loopback socket, with no tunnel that could have carried it.
    Loopback,
    /// A client that opened the loopback socket while `tunnels` reverse tunnels were open,
    /// so it may have come from any of them.
    Unattributed { tunnels: usize },
}

impl Peer {
    /// `ssh -R` forwards into the same loopback socket with the same source address, so once a
    /// tunnel is open no loopback client can be attributed to this machine any more.
    pub fn with_tunnels(self, open: usize) -> Self {
        match self {
            Peer::Loopback if open > 0 => Peer::Unattributed { tunnels: open },
            peer => peer,
        }
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Peer::Cli => f.write_str("the local CLI"),
            Peer::Loopback => f.write_str("the loopback socket"),
            Peer::Unattributed { tunnels } => write!(
                f,
                "unattributed ({tunnels} tunnel{} open)",
                if *tunnels == 1 { "" } else { "s" }
            ),
        }
    }
}

/// Everything an approval prompt needs to name one request.
#[derive(Clone, Debug)]
pub struct OpContext {
    /// Keystore the operation targets.
    pub key: String,
    /// What the caller asked for.
    pub op: Operation,
    /// Who asked.
    pub peer: Peer,
}

impl OpContext {
    /// The line shown on the Touch ID sheet and in the console's approval prompt.
    pub fn reason(&self) -> String {
        let route = match self.op {
            Operation::Read => "/read",
            Operation::Sign => "/sign",
            Operation::EvmGenerate => "/evm_generate",
            Operation::SolanaGenerate => "/solana_generate",
            Operation::EvmAddress => "/evm_address",
            Operation::SolanaAddress => "/solana_address",
        };
        format!("Unlock \"{}\" for {} from {}", self.key, route, self.peer)
    }
}

/// What a request path resolves to.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    Health,
    Op { op: Operation, key: String },
    Unknown,
}

const ROUTES: [(&str, Operation); 6] = [
    ("/read/", Operation::Read),
    ("/sign/", Operation::Sign),
    ("/evm_generate/", Operation::EvmGenerate),
    ("/evm_address/", Operation::EvmAddress),
    ("/solana_generate/", Operation::SolanaGenerate),
    ("/solana_address/", Operation::SolanaAddress),
];

fn parse_route(path: &str) -> Route {
    if path.ends_with("/health") {
        return Route::Health;
    }
    for (prefix, op) in ROUTES {
        let Some(key) = path.strip_prefix(prefix) else {
            continue;
        };
        if !is_valid_string_name(key) {
            return Route::Unknown;
        }
        return Route::Op {
            op,
            key: key.to_string(),
        };
    }
    Route::Unknown
}

create_err_with_impls!(
    #[derive(Debug)]
    pub OpErr,
    Denied,
    ApiBackend(ApiBackendErr),
    Sign(SignErr)
    ;
);

/// One request handed to whoever owns Touch ID and the DEK.
pub struct PrivilegedOp {
    /// What is being asked for, and by whom.
    pub ctx: OpContext,
    /// The request body (df-share handshake or sign intent); empty for body-less routes.
    pub body: Bytes,
    /// Where the ciphertext answer goes.
    pub reply: oneshot::Sender<Result<Vec<u8>, OpErr>>,
}

/// Privileged ops that may queue before the console starts refusing with 503.
pub const PENDING_OPS: usize = 4;

/// Takes the human decision. It returns a pre-evaluated biometric context when the flow it
/// approved reuses one; a session whose KEK is the recovery passphrase has no biometric to
/// reuse, so it approves with `None` and the passphrase unlocker does the unwrapping.
pub trait Approver: Send + Sync {
    fn approve(&self, ctx: &OpContext, summary: &str) -> Result<Option<LaContext>, SignErr>;
}

/// How a connection task turns a request into a reply.
#[derive(Clone)]
pub enum Approval {
    /// The daemon unlocks in the connection task; the backend is reachable from workers.
    Inline {
        api: Arc<HotApi>,
        approver: Arc<dyn Approver>,
    },
    /// The console keeps the backend on its main thread; workers only shuttle ciphertext.
    Console(mpsc::Sender<PrivilegedOp>),
}

/// Run one operation against the backend. Callers must already own the approval thread.
pub fn execute(
    api: &HotApi,
    approver: &dyn Approver,
    ctx: &OpContext,
    body: &[u8],
) -> Result<Vec<u8>, OpErr> {
    match ctx.op {
        Operation::Read => Ok(api.read(ctx, body)?),
        Operation::Sign => Ok(api.sign_intent(ctx, body, approver)?),
        Operation::EvmGenerate => {
            api.generate(ctx)?;
            Ok(b"success".to_vec())
        }
        Operation::SolanaGenerate => {
            api.generate_solana(ctx)?;
            Ok(b"success".to_vec())
        }
        Operation::EvmAddress => Ok(api.address(ctx)?.into_bytes()),
        Operation::SolanaAddress => Ok(api.address_solana(ctx)?.into_bytes()),
    }
}

create_err_with_impls!(
    #[derive(Debug)]
    pub(crate) DelegateErr,
    Overloaded,
    ConsoleGone,
    Op(OpErr)
    ;
);

/// Hand the op to the console's main thread and await its ciphertext. The queue bounds memory
/// only — a freed slot refills at once — so the flood bound is the console's per-pass approval
/// cap, not this depth.
async fn delegate(
    tx: &mpsc::Sender<PrivilegedOp>,
    ctx: OpContext,
    body: Bytes,
) -> Result<Vec<u8>, DelegateErr> {
    let (reply, answer) = oneshot::channel();
    if let Err(e) = tx.try_send(PrivilegedOp { ctx, body, reply }) {
        return Err(match e {
            mpsc::error::TrySendError::Full(_) => DelegateErr::Overloaded,
            mpsc::error::TrySendError::Closed(_) => DelegateErr::ConsoleGone,
        });
    }
    match answer.await {
        Ok(result) => Ok(result?),
        Err(_) => Err(DelegateErr::ConsoleGone),
    }
}

const MAX_BODY_BYTES: usize = 64 * 1024;

create_err_with_impls!(
    #[derive(Debug)]
    pub(crate) BodyErr,
    TooLarge,
    Malformed(serde_json::Error)
    ;
);

/// Read a request body but refuse anything past [`MAX_BODY_BYTES`], so a hostile local caller
/// cannot OOM the daemon with an unbounded body (intents and DH handshakes are tiny).
async fn read_body_capped<B>(body: B) -> Result<Bytes, BodyErr>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(_) => Err(BodyErr::TooLarge),
    }
}

/// A body that cannot parse can never produce an answer, so it is refused at the boundary:
/// garbage aimed at a route that prompts must never cost the owner an approval.
fn check_body(op: Operation, body: &[u8]) -> Result<(), BodyErr> {
    match op {
        Operation::Read => {
            serde_json::from_slice::<ClientReq>(body)?;
        }
        Operation::Sign => {
            serde_json::from_slice::<sign::intent::Intent>(body)?;
        }
        Operation::EvmGenerate
        | Operation::SolanaGenerate
        | Operation::EvmAddress
        | Operation::SolanaAddress => {}
    }
    Ok(())
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
    Ecdsa(k256::ecdsa::Error),
    Sign(crate::sign::SignErr)
    ;
);

/// The backend supplies the Data Encryption Key (per request) and the store location.
/// Unlocking is where the Touch ID / Secure Enclave gate lives now — see `unlock_dek`.
pub trait BackendImpl: Send + Sync {
    /// Unwrap the DEK for a single operation. `reason` is surfaced to the user
    /// (e.g. the biometric prompt). A pre-evaluated `auth` context (when `Some`) is
    /// reused so the SE op doesn't prompt again. The returned DEK is zeroized when dropped.
    fn unlock_dek(&self, reason: &str, auth: Option<&LaContext>) -> Result<Dek, UnlockErr>;
    fn store(&self) -> &str;

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

/// `0x`-prefixed EVM address of a 32-byte secp256k1 secret (keccak of the uncompressed
/// public key, last 20 bytes). Shared with `migrate` and the reference client.
pub fn sk_to_adr(key: &[u8]) -> Result<String, ApiBackendErr> {
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

    pub fn address(&self, ctx: &OpContext) -> Result<String, ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(&ctx.key);
        if !path.exists() {
            return Err(ApiBackendErr::KeyNotExists);
        }
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        let mut key = decrypt_file(&path, &ctx.key, &dek)?;
        let addr = sk_to_adr(&key);
        key.zeroize();
        addr
    }
    pub fn address_solana(&self, ctx: &OpContext) -> Result<String, ApiBackendErr> {
        use solana_signer::Signer;
        let path = Path::new(&self.inner.store_path()).join(&ctx.key);
        if !path.exists() {
            return Err(ApiBackendErr::KeyNotExists);
        }
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        let mut key = decrypt_file(&path, &ctx.key, &dek)?;
        let keypair = solana_keypair::Keypair::from_bytes(&key)
            .map_err(|_| ApiBackendErr::FailReadKeypair)?;
        let addr = keypair.pubkey();
        key.zeroize();
        Ok(addr.to_string())
    }
    pub fn generate_solana(&self, ctx: &OpContext) -> Result<(), ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(&ctx.key);
        if path.exists() {
            return Err(ApiBackendErr::KeyExists);
        }
        let mut pk = solana_keypair::Keypair::new().to_bytes();
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        encrypt_file(&self.inner.store_path(), &ctx.key, &dek, &pk)?;
        pk.zeroize();
        Ok(())
    }
    pub fn generate(&self, ctx: &OpContext) -> Result<(), ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(&ctx.key);
        if path.exists() {
            return Err(ApiBackendErr::KeyExists);
        }
        let mut rng = rand::rngs::OsRng;
        let mut pk = random_pk(&mut rng).to_bytes().to_vec();
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        encrypt_file(&self.inner.store_path(), &ctx.key, &dek, &pk)?;
        pk.zeroize();
        Ok(())
    }
    /// read works for both solana/evm
    pub fn read(&self, ctx: &OpContext, body: &[u8]) -> Result<Vec<u8>, ApiBackendErr> {
        let req: ClientReq = serde_json::from_slice(body)?;
        let path = Path::new(&self.inner.store_path()).join(&ctx.key);
        if !path.exists() {
            return Err(ApiBackendErr::KeyNotExists);
        }
        tracing::info!("client pubk:\n{}", df_share::generate_ascii_art(&req.pubk));
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        let mut key = decrypt_file(&path, &ctx.key, &dek)?;
        let server = EphemeralServer::new()?;
        let res = server.encrypt_secret(&req, &key)?;
        key.zeroize();
        Ok(serde_json::to_vec(&res)?)
    }

    /// Sign a prehashed 32-byte digest with keystore `name`. Unlocks the DEK (reusing the
    /// pre-evaluated `auth` context so no second prompt), decrypts the key in memory, signs,
    /// verifies the signature recovers to the signer, then zeroizes the key.
    pub fn sign(
        &self,
        ctx: &OpContext,
        digest: B256,
        auth: Option<&LaContext>,
    ) -> Result<SafeSignature, SignErr> {
        use k256::ecdsa::{SigningKey, VerifyingKey};
        let path = Path::new(&self.inner.store_path()).join(&ctx.key);
        if !path.exists() {
            return Err(SignErr::KeyNotExists);
        }
        let dek = self.inner.unlock_dek(&ctx.reason(), auth)?;
        let mut key = decrypt_file(&path, &ctx.key, &dek)?;
        let result = (|| {
            let sk = SigningKey::from_slice(&key)?;
            let (sig, recid) = sk.sign_prehash_recoverable(digest.as_slice())?;
            let recovered = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, recid)?;
            if &recovered != sk.verifying_key() {
                return Err(SignErr::AddressMismatch);
            }
            let signer = {
                let pt = recovered.to_encoded_point(false);
                let hash = keccak256(pt.as_bytes()[1..].to_vec());
                Address::from_slice(&hash[12..])
            };
            let bytes = sig.to_bytes();
            Ok(SafeSignature {
                r: B256::from_slice(&bytes[..32]),
                s: B256::from_slice(&bytes[32..]),
                v: 27 + recid.to_byte(),
                signer,
            })
        })();
        key.zeroize();
        result
    }

    /// Rebuild `safeTxHash` from submitted fields, enforce the per-key policy, take the
    /// single biometric approval, sign, and return the JSON [`SignResponse`].
    pub fn sign_intent(
        &self,
        ctx: &OpContext,
        body: &[u8],
        approver: &dyn Approver,
    ) -> Result<Vec<u8>, SignErr> {
        if !is_valid_string_name(&ctx.key) {
            return Err(SignErr::InvalidName);
        }
        let sign::intent::Intent::SafeTx(intent) = serde_json::from_slice(body)?;
        if intent.key != ctx.key {
            return Err(SignErr::IntentKeyMismatch);
        }
        let policy = sign::policy::Policy::load(&self.inner.store_path(), &ctx.key)?;
        sign::policy::evaluate(&intent, &policy).map_err(sign::policy::PolicyErr::from)?;

        let digest = sign::adapter::safe_tx_hash(&intent);
        let summary = sign::adapter::summary(&intent);
        let auth = approver.approve(ctx, &summary)?;
        let sig = self.sign(ctx, digest, auth.as_ref())?;

        let mut raw = Vec::with_capacity(65);
        raw.extend_from_slice(sig.r.as_slice());
        raw.extend_from_slice(sig.s.as_slice());
        raw.push(sig.v);
        let response = SignResponse {
            safe_tx_hash: digest,
            signature: SafeBytes::from(raw),
            signer: sig.signer,
        };
        Ok(serde_json::to_vec(&response)?)
    }
}

/// Best-effort backup push after a mutating HTTP request (key generation), offloaded to a
/// blocking task so rsync never blocks the async handler. No-op without configured remotes.
fn backup_after_mutation(cfg: &Arc<Config>) {
    if cfg.backup_remotes.is_empty() {
        return;
    }
    let cfg = cfg.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = backup::push_all(&cfg) {
            tracing::warn!(error = %e, "post-generate backup push failed");
        }
    });
}

async fn service_impl(
    req: Request<Incoming>,
    config: Arc<Config>,
    approval: Approval,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = Response::new(Full::default());
    let path = req.uri().path().to_string();
    tracing::debug!(path = %path, "request");
    let body = match read_body_capped(req.into_body()).await {
        Ok(b) => b,
        Err(_) => {
            *response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
            return Ok(response);
        }
    };
    let (op, key) = match parse_route(&path) {
        Route::Health => {
            *response.body_mut() = "ok".as_bytes().to_vec().into();
            return Ok(response);
        }
        Route::Unknown => return Ok(response),
        Route::Op { op, key } => (op, key),
    };
    if let Err(e) = check_body(op, &body) {
        tracing::warn!(error = ?e, %path, "body refused before any approval");
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(response);
    }

    let ctx = OpContext {
        key,
        op,
        peer: Peer::Loopback,
    };
    let outcome = match &approval {
        Approval::Inline { api, approver } => {
            execute(api, approver.as_ref(), &ctx, &body).map_err(DelegateErr::from)
        }
        Approval::Console(tx) => delegate(tx, ctx, body).await,
    };
    match outcome {
        Ok(out) => {
            *response.body_mut() = out.into();
            if matches!(op, Operation::EvmGenerate | Operation::SolanaGenerate) {
                backup_after_mutation(&config);
            }
        }
        Err(DelegateErr::Op(e)) => {
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            tracing::error!(error = ?e, %path, "operation failed");
        }
        Err(e) => {
            *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            tracing::error!(error = ?e, %path, "operation refused");
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
        fn unlock_dek(&self, _reason: &str, _auth: Option<&LaContext>) -> Result<Dek, UnlockErr> {
            Ok(Dek::from_bytes([42u8; 32]))
        }
        fn store(&self) -> &str {
            &self.store
        }
    }

    fn ctx(key: &str, op: Operation) -> OpContext {
        OpContext {
            key: key.to_string(),
            op,
            peer: Peer::Cli,
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
        api.generate(&ctx("EVM_TEST", Operation::EvmGenerate))
            .unwrap();
        let a1 = api
            .address(&ctx("EVM_TEST", Operation::EvmAddress))
            .unwrap();
        let a2 = api
            .address(&ctx("EVM_TEST", Operation::EvmAddress))
            .unwrap();
        assert_eq!(a1, a2, "address must be deterministic across decrypts");
        assert!(!a1.is_empty());
        // regenerate must refuse to overwrite an existing key
        assert!(matches!(
            api.generate(&ctx("EVM_TEST", Operation::EvmGenerate)),
            Err(ApiBackendErr::KeyExists)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `sign` must emit an `{r,s,v}` whose `v` truly recovers the signer, and report that
    /// signer's address — the recover-and-assert invariant the signer is built around.
    #[test]
    fn sign_emits_recoverable_signature_for_fixed_key() {
        let dir = std::env::temp_dir().join("hot_cheese_sign_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.to_string_lossy().to_string();
        let api = HotApi {
            inner: Box::new(TestBackend {
                store: store.clone(),
            }),
        };

        let sk_bytes = [0x11u8; 32];
        encrypt_file(
            Path::new(&store),
            "SIGN_TEST",
            &Dek::from_bytes([42u8; 32]),
            &sk_bytes,
        )
        .unwrap();

        let digest = B256::from([0x22u8; 32]);
        let sig = api
            .sign(&ctx("SIGN_TEST", Operation::Sign), digest, None)
            .unwrap();

        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(sig.r.as_slice());
        rs[32..].copy_from_slice(sig.s.as_slice());
        let signature = k256::ecdsa::Signature::from_slice(&rs).unwrap();
        let recid = k256::ecdsa::RecoveryId::from_byte(sig.v - 27).unwrap();
        let recovered =
            k256::ecdsa::VerifyingKey::recover_from_prehash(digest.as_slice(), &signature, recid)
                .unwrap();
        let expected = *k256::ecdsa::SigningKey::from_slice(&sk_bytes)
            .unwrap()
            .verifying_key();
        assert_eq!(recovered, expected, "v must recover the true signer");

        let pt = expected.to_encoded_point(false);
        let addr = Address::from_slice(&keccak256(pt.as_bytes()[1..].to_vec())[12..]);
        assert_eq!(
            sig.signer, addr,
            "reported signer must be the key's address"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Name validation is centralized in `sign_intent`, so the CLI path (which forwards an
    /// unvalidated intent key) is rejected before any body parse, policy load, or unlock.
    #[test]
    fn sign_intent_rejects_invalid_name() {
        let api = HotApi {
            inner: Box::new(TestBackend {
                store: "/nonexistent".to_string(),
            }),
        };
        assert!(matches!(
            api.sign_intent(&ctx("bad name!", Operation::Sign), b"{}", &DenyAll),
            Err(SignErr::InvalidName)
        ));
    }

    struct DenyAll;
    impl Approver for DenyAll {
        fn approve(&self, _ctx: &OpContext, _summary: &str) -> Result<Option<LaContext>, SignErr> {
            Err(SignErr::ApprovalDenied)
        }
    }

    /// A request that arrived on the loopback socket while a reverse tunnel is open may have
    /// come through it, so neither the console prompt nor the biometric sheet may claim
    /// localhost; with no tunnel open the socket is all that is claimed.
    #[test]
    fn an_open_tunnel_strips_the_local_origin_claim() {
        let mut ctx = ctx("TRADER", Operation::Read);
        ctx.peer = Peer::Loopback.with_tunnels(1);
        assert_eq!(ctx.peer, Peer::Unattributed { tunnels: 1 });
        let reason = ctx.reason();
        assert!(!reason.contains("localhost"), "{reason}");
        assert!(reason.contains("unattributed (1 tunnel open)"), "{reason}");

        ctx.peer = Peer::Loopback.with_tunnels(0);
        assert_eq!(ctx.peer, Peer::Loopback);
        assert!(ctx.reason().contains("the loopback socket"));
        assert_eq!(Peer::Cli.with_tunnels(3), Peer::Cli);
    }

    /// A body that can never parse must be refused at the boundary, because `/read` prompts the
    /// owner before it looks at the body: garbage may not cost an approval.
    #[test]
    fn unparseable_bodies_are_refused_before_any_approval() {
        assert!(matches!(
            check_body(Operation::Read, b"not json"),
            Err(BodyErr::Malformed(_))
        ));
        assert!(matches!(
            check_body(Operation::Sign, b"{}"),
            Err(BodyErr::Malformed(_))
        ));
        assert!(check_body(Operation::EvmAddress, b"not json").is_ok());
    }

    /// A privileged op crosses from a connection worker to the thread that owns Touch ID, so
    /// every error nested in `OpErr` must stay `Send` forever.
    #[test]
    fn privileged_op_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PrivilegedOp>();
    }

    /// The route table must map each prefix to its operation, and must treat a rejected key
    /// name exactly like an unknown path so no invalid name ever reaches an unlock.
    #[test]
    fn route_table_maps_prefixes_and_rejects_bad_names() {
        assert_eq!(parse_route("/health"), Route::Health);
        assert_eq!(
            parse_route("/solana_address/TRADER"),
            Route::Op {
                op: Operation::SolanaAddress,
                key: "TRADER".to_string()
            }
        );
        assert_eq!(
            parse_route("/read/A_1"),
            Route::Op {
                op: Operation::Read,
                key: "A_1".to_string()
            }
        );
        assert_eq!(parse_route("/read/bad name"), Route::Unknown);
        assert_eq!(parse_route("/read/../etc"), Route::Unknown);
        assert_eq!(parse_route("/nope/KEY"), Route::Unknown);
    }

    /// The body reader caps at 64 KiB: a small body is read whole, an over-cap body is refused
    /// (as `TooLarge`) so no route can OOM the daemon with an unbounded local request.
    #[tokio::test]
    async fn body_reader_caps_at_limit() {
        let small = read_body_capped(Full::new(Bytes::from(vec![7u8; 1024]))).await;
        assert_eq!(small.expect("small body reads").len(), 1024);
        let too_big = read_body_capped(Full::new(Bytes::from(vec![7u8; MAX_BODY_BYTES + 1]))).await;
        assert!(matches!(too_big, Err(BodyErr::TooLarge)));
    }
}
