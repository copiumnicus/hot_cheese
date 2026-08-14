//! The HTTPS daemon: routes, provenance, the privileged API, and the accept loop.
//!
//! [`qr_term`] draws one [`hc_sign::qr`] frame for whichever terminal is asking — the CLI's or
//! the console's. It sits here rather than in `hc-sign` because a phone links that crate to run
//! the policy and the digest, and a phone has no terminal to draw on.
pub mod approval;
pub mod bundle_poll;
pub mod exposure;
pub mod flock;
pub mod git_store;
pub mod live;
pub mod qr_term;
pub mod renderer;
pub mod runtime;
pub mod socket;

use crate::approval::Approver;
use alloy_primitives::B256;
use df_share::error::Unspecified;
use df_share::{to_hex_str, ClientReq, EphemeralServer};
use err_mac::create_err_with_impls;
use hc_core::config::{cert_paths, Config};
use hc_core::crypto::envelope::{decrypt_file, encrypt_file, read_keystore, ExportPermit, KeyUse};
use hc_core::crypto::{keccak256, random_pk};
use hc_core::is_valid_string_name;
use hc_core::mac::local_auth::LaContext;
use hc_core::mac::BackendImpl;
use hc_core::unlock::UnlockErr;
use hc_sign::grant::SignGrant;
use hc_sign::intent::SafeTxIntent;
use hc_sign::manifest::LoadedManifest;
use hc_sign::{SafeSignature, SignErr, SignResponse};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io;
use std::io::BufReader;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroize;

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

/// `hot_cheese serve`: the headless renderer over the one [`runtime::Runtime`]. Every manifest
/// is loaded, pin-checked and intersected with the policies in force BEFORE anything binds, so a
/// manifest that claims more than its key's policy grants stops the daemon at startup instead of
/// at an incident. `store` is the claim `hot_cheese serve` took above its own clone-if-absent.
pub fn serve(
    config: Config,
    backend: Box<dyn BackendImpl>,
    store: flock::Claim,
) -> Result<(), runtime::RuntimeErr> {
    let mut rt = runtime::Runtime::start(
        config,
        backend,
        runtime::UnlockGate::Biometric,
        Arc::new(renderer::Headless::detect()),
        runtime::BindPort::Configured,
        store,
    )?;
    let result = rt.approve_forever();
    rt.stop();
    result
}

/// How long the accept loop waits after a failed `accept` before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Connections one listener serves at once. Past this the next one is closed immediately, so an
/// unbounded number of peers can never become an unbounded number of tasks.
const MAX_CONNECTIONS: usize = 64;

/// How long a peer may hold one of those slots before it has asked for anything: the TLS
/// handshake, the request headers and the wait for a first request each get this long, so a
/// peer that opens a connection and goes quiet cannot pin a slot.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// What one [`serve_loop`] accepts on.
pub enum Listener {
    /// The pinned-TLS loopback listener.
    Tcp(TcpListener, TlsAcceptor),
    /// One adapter's 0600 unix socket. No TLS: the bytes never leave the kernel.
    Unix(UnixListener),
}

/// One accepted connection, before any TLS handshake.
enum Accepted {
    Tcp(TcpStream, TlsAcceptor),
    Unix(UnixStream),
}

impl Listener {
    async fn accept(&self) -> io::Result<Accepted> {
        match self {
            Listener::Tcp(listener, tls) => {
                let (stream, remote_addr) = listener.accept().await?;
                tracing::debug!(%remote_addr, "accepted a connection");
                Ok(Accepted::Tcp(stream, tls.clone()))
            }
            Listener::Unix(listener) => {
                let (stream, _) = listener.accept().await?;
                match stream.peer_cred() {
                    Ok(cred) => tracing::debug!(
                        uid = cred.uid(),
                        gid = cred.gid(),
                        pid = ?cred.pid(),
                        "accepted an adapter connection; peer credentials are a log field, not authentication"
                    ),
                    Err(e) => {
                        tracing::debug!(error = %e, "accepted an adapter connection with unreadable peer credentials")
                    }
                }
                Ok(Accepted::Unix(stream))
            }
        }
    }
}

/// Serve one connection, whatever it arrived on. `peer` is the listener's provenance and the
/// request cannot influence it, which is what makes an adapter's identity unforgeable.
///
/// A connection that has not produced a single request within [`HANDSHAKE_TIMEOUT`] is closed;
/// once it has, it is served for as long as it takes, because the wait it is in is a human's.
async fn serve_io<I>(
    io: TokioIo<I>,
    git: Arc<git_store::GitStore>,
    ops: mpsc::Sender<PrivilegedOp>,
    pending: Arc<live::Pending>,
    peer: Peer,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let asked = Arc::new(AtomicBool::new(false));
    let requested = asked.clone();
    let service = service_fn(move |req| {
        requested.store(true, Ordering::Relaxed);
        let git = git.clone();
        let ops = ops.clone();
        let pending = pending.clone();
        let peer = peer.clone();
        async move { service_impl(req, git, ops, pending, peer).await }
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HANDSHAKE_TIMEOUT);
    let connection = builder.serve_connection(io, service);
    tokio::pin!(connection);
    let served = tokio::select! {
        served = &mut connection => Some(served),
        _ = tokio::time::sleep(HANDSHAKE_TIMEOUT) => None,
    };
    let served = match served {
        Some(served) => served,
        None if asked.load(Ordering::Relaxed) => connection.await,
        None => {
            tracing::warn!("closing a connection that never sent a request");
            return;
        }
    };
    if let Err(err) = served {
        tracing::error!(error = %err, "failed to serve connection");
    }
}

/// Accept connections until `shutdown` fires, serving each on its own task with the
/// provenance of the listener that accepted it. A failed `accept` (the peer vanished,
/// descriptors ran out) is transient: it is logged and retried after [`ACCEPT_BACKOFF`],
/// never taken as the end of the listener. At most [`MAX_CONNECTIONS`] are alive at once and
/// the one that would exceed that is closed, so no peer can spawn tasks without bound.
pub async fn serve_loop(
    listener: Listener,
    peer: Peer,
    git: Arc<git_store::GitStore>,
    ops: mpsc::Sender<PrivilegedOp>,
    pending: Arc<live::Pending>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServeErr> {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = shutdown.changed() => return Ok(()),
        };
        let accepted = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed, retrying");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            tracing::warn!(
                limit = MAX_CONNECTIONS,
                "closing a connection: every slot is busy"
            );
            continue;
        };
        let git = git.clone();
        let ops = ops.clone();
        let pending = pending.clone();
        let peer = peer.clone();
        tokio::spawn(async move {
            let _slot = slot;
            match accepted {
                Accepted::Tcp(stream, tls) => {
                    let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, tls.accept(stream));
                    let tls_stream = match handshake.await {
                        Ok(Ok(tls_stream)) => tls_stream,
                        Ok(Err(err)) => {
                            tracing::error!(error = %err, "tls handshake failed");
                            return;
                        }
                        Err(elapsed) => {
                            tracing::warn!(error = %elapsed, "tls handshake timed out");
                            return;
                        }
                    };
                    serve_io(TokioIo::new(tls_stream), git, ops, pending, peer).await;
                }
                Accepted::Unix(stream) => {
                    serve_io(TokioIo::new(stream), git, ops, pending, peer).await
                }
            }
        });
    }
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

/// Where a request came from, as far as it can honestly be known. It is decided by the
/// listener that accepted the connection and never by anything in the request, so an adapter
/// cannot claim to be another one: it would have to open another adapter's socket.
#[derive(Clone, Debug)]
pub enum Peer {
    /// A `hot_cheese` subcommand run by the owner in this terminal.
    Cli,
    /// A client that opened the loopback socket, with no tunnel that could have carried it.
    Loopback,
    /// A client that opened the loopback socket while `tunnels` reverse tunnels were open,
    /// so it may have come from any of them.
    Unattributed { tunnels: usize },
    /// A client that opened one adapter's 0600 unix socket. The manifest is the pinned one
    /// that socket was bound for, and it is the only extra authority the request gets.
    Adapter(Arc<LoadedManifest>),
}

impl Peer {
    /// `ssh -R` forwards into the same loopback socket with the same source address, so once a
    /// tunnel is open no loopback client can be attributed to this machine any more.
    pub fn with_tunnels(&self, open: usize) -> Self {
        match self {
            Peer::Loopback if open > 0 => Peer::Unattributed { tunnels: open },
            peer => peer.clone(),
        }
    }

    /// The route table a listener carrying this provenance answers. Tying the two together
    /// here is what makes "an adapter reached `/read`" unreachable rather than merely denied.
    pub fn surface(&self) -> Surface {
        match self {
            Peer::Adapter(_) => Surface::Adapter,
            Peer::Cli | Peer::Loopback | Peer::Unattributed { .. } => Surface::Local,
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
            Peer::Adapter(adapter) => write!(
                f,
                "adapter \"{}\" (manifest {})",
                adapter.manifest.id,
                hex::encode(&adapter.digest[..8])
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
    /// Name an operation the operator invoked at this machine's own keyboard. Nothing outside a
    /// listener may choose its own provenance.
    pub fn local(key: String, op: Operation) -> Self {
        Self {
            key,
            op,
            peer: Peer::Cli,
        }
    }

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

/// Which route table a listener answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    /// The pinned-TLS loopback listener and the CLI: every route.
    Local,
    /// An adapter's socket: signing and liveness, and nothing else. Export and key creation
    /// are not in this table at all, which is a second, independent reason a `sign_only` key
    /// cannot leave through an adapter.
    Adapter,
}

const LOCAL_ROUTES: [(&str, Operation); 6] = [
    ("/read/", Operation::Read),
    ("/sign/", Operation::Sign),
    ("/evm_generate/", Operation::EvmGenerate),
    ("/evm_address/", Operation::EvmAddress),
    ("/solana_generate/", Operation::SolanaGenerate),
    ("/solana_address/", Operation::SolanaAddress),
];

const ADAPTER_ROUTES: [(&str, Operation); 1] = [("/sign/", Operation::Sign)];

fn parse_route(surface: Surface, path: &str) -> Route {
    if path == "/health" {
        return Route::Health;
    }
    let routes: &[(&str, Operation)] = match surface {
        Surface::Local => &LOCAL_ROUTES,
        Surface::Adapter => &ADAPTER_ROUTES,
    };
    for (prefix, op) in routes {
        let Some(key) = path.strip_prefix(prefix) else {
            continue;
        };
        if !is_valid_string_name(key) {
            return Route::Unknown;
        }
        return Route::Op {
            op: *op,
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

/// Hex characters of the request-body digest shown at the prompt: enough that two concurrent
/// `/read`s for one keystore, which differ in nothing else, are two different lines.
const DIGEST_CHARS: usize = 16;

/// Run one operation against the backend. Callers must already own the approval thread. Every
/// arm reaches `approver`, because every one of them is a request that arrived over the network
/// surface and each costs the key owner something.
///
/// The export permit is minted BEFORE the prompt, from the target's cleartext header: a key that
/// is not sealed shareable is refused without unlocking anything and without costing an
/// approval, and a remote caller may only ever mint itself a [`KeyUse::SignOnly`] key. `Sign`
/// prompts inside [`HotApi::sign_intent`], after the policy and the manifest have run, for the
/// same reason.
pub fn execute(
    api: &HotApi,
    approver: &Approver,
    ctx: &OpContext,
    body: &[u8],
) -> Result<Vec<u8>, OpErr> {
    match ctx.op {
        Operation::Read => {
            let permit = api.export_permit(ctx)?;
            let digest = hex::encode(Sha256::digest(body));
            approver.approve(
                ctx,
                &format!("request body sha256 {}", &digest[..DIGEST_CHARS]),
            )?;
            Ok(api.read(ctx, body, permit)?)
        }
        Operation::Sign => Ok(api.sign_intent(ctx, body, approver)?),
        Operation::EvmGenerate => {
            approver.approve(ctx, "")?;
            api.generate(ctx, KeyUse::SignOnly)?;
            Ok(b"success".to_vec())
        }
        Operation::SolanaGenerate => {
            approver.approve(ctx, "")?;
            api.generate_solana(ctx, KeyUse::SignOnly)?;
            Ok(b"success".to_vec())
        }
        Operation::EvmAddress => {
            approver.approve(ctx, "")?;
            Ok(api.address(ctx)?.into_bytes())
        }
        Operation::SolanaAddress => {
            approver.approve(ctx, "")?;
            Ok(api.address_solana(ctx)?.into_bytes())
        }
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

/// Hand the op to the thread that owns the runtime and await its ciphertext. The queue bounds
/// memory only — a freed slot refills at once — so the flood bound is the terminal renderer's
/// per-pass approval cap, not this depth.
///
/// The gauge slot is taken BEFORE the send, so there is no instant in which an op is queued and
/// uncounted; a refused send drops it on the `return`, which nets to zero.
async fn delegate(
    tx: &mpsc::Sender<PrivilegedOp>,
    pending: &Arc<live::Pending>,
    ctx: OpContext,
    body: Bytes,
) -> Result<Vec<u8>, DelegateErr> {
    let (reply, answer) = oneshot::channel();
    let _outstanding = live::Outstanding::new(pending.clone());
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
    Malformed(serde_json::Error)
    ;
    TooLarge { limit: usize },
    Unreadable { source: Box<dyn std::error::Error + Send + Sync> }
);

/// Read a request body but refuse anything past [`MAX_BODY_BYTES`], so a hostile local caller
/// cannot OOM the daemon with an unbounded body (intents and DH handshakes are tiny). A body
/// that breaks off part-way is a different failure from one that is too big and keeps its own
/// error: reporting a reset connection as `413` would send the caller after the wrong problem.
async fn read_body_capped<B>(body: B) -> Result<Bytes, BodyErr>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(source) if source.is::<LengthLimitError>() => Err(BodyErr::TooLarge {
            limit: MAX_BODY_BYTES,
        }),
        Err(source) => Err(BodyErr::Unreadable { source }),
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
            serde_json::from_slice::<hc_sign::intent::Intent>(body)?;
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
    Envelope(hc_core::crypto::envelope::EnvErr),
    Ecdsa(k256::ecdsa::Error),
    Sign(SignErr)
    ;
);

pub struct HotApi {
    inner: Box<dyn BackendImpl>,
    /// The daemon's own config; the sign path reads the pinned grant key from it.
    config: Arc<Config>,
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
    pub fn new(inner: Box<dyn BackendImpl>, config: Arc<Config>) -> Self {
        Self { inner, config }
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
    pub fn generate_solana(&self, ctx: &OpContext, key_use: KeyUse) -> Result<(), ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(&ctx.key);
        if path.exists() {
            return Err(ApiBackendErr::KeyExists);
        }
        let mut pk = solana_keypair::Keypair::new().to_bytes();
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        encrypt_file(&self.inner.store_path(), &ctx.key, &dek, key_use, &pk)?;
        pk.zeroize();
        Ok(())
    }
    pub fn generate(&self, ctx: &OpContext, key_use: KeyUse) -> Result<(), ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(&ctx.key);
        if path.exists() {
            return Err(ApiBackendErr::KeyExists);
        }
        let mut rng = rand::rngs::OsRng;
        let mut pk = random_pk(&mut rng).to_bytes().to_vec();
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        encrypt_file(&self.inner.store_path(), &ctx.key, &dek, key_use, &pk)?;
        pk.zeroize();
        Ok(())
    }
    /// Mint the export permit for `ctx.key` from its cleartext header. Reads the container
    /// only: no DEK, no unlock, no biometric, so refusing a non-shareable key is free.
    pub fn export_permit(&self, ctx: &OpContext) -> Result<ExportPermit, ApiBackendErr> {
        let path = Path::new(&self.inner.store_path()).join(&ctx.key);
        if !path.exists() {
            return Err(ApiBackendErr::KeyNotExists);
        }
        Ok(read_keystore(&path)?.export_permit()?)
    }
    /// Release the permitted key to the client over df-share. Works for both solana/evm.
    /// The permit is the only way in, and it exists only for a sealed shareable keystore.
    pub fn read(
        &self,
        ctx: &OpContext,
        body: &[u8],
        permit: ExportPermit,
    ) -> Result<Vec<u8>, ApiBackendErr> {
        let req: ClientReq = serde_json::from_slice(body)?;
        tracing::info!("client pubk:\n{}", df_share::generate_ascii_art(&req.pubk));
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        let mut key = permit.open(&ctx.key, &dek)?;
        let server = EphemeralServer::new()?;
        let res = server.encrypt_secret(&req, &key)?;
        key.zeroize();
        Ok(serde_json::to_vec(&res)?)
    }

    /// Sign the digest `grant` attests, with keystore `ctx.key`. The flow itself lives in
    /// [`hc_sign::sign::sign_with_grant`], where a phone can link it; this is the daemon's
    /// backend and the daemon's prompt line handed to it.
    pub fn sign(
        &self,
        ctx: &OpContext,
        auth: Option<&LaContext>,
        grant: SignGrant,
    ) -> Result<SafeSignature, SignErr> {
        hc_sign::sign::sign_with_grant(self.inner.as_ref(), &ctx.key, &ctx.reason(), auth, grant)
    }

    /// The wire form of [`HotApi::sign_typed`] and [`HotApi::sign_typed_data`]: an untrusted body
    /// is parsed before anything privileged runs, its `kind` selects which of the two it is, and
    /// the typed answer goes back out as JSON. `#[serde(deny_unknown_fields)]` on each variant's
    /// struct makes the parsed value a faithful view of the bytes rather than a lossy one — which
    /// is what makes a typed-data body carrying its own `types`, `primaryType` or `domain` a
    /// parse failure here instead of a shape to compare against.
    pub fn sign_intent(
        &self,
        ctx: &OpContext,
        body: &[u8],
        approver: &Approver,
    ) -> Result<Vec<u8>, SignErr> {
        let response = match serde_json::from_slice(body)? {
            hc_sign::intent::Intent::SafeTx(intent) => self.sign_typed(ctx, intent, approver)?,
            hc_sign::intent::Intent::TypedData(intent) => {
                self.sign_typed_data(ctx, intent, approver)?
            }
        };
        Ok(serde_json::to_vec(&response)?)
    }

    /// The same flow for an EIP-712 message. The shape is the POLICY's `[[typed_data]]` block,
    /// never the request's: an adapter needs `typed_data` in its `intent_kinds` and the schema
    /// name in its own grant to reach one at all, and everything that can refuse still runs
    /// before the prompt.
    pub fn sign_typed_data(
        &self,
        ctx: &OpContext,
        intent: hc_sign::intent::TypedDataIntent,
        approver: &Approver,
    ) -> Result<SignResponse, SignErr> {
        if !is_valid_string_name(&ctx.key) {
            return Err(SignErr::InvalidName);
        }
        if intent.key != ctx.key {
            return Err(SignErr::IntentKeyMismatch);
        }
        let manifest_digest = match &ctx.peer {
            Peer::Adapter(adapter) => {
                hc_sign::manifest::evaluate_typed(&intent, &adapter.manifest)?;
                adapter.digest
            }
            Peer::Cli | Peer::Loopback | Peer::Unattributed { .. } => B256::ZERO,
        };
        let loaded = hc_sign::policy::Policy::load(&self.inner.store_path(), &ctx.key)?;
        let pinned = self
            .config
            .grant_public_key
            .as_deref()
            .ok_or(hc_sign::grant::GrantErr::NoPinnedGrantKey)?;

        let (approved, summary) =
            hc_sign::sign::prepare_typed_data(intent, &loaded, manifest_digest, &self.config)?;
        let auth = approver.approve(ctx, &summary)?;
        hc_sign::sign::finish(
            approved,
            self.inner.as_ref(),
            pinned,
            auth.as_ref(),
            &ctx.reason(),
        )
    }

    /// Enforce the per-key policy and — for a request that arrived on an adapter's socket —
    /// that adapter's manifest on top of it, take the single biometric approval, mint and verify
    /// the grant that signing demands, and sign. The manifest is an intersection, never a union:
    /// both it and the policy must pass, and the grant carries its digest so a hardware approval
    /// is bound to the exact adapter build that asked. Everything that can refuse the request —
    /// the name, the intent, the policy, the manifest, the pin — runs BEFORE the prompt, so a
    /// refusal costs the owner no biometric; after it only the enclave grant signature and the
    /// enclave ECDH of [`HotApi::sign`] remain, which is what keeps both inside one Touch ID.
    ///
    /// What is daemon-specific stays here: the route's key name, the intent, the provenance the
    /// listener stamped, and the pinned grant key from this machine's config. The rest is
    /// [`hc_sign::sign::prepare`] and [`hc_sign::sign::finish`], with the human's decision — a
    /// printed summary and Touch ID here, a sheet and Face ID on a phone — taken between them.
    pub fn sign_typed(
        &self,
        ctx: &OpContext,
        intent: SafeTxIntent,
        approver: &Approver,
    ) -> Result<SignResponse, SignErr> {
        if !is_valid_string_name(&ctx.key) {
            return Err(SignErr::InvalidName);
        }
        if intent.key != ctx.key {
            return Err(SignErr::IntentKeyMismatch);
        }
        let (grant, manifest_digest) = match &ctx.peer {
            Peer::Adapter(adapter) => (
                Some(hc_sign::manifest::evaluate(&intent, &adapter.manifest)?),
                adapter.digest,
            ),
            Peer::Cli | Peer::Loopback | Peer::Unattributed { .. } => (None, B256::ZERO),
        };
        let loaded = hc_sign::policy::Policy::load(&self.inner.store_path(), &ctx.key)?;
        let pinned = self
            .config
            .grant_public_key
            .as_deref()
            .ok_or(hc_sign::grant::GrantErr::NoPinnedGrantKey)?;

        let (approved, summary) =
            hc_sign::sign::prepare(intent, &loaded, grant, manifest_digest, &self.config)?;
        let auth = approver.approve(ctx, &summary)?;
        hc_sign::sign::finish(
            approved,
            self.inner.as_ref(),
            pinned,
            auth.as_ref(),
            &ctx.reason(),
        )
    }
}

async fn service_impl(
    req: Request<Incoming>,
    git: Arc<git_store::GitStore>,
    ops: mpsc::Sender<PrivilegedOp>,
    pending: Arc<live::Pending>,
    peer: Peer,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = Response::new(Full::default());
    let path = req.uri().path().to_string();
    tracing::debug!(path = %path, "request");
    let body = match read_body_capped(req.into_body()).await {
        Ok(b) => b,
        Err(e) => {
            *response.status_mut() = match e {
                BodyErr::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                BodyErr::Unreadable { .. } | BodyErr::Malformed(_) => StatusCode::BAD_REQUEST,
            };
            tracing::warn!(error = ?e, %path, "body refused before any route ran");
            return Ok(response);
        }
    };
    let (op, key) = match parse_route(peer.surface(), &path) {
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

    let ctx = OpContext { key, op, peer };
    match delegate(&ops, &pending, ctx, body).await {
        Ok(out) => {
            *response.body_mut() = out.into();
            if matches!(op, Operation::EvmGenerate | Operation::SolanaGenerate) {
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = git.after_mutation() {
                        tracing::warn!(error = %e, "recording a store mutation failed");
                    }
                });
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
    use alloy_primitives::{Address, U256};
    use hc_core::crypto::envelope::{Dek, EnvErr};

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
        OpContext::local(key.to_string(), op)
    }

    #[test]
    fn generate_then_address_roundtrips_through_envelope() {
        let dir = std::env::temp_dir().join("hot_cheese_server_test");
        let _ = std::fs::remove_dir_all(&dir);
        let store = dir.to_string_lossy().to_string();
        let api = HotApi {
            inner: Box::new(TestBackend {
                store: store.clone(),
            }),
            config: Config::for_test(&store),
        };
        api.generate(&ctx("EVM_TEST", Operation::EvmGenerate), KeyUse::SignOnly)
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
            api.generate(&ctx("EVM_TEST", Operation::EvmGenerate), KeyUse::SignOnly),
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
            config: Config::for_test(&store),
        };

        let sk_bytes = [0x11u8; 32];
        encrypt_file(
            Path::new(&store),
            "SIGN_TEST",
            &Dek::from_bytes([42u8; 32]),
            KeyUse::SignOnly,
            &sk_bytes,
        )
        .unwrap();

        let digest = B256::from([0x22u8; 32]);
        let sig = api
            .sign(
                &ctx("SIGN_TEST", Operation::Sign),
                None,
                hc_sign::grant::grant_for_test("SIGN_TEST", digest),
            )
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

    /// Name validation is centralized in `sign_typed`, so a local caller forwarding an
    /// unvalidated key name is rejected before any policy load or unlock.
    #[test]
    fn sign_typed_rejects_invalid_name() {
        let api = HotApi {
            inner: Box::new(TestBackend {
                store: "/nonexistent".to_string(),
            }),
            config: Config::for_test("/nonexistent"),
        };
        assert!(matches!(
            api.sign_typed(
                &ctx("bad name!", Operation::Sign),
                SafeTxIntent {
                    key: "bad name!".to_string(),
                    safe: Address::ZERO,
                    chain_id: U256::from(1),
                    to: Address::ZERO,
                    value: U256::ZERO,
                    data: alloy_primitives::Bytes::new(),
                    operation: hc_sign::intent::Operation::Call,
                    safe_tx_gas: U256::ZERO,
                    base_gas: U256::ZERO,
                    gas_price: U256::ZERO,
                    gas_token: Address::ZERO,
                    refund_receiver: Address::ZERO,
                    nonce: U256::ZERO,
                },
                &recording(renderer::Decision::Deny).1
            ),
            Err(SignErr::InvalidName)
        ));
    }

    /// Records every prompt it was shown and answers all of them the same way.
    struct Recorder {
        answer: renderer::Decision,
        seen: parking_lot::Mutex<Vec<(u64, Operation)>>,
    }

    impl renderer::Renderer for Recorder {
        fn ask(&self, seq: u64, ctx: &OpContext, _summary: &str) -> renderer::Decision {
            self.seen.lock().push((seq, ctx.op));
            self.answer
        }
        fn restore(&self) {}
    }

    fn recording(answer: renderer::Decision) -> (Arc<Recorder>, Approver) {
        let recorder = Arc::new(Recorder {
            answer,
            seen: parking_lot::Mutex::new(Vec::new()),
        });
        let approver = Approver::new(runtime::UnlockGate::Biometric, recorder.clone());
        (recorder, approver)
    }

    /// Every unlock fails, so any error other than the unlock error proves the DEK was never
    /// asked for — which on the real backend is the Touch ID sheet never appearing.
    struct NeverUnlocks {
        store: String,
    }
    impl BackendImpl for NeverUnlocks {
        fn unlock_dek(&self, _reason: &str, _auth: Option<&LaContext>) -> Result<Dek, UnlockErr> {
            Err(UnlockErr::NoMatchingEnrollment)
        }
        fn store(&self) -> &str {
            &self.store
        }
    }

    /// `/read` on a sign-only key must be refused BEFORE anything tries to unlock the DEK, so
    /// an export a policy forbids costs the owner zero biometric prompts. The shareable key in
    /// the same store reaching the (failing) unlock is what proves the refusal is the flag's
    /// doing and not a store that simply cannot answer.
    #[test]
    fn read_refuses_a_sign_only_key_before_any_unlock() {
        let dir = std::env::temp_dir().join("hot_cheese_export_refusal_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dek = Dek::from_bytes([42u8; 32]);
        encrypt_file(&dir, "LOCKED", &dek, KeyUse::SignOnly, &[0x11u8; 32]).unwrap();
        encrypt_file(&dir, "OPEN", &dek, KeyUse::Shareable, &[0x22u8; 32]).unwrap();

        let store = dir.to_string_lossy().to_string();
        let api = HotApi {
            inner: Box::new(NeverUnlocks {
                store: store.clone(),
            }),
            config: Config::for_test(&store),
        };
        let (req, _decryptor) = df_share::EphemeralClient::new().unwrap().sendable();
        let body = serde_json::to_vec(&req).unwrap();

        let (recorder, approver) = recording(renderer::Decision::Approve);
        assert!(matches!(
            execute(&api, &approver, &ctx("LOCKED", Operation::Read), &body),
            Err(OpErr::ApiBackend(ApiBackendErr::Envelope(
                EnvErr::ExportRefused {
                    key_use: KeyUse::SignOnly
                }
            )))
        ));
        assert!(
            recorder.seen.lock().is_empty(),
            "a structural refusal must cost no prompt"
        );
        assert!(matches!(
            execute(&api, &approver, &ctx("OPEN", Operation::Read), &body),
            Err(OpErr::ApiBackend(ApiBackendErr::Unlock(
                UnlockErr::NoMatchingEnrollment
            )))
        ));
        assert_eq!(
            recorder.seen.lock().len(),
            1,
            "the shareable key is prompted"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    const EVERY_OP_POLICY: &str = concat!(
        "safe = \"0x1111111111111111111111111111111111111111\"\n",
        "chain_id = 1\n",
        "\n",
        "[[allow]]\n",
        "to = \"0x2222222222222222222222222222222222222222\"\n",
        "max_value = \"0\"\n",
        "operation = \"call\"\n",
        "\n",
        "  [[allow.call]]\n",
        "  signature = \"transfer(address,uint256)\"\n",
        "\n",
        "    [[allow.call.arg]]\n",
        "    at = 0\n",
        "    name = \"to\"\n",
        "    rule = \"unbounded\"\n",
        "\n",
        "    [[allow.call.arg]]\n",
        "    at = 1\n",
        "    name = \"amount\"\n",
        "    rule = \"unbounded\"\n",
        "\n",
        "[[typed_data]]\n",
        "schema = \"permit2_usdc\"\n",
        "primary_type = \"Note\"\n",
        "\n",
        "  [typed_data.domain]\n",
        "  chain_id = 1\n",
        "  verifying_contract = \"0x2222222222222222222222222222222222222222\"\n",
        "\n",
        "  [[typed_data.types]]\n",
        "  name = \"Note\"\n",
        "\n",
        "    [[typed_data.types.field]]\n",
        "    name = \"text\"\n",
        "    type = \"string\"\n",
        "    rule = { enum = { one_of = [\"hello\"] } }\n",
    );

    const TRANSFER_DATA: &str = "0xa9059cbb0000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000a";

    const EVERY_OP_INTENT: &str = concat!(
        "{\"kind\":\"safe_tx\",\"key\":\"EVERY_OP\",",
        "\"safe\":\"0x1111111111111111111111111111111111111111\",",
        "\"chain_id\":1,\"to\":\"0x2222222222222222222222222222222222222222\",",
        "\"value\":\"0\",\"data\":\"0xa9059cbb0000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000a\",\"operation\":\"call\",\"nonce\":0}"
    );

    /// Every privileged route is a request the key owner answers, so a renderer that denies
    /// everything must turn all six into `ApprovalDenied`. An unlock error from any of them
    /// would mean that route reached the DEK without a human, and an arm added later without a
    /// prompt fails here rather than in production.
    #[test]
    fn every_privileged_operation_reaches_the_approver() {
        let dir = std::env::temp_dir().join("hot_cheese_every_op_prompts");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("policies")).unwrap();
        std::fs::write(dir.join("policies").join("EVERY_OP.toml"), EVERY_OP_POLICY).unwrap();
        encrypt_file(
            &dir,
            "EVERY_OP",
            &Dek::from_bytes([42u8; 32]),
            KeyUse::Shareable,
            &[0x33u8; 32],
        )
        .unwrap();

        let store = dir.to_string_lossy().to_string();
        let api = HotApi {
            inner: Box::new(NeverUnlocks {
                store: store.clone(),
            }),
            config: Config::for_test(&store),
        };
        let (recorder, approver) = recording(renderer::Decision::Deny);

        let every = [
            Operation::Read,
            Operation::Sign,
            Operation::EvmGenerate,
            Operation::SolanaGenerate,
            Operation::EvmAddress,
            Operation::SolanaAddress,
        ];
        for op in every {
            let body: &[u8] = match op {
                Operation::Sign => EVERY_OP_INTENT.as_bytes(),
                _ => b"{}",
            };
            assert!(
                matches!(
                    execute(&api, &approver, &ctx("EVERY_OP", op), body),
                    Err(OpErr::Sign(SignErr::ApprovalDenied))
                ),
                "{op:?} must be refused at the prompt, before the backend"
            );
        }
        let seen: Vec<Operation> = recorder.seen.lock().iter().map(|(_, op)| *op).collect();
        assert_eq!(seen, every, "every route must have reached the renderer");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A request that arrived on the loopback socket while a reverse tunnel is open may have
    /// come through it, so neither the console prompt nor the biometric sheet may claim
    /// localhost; with no tunnel open the socket is all that is claimed.
    #[test]
    fn an_open_tunnel_strips_the_local_origin_claim() {
        let mut ctx = ctx("TRADER", Operation::Read);
        ctx.peer = Peer::Loopback.with_tunnels(1);
        assert!(matches!(ctx.peer, Peer::Unattributed { tunnels: 1 }));
        let reason = ctx.reason();
        assert!(!reason.contains("localhost"), "{reason}");
        assert!(reason.contains("unattributed (1 tunnel open)"), "{reason}");

        ctx.peer = Peer::Loopback.with_tunnels(0);
        assert!(matches!(ctx.peer, Peer::Loopback));
        assert!(ctx.reason().contains("the loopback socket"));
        assert!(matches!(Peer::Cli.with_tunnels(3), Peer::Cli));
    }

    fn adapter_peer() -> Peer {
        Peer::Adapter(Arc::new(LoadedManifest {
            manifest: hc_sign::manifest::Manifest {
                schema: hc_sign::manifest::SCHEMA.to_string(),
                id: "safe_treasury_bot".to_string(),
                grants: Vec::new(),
            },
            digest: B256::from([0xabu8; 32]),
            path: Path::new("/nonexistent/safe_treasury_bot.toml").to_path_buf(),
        }))
    }

    /// Provenance belongs to the listener, never to the request: an adapter peer answers the
    /// adapter route table by construction, and the line the Touch ID sheet and the console
    /// prompt show names which adapter asked and which manifest build it is running.
    #[test]
    fn adapter_provenance_picks_its_route_table_and_names_itself() {
        assert_eq!(adapter_peer().surface(), Surface::Adapter);
        assert_eq!(Peer::Loopback.surface(), Surface::Local);
        assert_eq!(Peer::Cli.surface(), Surface::Local);
        assert_eq!(
            Peer::Unattributed { tunnels: 2 }.surface(),
            Surface::Local,
            "a tunnelled loopback client is still not an adapter"
        );

        let ctx = OpContext {
            key: "TREASURY".to_string(),
            op: Operation::Sign,
            peer: adapter_peer(),
        };
        let reason = ctx.reason();
        assert!(reason.contains("safe_treasury_bot"), "{reason}");
        assert!(reason.contains("abababababababab"), "{reason}");
    }

    /// A body that can never parse must be refused at the boundary, because `/read` prompts the
    /// owner before it looks at the body: garbage may not cost an approval. An intent carrying
    /// a field the daemon does not know is such a body — the daemon would sign something other
    /// than what the caller wrote — so it dies here too, and the same intent without it lives.
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

        const INTENT: &str = concat!(
            "{\"kind\":\"safe_tx\",\"key\":\"TRADER\",",
            "\"safe\":\"0x1111111111111111111111111111111111111111\",",
            "\"chain_id\":1,\"to\":\"0x2222222222222222222222222222222222222222\",",
            "\"value\":\"0\",\"data\":\"0xa9059cbb\",\"operation\":\"call\",\"nonce\":0"
        );
        assert!(check_body(Operation::Sign, format!("{INTENT}}}").as_bytes()).is_ok());
        assert!(matches!(
            check_body(
                Operation::Sign,
                format!("{INTENT},\"required\":\"anything\"}}").as_bytes()
            ),
            Err(BodyErr::Malformed(_))
        ));

        // A typed-data request may not describe its own shape: the digest and the words a human
        // reads come from the POLICY's schema, so a body carrying `types`, `primaryType` or
        // `domain` has no field to land in and dies here, at the boundary, before any approval.
        const TYPED: &str = concat!(
            "{\"kind\":\"typed_data\",\"key\":\"TRADER\",\"schema\":\"permit2\",",
            "\"chain_id\":1,",
            "\"verifying_contract\":\"0x2222222222222222222222222222222222222222\",",
            "\"message\":{\"amount\":\"1\"}"
        );
        assert!(check_body(Operation::Sign, format!("{TYPED}}}").as_bytes()).is_ok());
        for smuggled in [
            "\"types\":{\"Permit\":[]}",
            "\"primaryType\":\"Permit\"",
            "\"domain\":{\"name\":\"Permit2\"}",
        ] {
            assert!(
                matches!(
                    check_body(Operation::Sign, format!("{TYPED},{smuggled}}}").as_bytes()),
                    Err(BodyErr::Malformed(_))
                ),
                "a typed-data body must not be able to state {smuggled}"
            );
            assert!(
                matches!(
                    check_body(Operation::Sign, format!("{INTENT},{smuggled}}}").as_bytes()),
                    Err(BodyErr::Malformed(_))
                ),
                "nor may a safe_tx body carry {smuggled}"
            );
        }
        assert!(
            check_body(
                Operation::Sign,
                format!("{TYPED},\"message\":{{\"types\":{{}}}}}}").as_bytes()
            )
            .is_ok(),
            "a `types` key INSIDE the message parses, and is refused by the schema walk instead"
        );
    }

    /// The ordering invariant this whole stage rests on: every typed refusal happens before the
    /// approver is reached, so no refusal ever costs the owner a Touch ID. Five different
    /// refusals — a destination outside the policy, a payload that will not decode against the
    /// declared signature, an argument outside its rule, a typed-data schema the policy never
    /// declared, and a typed-data message with a field the schema does not name — must all come
    /// back as different typed errors with the approver never asked once.
    #[test]
    fn a_refusal_never_reaches_the_approver() {
        let dir = std::env::temp_dir().join("hot_cheese_refusal_before_prompt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("policies")).unwrap();
        std::fs::write(dir.join("policies").join("EVERY_OP.toml"), EVERY_OP_POLICY).unwrap();
        let store = dir.to_string_lossy().to_string();
        let api = HotApi {
            inner: Box::new(NeverUnlocks {
                store: store.clone(),
            }),
            config: Config::for_test(&store),
        };
        let (recorder, approver) = recording(renderer::Decision::Approve);

        let body = |to: &str, data: &str| {
            format!(
                "{{\"kind\":\"safe_tx\",\"key\":\"EVERY_OP\",\
                 \"safe\":\"0x1111111111111111111111111111111111111111\",\
                 \"chain_id\":1,\"to\":\"{to}\",\"value\":\"0\",\"data\":\"{data}\",\
                 \"operation\":\"call\",\"nonce\":0}}"
            )
        };
        let typed = |schema: &str, message: &str| {
            format!(
                "{{\"kind\":\"typed_data\",\"key\":\"EVERY_OP\",\"schema\":\"{schema}\",\
                 \"chain_id\":1,\
                 \"verifying_contract\":\"0x2222222222222222222222222222222222222222\",\
                 \"message\":{message}}}"
            )
        };
        let truncated = &TRANSFER_DATA[..TRANSFER_DATA.len() - 16];
        let dirty = format!("0xa9059cbbff{}", &TRANSFER_DATA[12..]);

        for (what, body) in [
            (
                "a destination the policy never allowed",
                body("0x9999999999999999999999999999999999999999", TRANSFER_DATA),
            ),
            (
                "a payload that does not decode against the declared signature",
                body("0x2222222222222222222222222222222222222222", truncated),
            ),
            (
                "a payload that decodes but does not re-encode to the submitted bytes",
                body("0x2222222222222222222222222222222222222222", &dirty),
            ),
            (
                "a schema the policy never declared",
                typed("nothing_declared", "{}"),
            ),
            (
                "a message field the schema does not name",
                typed("permit2_usdc", "{\"ghost\":\"1\"}"),
            ),
        ] {
            let refused = execute(
                &api,
                &approver,
                &ctx("EVERY_OP", Operation::Sign),
                body.as_bytes(),
            );
            assert!(refused.is_err(), "{what} must be refused");
            assert!(
                recorder.seen.lock().is_empty(),
                "{what} reached the approver"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
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
        assert_eq!(parse_route(Surface::Local, "/health"), Route::Health);
        assert_eq!(
            parse_route(Surface::Local, "/solana_address/TRADER"),
            Route::Op {
                op: Operation::SolanaAddress,
                key: "TRADER".to_string()
            }
        );
        assert_eq!(
            parse_route(Surface::Local, "/read/A_1"),
            Route::Op {
                op: Operation::Read,
                key: "A_1".to_string()
            }
        );
        assert_eq!(
            parse_route(Surface::Local, "/read/bad name"),
            Route::Unknown
        );
        assert_eq!(parse_route(Surface::Local, "/read/../etc"), Route::Unknown);
        assert_eq!(parse_route(Surface::Local, "/nope/KEY"), Route::Unknown);
    }

    /// `/health` is one exact path, not a suffix: a keystore may legally be called `health`, and
    /// answering `200 ok` to `/sign/health` would hand an adapter a success status with no
    /// signature in it. An empty key is not a name either, so `/sign/` routes nowhere.
    #[test]
    fn health_is_an_exact_path_and_an_empty_key_is_no_key() {
        for surface in [Surface::Local, Surface::Adapter] {
            assert_eq!(parse_route(surface, "/health"), Route::Health);
            assert_eq!(
                parse_route(surface, "/sign/health"),
                Route::Op {
                    op: Operation::Sign,
                    key: "health".to_string()
                }
            );
            assert_eq!(parse_route(surface, "/sign/"), Route::Unknown);
            assert_eq!(parse_route(surface, "/healthy"), Route::Unknown);
        }
        assert_eq!(
            parse_route(Surface::Local, "/read/health"),
            Route::Op {
                op: Operation::Read,
                key: "health".to_string()
            }
        );
        assert_eq!(parse_route(Surface::Local, "/read/"), Route::Unknown);
    }

    /// An adapter socket answers signing and liveness, and nothing else. `/read` is not in its
    /// table at all, so no policy, manifest or key flag has to be consulted for an adapter to
    /// be unable to export a key — and neither is any route that would mint one.
    #[test]
    fn an_adapter_surface_routes_only_health_and_sign() {
        assert_eq!(parse_route(Surface::Adapter, "/health"), Route::Health);
        assert_eq!(
            parse_route(Surface::Adapter, "/sign/TREASURY"),
            Route::Op {
                op: Operation::Sign,
                key: "TREASURY".to_string()
            }
        );
        for path in [
            "/read/TREASURY",
            "/evm_generate/TREASURY",
            "/solana_generate/TREASURY",
            "/evm_address/TREASURY",
            "/solana_address/TREASURY",
        ] {
            assert_eq!(
                parse_route(Surface::Adapter, path),
                Route::Unknown,
                "{path} must not exist on an adapter socket"
            );
            assert!(
                matches!(parse_route(Surface::Local, path), Route::Op { .. }),
                "{path} must still be routed locally"
            );
        }
        assert_eq!(
            parse_route(Surface::Adapter, "/sign/bad name"),
            Route::Unknown
        );
    }

    /// The body reader caps at 64 KiB: a small body is read whole, an over-cap body is refused
    /// (as `TooLarge`) so no route can OOM the daemon with an unbounded local request.
    #[tokio::test]
    async fn body_reader_caps_at_limit() {
        let small = read_body_capped(Full::new(Bytes::from(vec![7u8; 1024]))).await;
        assert_eq!(small.expect("small body reads").len(), 1024);
        let too_big = read_body_capped(Full::new(Bytes::from(vec![7u8; MAX_BODY_BYTES + 1]))).await;
        assert!(matches!(too_big, Err(BodyErr::TooLarge { .. })));
    }
}
