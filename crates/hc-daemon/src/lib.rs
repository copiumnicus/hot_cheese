//! The HTTPS daemon: routes, provenance, the privileged API, and the accept loop.
//!
//! [`qr_term`] draws one [`hc_sign::qr`] frame for whichever terminal is asking — the CLI's or
//! the console's. It sits here rather than in `hc-sign` because a phone links that crate to run
//! the policy and the digest, and a phone has no terminal to draw on.
pub mod approval;
pub mod backup;
pub mod bundle;
pub mod qr_term;
pub mod socket;

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
use hc_sign::manifest::LoadedManifest;
use hc_sign::{SafeSignature, SignErr};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fmt;
use std::io;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
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
    Manifest(hc_sign::manifest::ManifestErr),
    Socket(socket::SocketErr),
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

/// A signal that ends `serve`.
#[derive(Clone, Copy, Debug)]
enum ExitSignal {
    Interrupt,
    Terminate,
    Hangup,
}

/// `hot_cheese serve`: bind loopback plus one socket per trusted adapter, and unlock on a
/// blocking thread via the TTY approver. Every manifest is loaded, pin-checked and
/// intersected with the policies in force BEFORE anything binds, so a manifest that claims
/// more than its key's policy grants stops the daemon here instead of at an incident.
///
/// SIGINT, SIGTERM and SIGHUP end the accept loops and return through here, so the sockets
/// bound below are unlinked on every ending the process can act on. `SIGKILL` cannot be caught
/// by anything, and the stale-socket protocol in [`socket`] is what covers the file it strands.
#[tokio::main]
pub async fn run_server(backend: Box<dyn BackendImpl>, config: Config) -> Result<(), ServeErr> {
    let adapters = hc_sign::manifest::load_all(&config)?;
    let tls = tls_from_home()?;
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), config.port());
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, adapters = adapters.len(), "hot_cheese serving over https");

    let config = Arc::new(config);
    let approval = Approval::Inline {
        api: Arc::new(HotApi::new(backend, config.clone())),
        approver: Arc::new(crate::approval::ServeApprover),
    };
    let (shutdown, rx) = watch::channel(false);
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        let caught = tokio::select! {
            _ = interrupt.recv() => ExitSignal::Interrupt,
            _ = terminate.recv() => ExitSignal::Terminate,
            _ = hangup.recv() => ExitSignal::Hangup,
        };
        tracing::warn!(signal = ?caught, "stopping every listener and unlinking its socket");
        let _ = shutdown.send(true);
    });

    let mut sockets = socket::AdapterSockets::bind(adapters)?;
    for (adapter, bound) in sockets.bound.drain(..) {
        let config = config.clone();
        let approval = approval.clone();
        let rx = rx.clone();
        tokio::spawn(async move {
            let id = adapter.manifest.id.clone();
            if let Err(e) = serve_loop(
                Listener::Unix(bound),
                Peer::Adapter(adapter),
                config,
                approval,
                rx,
            )
            .await
            {
                tracing::error!(adapter = %id, error = ?e, "adapter listener exited");
            }
        });
    }
    serve_loop(
        Listener::Tcp(listener, tls),
        Peer::Loopback,
        config,
        approval,
        rx,
    )
    .await
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
async fn serve_io<I>(io: TokioIo<I>, config: Arc<Config>, approval: Approval, peer: Peer)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let asked = Arc::new(AtomicBool::new(false));
    let requested = asked.clone();
    let service = service_fn(move |req| {
        requested.store(true, Ordering::Relaxed);
        let config = config.clone();
        let approval = approval.clone();
        let peer = peer.clone();
        async move { service_impl(req, config, approval, peer).await }
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
    config: Arc<Config>,
    approval: Approval,
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
        let config = config.clone();
        let approval = approval.clone();
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
                    serve_io(TokioIo::new(tls_stream), config, approval, peer).await;
                }
                Accepted::Unix(stream) => {
                    serve_io(TokioIo::new(stream), config, approval, peer).await
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

/// Takes the human decision. It returns a pre-evaluated biometric context when the flow it
/// approved reuses one; a session whose KEK is the recovery passphrase has no biometric to
/// reuse, so it approves with `None` and the passphrase unlocker does the unwrapping.
pub trait Approver: Send + Sync {
    fn approve(&self, ctx: &OpContext, summary: &str) -> Result<Option<LaContext>, SignErr>;
}

/// How a connection task turns a request into a reply.
#[derive(Clone)]
pub enum Approval {
    /// The daemon unlocks on a blocking thread, so a prompt waiting on a human never occupies
    /// an async worker and `/health` keeps answering while one is up.
    Inline {
        api: Arc<HotApi>,
        approver: Arc<dyn Approver>,
    },
    /// The console keeps the backend on its main thread; workers only shuttle ciphertext.
    Console(mpsc::Sender<PrivilegedOp>),
}

/// Run one operation against the backend. Callers must already own the approval thread.
///
/// The export permit is minted here, from the target's cleartext header, before `read` is
/// reachable at all: a key that is not sealed shareable is refused without unlocking anything,
/// and a remote caller may only ever mint itself a [`KeyUse::SignOnly`] key.
pub fn execute(
    api: &HotApi,
    approver: &dyn Approver,
    ctx: &OpContext,
    body: &[u8],
) -> Result<Vec<u8>, OpErr> {
    match ctx.op {
        Operation::Read => {
            let permit = api.export_permit(ctx)?;
            Ok(api.read(ctx, body, permit)?)
        }
        Operation::Sign => Ok(api.sign_intent(ctx, body, approver)?),
        Operation::EvmGenerate => {
            api.generate(ctx, KeyUse::SignOnly)?;
            Ok(b"success".to_vec())
        }
        Operation::SolanaGenerate => {
            api.generate_solana(ctx, KeyUse::SignOnly)?;
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
    Op(OpErr),
    Join(tokio::task::JoinError)
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

    /// Enforce the per-key policy and — for a request that arrived on an adapter's socket —
    /// that adapter's manifest on top of it, take the single biometric approval, mint and verify
    /// the grant that signing demands, sign, and return the JSON [`hc_sign::SignResponse`]. The
    /// manifest is an intersection, never a union: both it and the policy must pass, and the
    /// grant carries its digest so a hardware approval is bound to the exact adapter build that
    /// asked. Everything that can refuse the request — the name, the intent, the policy, the
    /// manifest, the pin — runs BEFORE the prompt, so a refusal costs the owner no biometric;
    /// after it only the enclave grant signature and the enclave ECDH of [`HotApi::sign`]
    /// remain, which is what keeps both inside one Touch ID.
    ///
    /// What is daemon-specific stays here: the route's key name, the request body, the
    /// provenance the listener stamped, and the pinned grant key from this machine's config.
    /// The rest is [`hc_sign::sign::prepare`] and [`hc_sign::sign::finish`], with the human's
    /// decision — a printed summary and Touch ID here, a sheet and Face ID on a phone — taken
    /// between them.
    pub fn sign_intent(
        &self,
        ctx: &OpContext,
        body: &[u8],
        approver: &dyn Approver,
    ) -> Result<Vec<u8>, SignErr> {
        if !is_valid_string_name(&ctx.key) {
            return Err(SignErr::InvalidName);
        }
        let hc_sign::intent::Intent::SafeTx(intent) = serde_json::from_slice(body)?;
        if intent.key != ctx.key {
            return Err(SignErr::IntentKeyMismatch);
        }
        let manifest_digest = match &ctx.peer {
            Peer::Adapter(adapter) => {
                hc_sign::manifest::evaluate(&intent, &adapter.manifest)?;
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

        let (approved, summary) = hc_sign::sign::prepare(intent, &loaded, manifest_digest)?;
        let auth = approver.approve(ctx, &summary)?;
        let response = hc_sign::sign::finish(
            approved,
            self.inner.as_ref(),
            pinned,
            auth.as_ref(),
            &ctx.reason(),
        )?;
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
    let outcome = match approval {
        Approval::Inline { api, approver } => {
            let unlock =
                tokio::task::spawn_blocking(move || execute(&api, approver.as_ref(), &ctx, &body));
            match unlock.await {
                Ok(Ok(answer)) => Ok(answer),
                Ok(Err(e)) => Err(e.into()),
                Err(e) => Err(e.into()),
            }
        }
        Approval::Console(tx) => delegate(&tx, ctx, body).await,
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
    use alloy_primitives::Address;
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

    /// Name validation is centralized in `sign_intent`, so the CLI path (which forwards an
    /// unvalidated intent key) is rejected before any body parse, policy load, or unlock.
    #[test]
    fn sign_intent_rejects_invalid_name() {
        let api = HotApi {
            inner: Box::new(TestBackend {
                store: "/nonexistent".to_string(),
            }),
            config: Config::for_test("/nonexistent"),
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

        assert!(matches!(
            execute(&api, &DenyAll, &ctx("LOCKED", Operation::Read), &body),
            Err(OpErr::ApiBackend(ApiBackendErr::Envelope(
                EnvErr::ExportRefused {
                    key_use: KeyUse::SignOnly
                }
            )))
        ));
        assert!(matches!(
            execute(&api, &DenyAll, &ctx("OPEN", Operation::Read), &body),
            Err(OpErr::ApiBackend(ApiBackendErr::Unlock(
                UnlockErr::NoMatchingEnrollment
            )))
        ));

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
