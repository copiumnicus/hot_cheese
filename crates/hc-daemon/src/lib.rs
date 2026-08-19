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
use err_mac::create_err_with_impls;
use hc_core::config::{cert_paths, Config};
#[cfg(test)]
use hc_core::crypto::envelope::encrypt_file;
use hc_core::crypto::envelope::{
    decrypt_file, encrypt_file_new, parse_keystore, read_keystore, EnvErr, ExportPermit, KeyUse,
    MAX_KEYSTORE_FILE_BYTES,
};
use hc_core::crypto::{keccak256, random_pk};
use hc_core::is_valid_key_name;
#[cfg(test)]
use hc_core::mac::local_auth::LaContext;
use hc_core::mac::BackendImpl;
use hc_core::share::{ClientReq, EphemeralServer, ShareErr};
use hc_core::solana::{generate_keypair as generate_solana_keypair, solana_address};
use hc_core::unlock::UnlockErr;
use hc_sign::adapter::Summary;
use hc_sign::intent::SafeTxIntent;
use hc_sign::manifest::LoadedManifest;
use hc_sign::{SignErr, SignResponse};
use http::header::{HeaderMap, HeaderValue, ALLOW, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use pki_types::pem::PemObject;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

const MAX_TLS_PEM_BYTES: u64 = 1024 * 1024;

fn read_tls_pem(path: &Path) -> io::Result<Vec<u8>> {
    // The certificate is public, but its pathname is still a trust boundary: this is both the
    // identity the daemon presents and the anchor local clients pin. Do not let a final-component
    // symlink silently substitute another certificate between installation and startup.
    hc_core::read_regular_file_bounded(path, MAX_TLS_PEM_BYTES)
}

fn parse_certs(pem: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}
fn parse_private_key(pem: &[u8]) -> io::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

create_err_with_impls!(
    #[derive(Debug)]
    pub ServeErr,
    StdIo(io::Error),
    Rustls(rustls::Error)
    ;
);

fn server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<(ServerConfig, Vec<u8>), ServeErr> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = parse_certs(cert_pem)?;
    let leaf = certs
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no certificate in PEM"))?
        .as_ref()
        .to_vec();
    let key = parse_private_key(key_pem)?;
    // This also proves the private key is usable for the leaf certificate.
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((config, leaf))
}

/// Validate an imported PEM chain and private key exactly as the daemon will use them, returning
/// the leaf DER bytes whose fingerprint clients pin. No installation file need be written first.
pub fn validate_tls_pair(cert_pem: &[u8], key_pem: &[u8]) -> Result<Vec<u8>, ServeErr> {
    let (_, leaf) = server_config_from_pem(cert_pem, key_pem)?;
    Ok(leaf)
}

/// Install the ring provider, load the pinned cert/key `init` wrote, and build the acceptor.
pub fn tls_from_home() -> Result<TlsAcceptor, ServeErr> {
    let (cert_path, key_path) = cert_paths();
    let cert_pem = read_tls_pem(&cert_path)?;
    let key_pem = hc_core::read_private_file_bounded(&key_path, MAX_TLS_PEM_BYTES)?;
    let (server_config, _) = server_config_from_pem(&cert_pem, &key_pem)?;
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

/// How long it waits instead when the failure was the process running out of descriptors. That
/// clears only as open connections end, so retrying at [`ACCEPT_BACKOFF`] would be a spin.
const DESCRIPTOR_BACKOFF: Duration = Duration::from_millis(500);

/// Connections one listener holds at once, charged at `accept` and released when the connection
/// ends. Past this the next peer is closed immediately, so an unbounded number of peers can never
/// become an unbounded number of tasks or descriptors on that listener. The process-wide ceiling
/// a launchd session gets is lower again, which is why [`descriptors_exhausted`] exists.
const MAX_CONNECTIONS: usize = 64;

/// Requests one listener has in flight at once, charged when a request actually arrives and held
/// across the human's wait, which is the only thing here that lasts. A peer that completes its
/// handshake and then says nothing holds none of these, so silent connections cannot close the
/// daemon to everybody else.
const MAX_REQUESTS: usize = 16;

/// How long a peer has to complete the TLS handshake. A loopback handshake finishes in
/// milliseconds, so this is a liveness proof rather than a lease on anything scarce.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(750);

/// How long a connection has to produce its first request. A client that has finished its
/// handshake sends one immediately, so this too is a liveness proof: past it the connection is
/// closed, and it never held a request slot to begin with.
const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Once headers select a privileged route, its complete body must arrive promptly too. Human
/// approval is deliberately unbounded, but an unauthenticated slow sender gets no such lease.
const BODY_TIMEOUT: Duration = Duration::from_secs(10);

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
    Unix(UnixStream, Option<PeerCred>),
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
                let cred = match stream.peer_cred() {
                    Ok(cred) => {
                        let cred = PeerCred {
                            uid: cred.uid(),
                            gid: cred.gid(),
                            pid: cred.pid(),
                        };
                        tracing::debug!(%cred, "accepted an adapter connection");
                        Some(cred)
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "accepted an adapter connection with unreadable peer credentials");
                        None
                    }
                };
                Ok(Accepted::Unix(stream, cred))
            }
        }
    }
}

/// Serve one connection, whatever it arrived on. `peer` is the listener's provenance and the
/// request cannot influence it, which is what makes an adapter's identity unforgeable.
///
/// A connection that has not produced a single request within [`FIRST_REQUEST_TIMEOUT`] is
/// closed; once it has, it is served for as long as it takes, because the wait it is in is a
/// human's. The scarce budget is charged at that same moment and never before, so a peer holds
/// one only while a request of its own is outstanding — and a peer that finds them all busy is
/// told so rather than dropped without a word.
async fn serve_io<I>(
    io: TokioIo<I>,
    requests: Arc<Semaphore>,
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
        let slot = requests.clone().try_acquire_owned();
        let ops = ops.clone();
        let pending = pending.clone();
        let peer = peer.clone();
        async move {
            let Ok(_slot) = slot else {
                if renderer::peer_may_log() {
                    tracing::warn!(
                        limit = MAX_REQUESTS,
                        "refusing a request: every request slot is busy"
                    );
                }
                return Ok(overloaded());
            };
            service_impl(req, ops, pending, peer).await
        }
    });
    // One HTTP/1 request per connection. This removes idle keep-alive and multiplexed HTTP/2
    // connections as ways to pin a scarce connection slot after doing one cheap request.
    let mut builder = Builder::new(TokioExecutor::new()).http1_only();
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(FIRST_REQUEST_TIMEOUT)
        .keep_alive(false)
        .max_headers(64)
        .max_buf_size(16 * 1024);
    let connection = builder.serve_connection(io, service);
    tokio::pin!(connection);
    let served = tokio::select! {
        served = &mut connection => Some(served),
        _ = tokio::time::sleep(FIRST_REQUEST_TIMEOUT) => None,
    };
    let served = match served {
        Some(served) => served,
        None if asked.load(Ordering::Relaxed) => connection.await,
        None => {
            if renderer::peer_may_log() {
                tracing::warn!("closing a connection that never sent a request");
            }
            return;
        }
    };
    if let Err(err) = served {
        if renderer::peer_may_log() {
            tracing::error!(error = %err, "failed to serve connection");
        }
    }
}

/// Whether `accept` failed because the process is out of descriptors. A launchd session gets far
/// fewer than an unauthenticated flood can open, so this is a state to wait out while open
/// connections end rather than a transient to retry at speed.
fn descriptors_exhausted(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE))
}

/// Accept connections until `shutdown` fires, serving each on its own task with the
/// provenance of the listener that accepted it. A failed `accept` is never taken as the end of
/// the listener: a peer that vanished is retried after [`ACCEPT_BACKOFF`], and a process with no
/// descriptors left after [`DESCRIPTOR_BACKOFF`], which is long enough that the wait is one and
/// not a spin.
///
/// Two budgets, because they cost different things. Every accepted peer holds one of
/// [`MAX_CONNECTIONS`], which bounds tasks and descriptors and is given up the moment its socket
/// closes — at [`HANDSHAKE_TIMEOUT`] for a peer that never handshakes and at
/// [`FIRST_REQUEST_TIMEOUT`] for one that handshakes and then goes quiet. Only a peer with a
/// request outstanding holds one of the [`MAX_REQUESTS`] slots, which is the budget that lasts a
/// human's wait: charging that at accept or at handshake is what would let silent sockets close
/// the daemon to everybody else.
pub async fn serve_loop(
    listener: Listener,
    peer: Peer,
    ops: mpsc::Sender<PrivilegedOp>,
    pending: Arc<live::Pending>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServeErr> {
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let requests = Arc::new(Semaphore::new(MAX_REQUESTS));
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = shutdown.changed() => return Ok(()),
        };
        let accepted = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                let backoff = match descriptors_exhausted(&e) {
                    true => DESCRIPTOR_BACKOFF,
                    false => ACCEPT_BACKOFF,
                };
                if renderer::peer_may_log() {
                    tracing::warn!(error = %e, backoff = ?backoff, "accept failed, retrying");
                }
                tokio::time::sleep(backoff).await;
                continue;
            }
        };
        let Ok(held) = connections.clone().try_acquire_owned() else {
            if renderer::peer_may_log() {
                tracing::warn!(
                    limit = MAX_CONNECTIONS,
                    "closing a connection: this listener is already full"
                );
            }
            continue;
        };
        let ops = ops.clone();
        let queued = pending.clone();
        let peer = peer.clone();
        let requests = requests.clone();
        tokio::spawn(async move {
            let _held = held;
            match accepted {
                Accepted::Tcp(stream, tls) => {
                    let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, tls.accept(stream));
                    let tls_stream = match handshake.await {
                        Ok(Ok(tls_stream)) => tls_stream,
                        Ok(Err(err)) => {
                            if renderer::peer_may_log() {
                                tracing::error!(error = %err, "tls handshake failed");
                            }
                            return;
                        }
                        Err(elapsed) => {
                            if renderer::peer_may_log() {
                                tracing::warn!(error = %elapsed, "tls handshake timed out");
                            }
                            return;
                        }
                    };
                    serve_io(TokioIo::new(tls_stream), requests, ops, queued, peer).await;
                }
                Accepted::Unix(stream, cred) => {
                    let peer = peer.with_process(cred);
                    serve_io(TokioIo::new(stream), requests, ops, queued, peer).await;
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
    /// A connection accepted on loopback TCP. Its ultimate origin is unauthenticated: SSH,
    /// launchd, containers, and other local forwarders are indistinguishable from a process on
    /// this machine, and some of them are invisible in this process's tunnel inventory.
    Loopback,
    /// The same unauthenticated loopback transport while `tunnels` managed reverse tunnels were
    /// open. The count is an extra warning, not a complete inventory or an origin claim.
    Unattributed { tunnels: usize },
    /// A client that opened one adapter's 0600 unix socket. The manifest is the pinned one
    /// that socket was bound for, and it is the only extra authority the request gets.
    Adapter {
        /// The manifest the accepting socket was bound for.
        manifest: Arc<LoadedManifest>,
        /// What the kernel says about the process at the other end, when it would say.
        cred: Option<PeerCred>,
    },
}

/// What `SO_PEERCRED` reports about the process on the other end of a unix socket. Shown to the
/// operator because a prompt that names nobody is a prompt nobody can judge; it is NOT
/// authentication, since pids recycle and `ssh -R` forwards into a unix socket like any other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCred {
    /// Uid the connecting process runs as.
    pub uid: u32,
    /// Its primary gid.
    pub gid: u32,
    /// Its pid, when this platform reports one.
    pub pid: Option<i32>,
}

impl fmt::Display for PeerCred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pid {
            Some(pid) => write!(f, "pid {pid}, uid {}, gid {}", self.uid, self.gid),
            None => write!(f, "uid {}, gid {}", self.uid, self.gid),
        }
    }
}

impl Peer {
    /// Name the process the kernel says opened this connection. Only an adapter socket has one,
    /// and it never changes which manifest the request is evaluated against.
    fn with_process(&self, cred: Option<PeerCred>) -> Self {
        match self {
            Peer::Adapter { manifest, .. } => Peer::Adapter {
                manifest: manifest.clone(),
                cred,
            },
            peer => peer.clone(),
        }
    }

    /// `ssh -R` forwards into the same loopback socket with the same source address. Managed
    /// tunnels add a visible warning; zero never upgrades loopback TCP into authenticated local
    /// provenance because other forwarders cannot be enumerated completely.
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
            Peer::Adapter { .. } => Surface::Adapter,
            Peer::Cli | Peer::Loopback | Peer::Unattributed { .. } => Surface::Local,
        }
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Peer::Cli => f.write_str("the local CLI"),
            Peer::Loopback => f.write_str("loopback TCP (origin unauthenticated)"),
            Peer::Unattributed { tunnels } => write!(
                f,
                "loopback TCP (origin unauthenticated; {tunnels} managed tunnel{} open)",
                if *tunnels == 1 { "" } else { "s" }
            ),
            Peer::Adapter {
                manifest,
                cred: Some(cred),
            } => write!(
                f,
                "adapter \"{}\" (manifest {}, {cred})",
                manifest.manifest.id,
                hex::encode(&manifest.digest[..8])
            ),
            Peer::Adapter {
                manifest,
                cred: None,
            } => write!(
                f,
                "adapter \"{}\" (manifest {}, peer process unknown)",
                manifest.manifest.id,
                hex::encode(&manifest.digest[..8])
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

fn required_method(route: &Route) -> Option<Method> {
    match route {
        Route::Health => Some(Method::GET),
        Route::Op { .. } => Some(Method::POST),
        Route::Unknown => None,
    }
}

/// A browser form can issue a credential-free POST to localhost, so POST alone is not a CSRF
/// boundary. HTML forms cannot set `application/json`; browser script must preflight it, and this
/// server deliberately answers no CORS preflight. Native clients and adapters set it directly.
fn has_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
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
        if !is_valid_key_name(key) {
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
    Sign(SignErr),
    Git(git_store::GitErr)
    ;
);

/// One request handed to whoever owns Touch ID and the DEK.
pub struct PrivilegedOp {
    /// What is being asked for, and by whom.
    pub ctx: OpContext,
    /// The request body (ephemeral read handshake or sign intent); empty for body-less routes.
    pub body: Bytes,
    /// Where the ciphertext answer goes.
    pub reply: oneshot::Sender<Result<Vec<u8>, OpErr>>,
    /// Keeps the pending gauge accurate even when the connection task is cancelled after send.
    pub outstanding: live::Outstanding,
}

/// Privileged ops that may queue before a further one is refused with 503 and a `Retry-After`.
pub const PENDING_OPS: usize = 4;

/// Hex characters of the request-body digest shown at the prompt: enough that two concurrent
/// `/read`s for one keystore, which differ in nothing else, are two different lines.
const DIGEST_CHARS: usize = 16;

/// Bytes of the recipient fingerprint shown at the prompt, hex-encoded to twice as many
/// characters. `/read` hands out a whole private key, so the operator is told which ephemeral
/// public key it would be sealed to and can compare it with the one their client printed.
const RECIPIENT_BYTES: usize = 8;

/// What the human reads for a route with no payload to deconstruct. Nothing walked a policy
/// here, so there is nothing that could have raised an alarm and `body` is the whole of it.
fn stated(body: String) -> Summary {
    Summary {
        alarms: Vec::new(),
        body,
    }
}

/// Run one operation against the backend. Callers must already own the approval thread. Every
/// structurally viable arm reaches `approver`, because every one of them is a request that
/// arrived over the network surface and each costs the key owner something. Requests whose
/// public on-disk state already proves they cannot succeed are refused first.
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
            let recipient = api.recipient(body)?;
            let digest = hex::encode(Sha256::digest(body));
            approver.approve(
                ctx,
                &stated(format!(
                    "recipient key sha256 {recipient}\nrequest body sha256 {}",
                    &digest[..DIGEST_CHARS]
                )),
            )?;
            Ok(api.read(ctx, body, permit)?)
        }
        Operation::Sign => Ok(api.sign_intent(ctx, body, approver)?),
        Operation::EvmGenerate => {
            api.preflight_vacant(ctx)?;
            approver.approve(ctx, &stated(String::new()))?;
            let mutation = api.git.as_ref().map(|git| git.mutation());
            api.generate(ctx, KeyUse::SignOnly)?;
            if let Some(mutation) = mutation {
                mutation.commit()?;
            }
            Ok(b"success".to_vec())
        }
        Operation::SolanaGenerate => {
            api.preflight_vacant(ctx)?;
            approver.approve(ctx, &stated(String::new()))?;
            let mutation = api.git.as_ref().map(|git| git.mutation());
            api.generate_solana(ctx, KeyUse::SignOnly)?;
            if let Some(mutation) = mutation {
                mutation.commit()?;
            }
            Ok(b"success".to_vec())
        }
        Operation::EvmAddress => {
            api.preflight_existing(ctx)?;
            approver.approve(ctx, &stated(String::new()))?;
            Ok(api.address(ctx)?.into_bytes())
        }
        Operation::SolanaAddress => {
            api.preflight_existing(ctx)?;
            approver.approve(ctx, &stated(String::new()))?;
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

/// Hand the op to the thread that owns the runtime and await its ciphertext. A full queue is
/// answered with [`DelegateErr::Overloaded`] at once rather than by waiting, so back-pressure
/// reaches the caller as a retryable status instead of an unbounded hold. What bounds a flood is
/// not a budget the daemon spends — nothing here can tell a flood from the operator's own service
/// — but the operator: prompts are serialized on one thread, every Touch ID needs a fresh `y`,
/// and one answer at a prompt buys quiet from a caller for [`approval::QUIET_PERIOD`].
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
    let outstanding = live::Outstanding::new(pending.clone());
    if let Err(e) = tx.try_send(PrivilegedOp {
        ctx,
        body,
        reply,
        outstanding,
    }) {
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
    Unreadable { source: Box<dyn std::error::Error + Send + Sync> },
    UnexpectedBody { len: usize }
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
            hc_core::wire::strict_json_from_slice::<ClientReq>(body)?;
        }
        Operation::Sign => {
            hc_core::wire::strict_json_from_slice::<hc_sign::intent::Intent>(body)?;
        }
        Operation::EvmGenerate
        | Operation::SolanaGenerate
        | Operation::EvmAddress
        | Operation::SolanaAddress => {
            if !body.is_empty() {
                return Err(BodyErr::UnexpectedBody { len: body.len() });
            }
        }
    }
    Ok(())
}

create_err_with_impls!(
    #[derive(Debug)]
    pub ApiBackendErr,
    KeyExists,
    FailReadKeypair,
    KeyNotExists,
    InvalidName,
    Serde(serde_json::Error),
    Share(ShareErr),
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
    git: Option<Arc<git_store::GitStore>>,
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
    let hash = keccak256(&pubk[1..]);
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

impl HotApi {
    fn validate_key(ctx: &OpContext) -> Result<(), ApiBackendErr> {
        if is_valid_key_name(&ctx.key) {
            Ok(())
        } else {
            Err(ApiBackendErr::InvalidName)
        }
    }

    /// Validate a keystore's public container without unlocking its secret. Missing or malformed
    /// targets cannot succeed, so network entry points use this before they alert the operator.
    fn preflight_existing(&self, ctx: &OpContext) -> Result<(), ApiBackendErr> {
        Self::validate_key(ctx)?;
        let path = self.inner.store_path().join(&ctx.key);
        match read_keystore(&path) {
            Ok(_) => Ok(()),
            Err(EnvErr::StdIo(error)) if error.kind() == io::ErrorKind::NotFound => {
                Err(ApiBackendErr::KeyNotExists)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Check namespace occupancy without following the final component. In particular, a
    /// dangling symlink is occupied and must be rejected before an approval is requested.
    fn preflight_vacant(&self, ctx: &OpContext) -> Result<(), ApiBackendErr> {
        Self::validate_key(ctx)?;
        let path = self.inner.store_path().join(&ctx.key);
        match std::fs::symlink_metadata(path) {
            Ok(_) => Err(ApiBackendErr::KeyExists),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(EnvErr::StdIo(error).into()),
        }
    }

    /// Validate the signing keystore's container and return the exact bytes validation ran over.
    /// The signing path consumes those bytes and never reopens the file, so the container the
    /// operator is asked about is the container that signs.
    fn preflight_signing_key(&self, key: &str) -> Result<Zeroizing<Vec<u8>>, SignErr> {
        let path = self.inner.store_path().join(key);
        let bytes = match hc_core::read_regular_file_bounded(&path, MAX_KEYSTORE_FILE_BYTES) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(SignErr::KeyNotExists)
            }
            Err(error) => return Err(EnvErr::StdIo(error).into()),
        };
        parse_keystore(&bytes)?;
        Ok(bytes)
    }

    pub fn new(inner: Box<dyn BackendImpl>, config: Arc<Config>) -> Self {
        Self {
            inner,
            config,
            git: None,
        }
    }

    pub(crate) fn runtime(
        inner: Box<dyn BackendImpl>,
        config: Arc<Config>,
        git: Arc<git_store::GitStore>,
    ) -> Self {
        Self {
            inner,
            config,
            git: Some(git),
        }
    }

    pub fn address(&self, ctx: &OpContext) -> Result<String, ApiBackendErr> {
        self.preflight_existing(ctx)?;
        let path = self.inner.store_path().join(&ctx.key);
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        let key = decrypt_file(&path, &ctx.key, &dek)?;
        sk_to_adr(&key)
    }
    pub fn address_solana(&self, ctx: &OpContext) -> Result<String, ApiBackendErr> {
        self.preflight_existing(ctx)?;
        let path = self.inner.store_path().join(&ctx.key);
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        let key = decrypt_file(&path, &ctx.key, &dek)?;
        solana_address(key.as_slice()).map_err(|_| ApiBackendErr::FailReadKeypair)
    }
    pub fn generate_solana(&self, ctx: &OpContext, key_use: KeyUse) -> Result<(), ApiBackendErr> {
        self.preflight_vacant(ctx)?;
        let mut rng = rand::rngs::OsRng;
        let pk = generate_solana_keypair(&mut rng).map_err(|_| ApiBackendErr::FailReadKeypair)?;
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        match encrypt_file_new(
            &self.inner.store_path(),
            &ctx.key,
            &dek,
            key_use,
            pk.as_slice(),
        ) {
            Err(EnvErr::StdIo(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(ApiBackendErr::KeyExists)
            }
            Err(error) => return Err(error.into()),
            Ok(()) => {}
        }
        Ok(())
    }
    pub fn generate(&self, ctx: &OpContext, key_use: KeyUse) -> Result<(), ApiBackendErr> {
        self.preflight_vacant(ctx)?;
        let mut rng = rand::rngs::OsRng;
        let pk = Zeroizing::new(random_pk(&mut rng).to_bytes().to_vec());
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        match encrypt_file_new(
            &self.inner.store_path(),
            &ctx.key,
            &dek,
            key_use,
            pk.as_slice(),
        ) {
            Err(EnvErr::StdIo(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(ApiBackendErr::KeyExists)
            }
            Err(error) => return Err(error.into()),
            Ok(()) => {}
        }
        Ok(())
    }
    /// Mint the export permit for `ctx.key` from its cleartext header. Reads the container
    /// only: no DEK, no unlock, no biometric, so refusing a non-shareable key is free.
    pub fn export_permit(&self, ctx: &OpContext) -> Result<ExportPermit, ApiBackendErr> {
        Self::validate_key(ctx)?;
        let path = Path::new(&self.inner.store_path()).join(&ctx.key);
        if !path.exists() {
            return Err(ApiBackendErr::KeyNotExists);
        }
        Ok(read_keystore(&path)?.export_permit()?)
    }
    /// Fingerprint the ephemeral public key a `/read` would seal its answer to, so the prompt
    /// names the recipient rather than only the request. Reads nothing and unlocks nothing.
    pub fn recipient(&self, body: &[u8]) -> Result<String, ApiBackendErr> {
        let req: ClientReq = hc_core::wire::strict_json_from_slice(body)?;
        Ok(hex::encode(&Sha256::digest(&req.pubk)[..RECIPIENT_BYTES]))
    }

    /// Release the permitted key to the client over an ephemeral P-256 channel.
    /// Works for both solana/evm.
    /// The permit is the only way in, and it exists only for a sealed shareable keystore.
    pub fn read(
        &self,
        ctx: &OpContext,
        body: &[u8],
        permit: ExportPermit,
    ) -> Result<Vec<u8>, ApiBackendErr> {
        Self::validate_key(ctx)?;
        let req: ClientReq = hc_core::wire::strict_json_from_slice(body)?;
        let fingerprint = Sha256::digest(&req.pubk);
        tracing::info!(client_key = %hex::encode(&fingerprint[..8]), "accepted ephemeral read key");
        let dek = self.inner.unlock_dek(&ctx.reason(), None)?;
        let key = permit.open(&ctx.key, &dek)?;
        let server = EphemeralServer::new();
        let res = server.encrypt_secret(&req, &ctx.key, &key)?;
        Ok(serde_json::to_vec(&res)?)
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
        let response = match hc_core::wire::strict_json_from_slice(body)? {
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
        if !is_valid_key_name(&ctx.key) {
            return Err(SignErr::InvalidName);
        }
        if intent.key != ctx.key {
            return Err(SignErr::IntentKeyMismatch);
        }
        let manifest_digest = match &ctx.peer {
            Peer::Adapter { manifest, .. } => {
                hc_sign::manifest::evaluate_typed(&intent, &manifest.manifest)?;
                manifest.digest
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
        let container = self.preflight_signing_key(&ctx.key)?;
        let auth = approver.approve(ctx, &summary)?;
        hc_sign::sign::finish(
            approved,
            container,
            self.inner.as_ref(),
            pinned,
            auth.as_ref(),
            &ctx.reason(),
        )
    }

    /// Enforce the per-key policy and — for a request that arrived on an adapter's socket —
    /// that adapter's manifest on top of it, take the single biometric approval, mint and verify
    /// the grant that signing demands, and sign. The manifest is an intersection, never a union:
    /// both it and the policy must pass, and the grant carries its digest, so a hardware
    /// approval is bound to the manifest pinned for the SOCKET the request arrived on. Nothing
    /// here identifies the process behind that socket: its credentials are shown to the operator
    /// and are not verified, so the grant does not bind which build connected.
    ///
    /// Everything that can refuse the request —
    /// the name, the intent, the policy, the manifest, the pin, the keystore container — runs
    /// BEFORE the prompt, so a refusal costs the owner no biometric; after it only the enclave
    /// grant signature and the enclave ECDH of [`HotApi::sign`] remain, which is what keeps both
    /// inside one Touch ID. That container travels into [`hc_sign::sign::finish`] with the
    /// approval, so the signing path reopens no file and a swap during the answer changes nothing.
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
        if !is_valid_key_name(&ctx.key) {
            return Err(SignErr::InvalidName);
        }
        if intent.key != ctx.key {
            return Err(SignErr::IntentKeyMismatch);
        }
        let (grant, manifest_digest) = match &ctx.peer {
            Peer::Adapter { manifest, .. } => (
                Some(hc_sign::manifest::evaluate(&intent, &manifest.manifest)?),
                manifest.digest,
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
        let container = self.preflight_signing_key(&ctx.key)?;
        let auth = approver.approve(ctx, &summary)?;
        hc_sign::sign::finish(
            approved,
            container,
            self.inner.as_ref(),
            pinned,
            auth.as_ref(),
            &ctx.reason(),
        )
    }
}

fn uncached_response() -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::default());
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// What a peer gets when the daemon has no room for its request right now: a status it can act
/// on and a moment to come back with, rather than a connection closed with nothing said. It is
/// deliberately not `500`, because a client that retries every server error would otherwise turn
/// its own back-pressure into a loop.
fn overloaded() -> Response<Full<Bytes>> {
    let mut response = uncached_response();
    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

async fn service_impl(
    req: Request<Incoming>,
    ops: mpsc::Sender<PrivilegedOp>,
    pending: Arc<live::Pending>,
    peer: Peer,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = uncached_response();
    // Every privileged success is security-sensitive (ciphertext, a signature, an address, or
    // a key-creation result), and even an error can reveal whether a route/key exists. Keep all
    // of them out of intermediary and client caches; setting this before routing covers every
    // early-return path as well as successful operations.
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    tracing::debug!(path = %path, "request");
    let route = parse_route(peer.surface(), &path);
    let Some(expected) = required_method(&route) else {
        *response.status_mut() = StatusCode::NOT_FOUND;
        return Ok(response);
    };
    if method != expected {
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response.headers_mut().insert(
            ALLOW,
            match expected {
                Method::GET => HeaderValue::from_static("GET"),
                _ => HeaderValue::from_static("POST"),
            },
        );
        if renderer::peer_may_log() {
            tracing::warn!(%method, %path, "request method refused before any body or approval");
        }
        return Ok(response);
    }
    if route == Route::Health {
        *response.body_mut() = "ok".as_bytes().to_vec().into();
        return Ok(response);
    }
    if !has_json_content_type(req.headers()) {
        *response.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
        if renderer::peer_may_log() {
            tracing::warn!(%path, "privileged request lacked application/json before any body or approval");
        }
        return Ok(response);
    }
    let body = match tokio::time::timeout(BODY_TIMEOUT, read_body_capped(req.into_body())).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            *response.status_mut() = match e {
                BodyErr::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                BodyErr::Unreadable { .. }
                | BodyErr::Malformed(_)
                | BodyErr::UnexpectedBody { .. } => StatusCode::BAD_REQUEST,
            };
            if renderer::peer_may_log() {
                tracing::warn!(error = ?e, %path, "body refused before any route ran");
            }
            return Ok(response);
        }
        Err(e) => {
            *response.status_mut() = StatusCode::REQUEST_TIMEOUT;
            if renderer::peer_may_log() {
                tracing::warn!(error = %e, %path, "body timed out before any route ran");
            }
            return Ok(response);
        }
    };
    let Route::Op { op, key } = route else {
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return Ok(response);
    };
    if let Err(e) = check_body(op, &body) {
        if renderer::peer_may_log() {
            tracing::warn!(error = ?e, %path, "body refused before any approval");
        }
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(response);
    }

    let ctx = OpContext { key, op, peer };
    match delegate(&ops, &pending, ctx, body).await {
        Ok(out) => {
            *response.body_mut() = out.into();
        }
        Err(DelegateErr::Op(OpErr::Denied | OpErr::Sign(SignErr::ApprovalDenied))) => {
            *response.status_mut() = StatusCode::FORBIDDEN;
            if renderer::peer_may_log() {
                tracing::info!(%path, "the operator refused the request");
            }
        }
        Err(DelegateErr::Op(e)) => {
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            tracing::error!(error = ?e, %path, "operation failed");
        }
        Err(DelegateErr::Overloaded) => {
            response = overloaded();
            if renderer::peer_may_log() {
                tracing::warn!(%path, "operation refused: the approval queue is full");
            }
        }
        Err(DelegateErr::ConsoleGone) => {
            *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            tracing::error!(%path, "operation refused: nothing is answering approvals");
        }
    }
    Ok(response)
}

#[cfg(test)]
mod test {
    use super::*;
    use alloy_primitives::{Address, U256};
    use hc_core::crypto::envelope::{Dek, EnvErr};

    #[test]
    fn every_http_response_starts_uncacheable() {
        assert_eq!(
            uncached_response().headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }

    #[test]
    fn privileged_content_type_cannot_be_forged_by_an_html_form() {
        let mut headers = HeaderMap::new();
        assert!(!has_json_content_type(&headers));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(!has_json_content_type(&headers));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        assert!(!has_json_content_type(&headers));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(has_json_content_type(&headers));
    }

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
            git: None,
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

    #[test]
    fn local_api_rejects_path_names_before_writing() {
        let root = std::env::temp_dir().join(format!(
            "hot_cheese_api_invalid_name_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store_path = root.join("store");
        std::fs::create_dir_all(&store_path).unwrap();
        let store = store_path.to_string_lossy().into_owned();
        let api = HotApi {
            inner: Box::new(TestBackend {
                store: store.clone(),
            }),
            config: Config::for_test(&store),
            git: None,
        };

        assert!(matches!(
            api.generate(&ctx("../ESCAPE", Operation::EvmGenerate), KeyUse::SignOnly),
            Err(ApiBackendErr::InvalidName)
        ));
        assert!(matches!(
            api.address(&ctx("../ESCAPE", Operation::EvmAddress)),
            Err(ApiBackendErr::InvalidName)
        ));
        assert!(!root.join("ESCAPE").exists());

        std::fs::remove_dir_all(root).unwrap();
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
            git: None,
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

    #[test]
    fn a_disconnected_queued_request_never_prompts() {
        let api = HotApi {
            inner: Box::new(TestBackend {
                store: "/nonexistent".to_string(),
            }),
            config: Config::for_test("/nonexistent"),
            git: None,
        };
        let (recorder, approver) = recording(renderer::Decision::Approve);
        let pending = Arc::new(live::Pending::default());
        let (reply, answer) = oneshot::channel();
        let op = PrivilegedOp {
            ctx: ctx("NEVER_PROMPT", Operation::EvmGenerate),
            body: Bytes::new(),
            reply,
            outstanding: live::Outstanding::new(pending.clone()),
        };
        assert_eq!(pending.get(), 1);
        drop(answer);

        assert_eq!(
            runtime::service_one(&api, &approver, op),
            runtime::Outcome::Failed
        );
        assert!(recorder.seen.lock().is_empty());
        assert_eq!(pending.get(), 0);
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

    /// Public namespace/container failures cannot be repaired by Touch ID. Both address routes
    /// and both creation routes must therefore refuse them without reaching the renderer.
    #[test]
    fn public_keystore_failures_do_not_prompt() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_public_preflight_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("BROKEN"), b"not a keystore").unwrap();
        std::fs::write(dir.join("TAKEN"), b"occupied").unwrap();
        std::os::unix::fs::symlink("missing-target", dir.join("DANGLING")).unwrap();

        let store = dir.to_string_lossy().into_owned();
        let api = HotApi {
            inner: Box::new(NeverUnlocks {
                store: store.clone(),
            }),
            config: Config::for_test(&store),
            git: None,
        };
        let (recorder, approver) = recording(renderer::Decision::Approve);

        assert!(matches!(
            execute(&api, &approver, &ctx("MISSING", Operation::EvmAddress), b""),
            Err(OpErr::ApiBackend(ApiBackendErr::KeyNotExists))
        ));
        assert!(matches!(
            execute(
                &api,
                &approver,
                &ctx("BROKEN", Operation::SolanaAddress),
                b""
            ),
            Err(OpErr::ApiBackend(ApiBackendErr::Envelope(_)))
        ));
        assert!(matches!(
            execute(&api, &approver, &ctx("TAKEN", Operation::EvmGenerate), b""),
            Err(OpErr::ApiBackend(ApiBackendErr::KeyExists))
        ));
        assert!(matches!(
            execute(
                &api,
                &approver,
                &ctx("DANGLING", Operation::SolanaGenerate),
                b""
            ),
            Err(OpErr::ApiBackend(ApiBackendErr::KeyExists))
        ));
        assert!(recorder.seen.lock().is_empty());

        std::fs::remove_dir_all(dir).unwrap();
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
            git: None,
        };
        let (req, _decryptor) = hc_core::share::EphemeralClient::new().sendable();
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

    #[test]
    fn missing_signing_key_is_refused_after_policy_without_a_prompt() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_sign_preflight_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("policies")).unwrap();
        std::fs::write(
            dir.join("policies").join("MISSING_SIGN.toml"),
            EVERY_OP_POLICY,
        )
        .unwrap();

        let store = dir.to_string_lossy().into_owned();
        let api = HotApi {
            inner: Box::new(NeverUnlocks {
                store: store.clone(),
            }),
            config: Config::for_test(&store),
            git: None,
        };
        let (recorder, approver) = recording(renderer::Decision::Approve);
        let intent = EVERY_OP_INTENT.replace("EVERY_OP", "MISSING_SIGN");

        assert!(matches!(
            execute(
                &api,
                &approver,
                &ctx("MISSING_SIGN", Operation::Sign),
                intent.as_bytes()
            ),
            Err(OpErr::Sign(SignErr::KeyNotExists))
        ));
        assert!(recorder.seen.lock().is_empty());

        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The grant binds the key NAME, never the key, and no prompt shows the signer's address, so
    /// the container the operator is asked about has to be the container that signs. The daemon
    /// buys that by handing `finish` the bytes it validated: a same-uid writer replacing
    /// `<store>/<KEY>` during the deliberation reaches the file, never the approved container.
    #[test]
    fn the_signing_container_survives_a_swap_of_the_file_it_came_from() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_sign_swap_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dek = Dek::from_bytes([42u8; 32]);
        encrypt_file(&dir, "SWAP_ME", &dek, KeyUse::SignOnly, &[0x44u8; 32]).unwrap();

        let store = dir.to_string_lossy().to_string();
        let api = HotApi {
            inner: Box::new(TestBackend {
                store: store.clone(),
            }),
            config: Config::for_test(&store),
            git: None,
        };
        let container = api.preflight_signing_key("SWAP_ME").unwrap();
        encrypt_file(&dir, "SWAP_ME", &dek, KeyUse::SignOnly, &[0x55u8; 32]).unwrap();

        assert_eq!(
            parse_keystore(&container)
                .unwrap()
                .open("SWAP_ME", &dek)
                .unwrap()
                .as_slice(),
            &[0x44u8; 32],
            "the carried container must still be the approved key"
        );
        assert_eq!(
            decrypt_file(&dir.join("SWAP_ME"), "SWAP_ME", &dek)
                .unwrap()
                .as_slice(),
            &[0x55u8; 32],
            "the swap has to have actually landed for this to prove anything"
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

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
            git: None,
        };
        let (recorder, approver) = recording(renderer::Decision::Deny);
        let (req, _decryptor) = hc_core::share::EphemeralClient::new().sendable();
        let read_body = serde_json::to_vec(&req).unwrap();

        let every = [
            (Operation::Read, "EVERY_OP"),
            (Operation::Sign, "EVERY_OP"),
            (Operation::EvmGenerate, "NEW_EVM"),
            (Operation::SolanaGenerate, "NEW_SOLANA"),
            (Operation::EvmAddress, "EVERY_OP"),
            (Operation::SolanaAddress, "EVERY_OP"),
        ];
        for (op, key) in every {
            let body: &[u8] = match op {
                Operation::Sign => EVERY_OP_INTENT.as_bytes(),
                Operation::Read => &read_body,
                _ => b"{}",
            };
            assert!(
                matches!(
                    execute(&api, &approver, &ctx(key, op), body),
                    Err(OpErr::Sign(SignErr::ApprovalDenied))
                ),
                "{op:?} must be refused at the prompt, before the backend"
            );
        }
        let seen: Vec<Operation> = recorder.seen.lock().iter().map(|(_, op)| *op).collect();
        assert_eq!(
            seen,
            every.map(|(op, _)| op),
            "every route must have reached the renderer"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Loopback TCP never authenticates an ultimate origin. A managed reverse tunnel adds a
    /// count to that warning, but zero tunnels must not become a local-machine claim because an
    /// inbound sshd forward or another proxy is invisible to this inventory.
    #[test]
    fn an_open_tunnel_strips_the_local_origin_claim() {
        let mut ctx = ctx("TRADER", Operation::Read);
        ctx.peer = Peer::Loopback.with_tunnels(1);
        assert!(matches!(ctx.peer, Peer::Unattributed { tunnels: 1 }));
        let reason = ctx.reason();
        assert!(!reason.contains("localhost"), "{reason}");
        assert!(
            reason.contains("origin unauthenticated; 1 managed tunnel open"),
            "{reason}"
        );

        ctx.peer = Peer::Loopback.with_tunnels(0);
        assert!(matches!(ctx.peer, Peer::Loopback));
        assert!(ctx
            .reason()
            .contains("loopback TCP (origin unauthenticated)"));
        assert!(matches!(Peer::Cli.with_tunnels(3), Peer::Cli));
    }

    fn adapter_peer() -> Peer {
        Peer::Adapter {
            manifest: Arc::new(LoadedManifest {
                manifest: hc_sign::manifest::Manifest {
                    schema: hc_sign::manifest::SCHEMA.to_string(),
                    id: "safe_treasury_bot".to_string(),
                    grants: Vec::new(),
                },
                digest: B256::from([0xabu8; 32]),
                path: Path::new("/nonexistent/safe_treasury_bot.toml").to_path_buf(),
            }),
            cred: None,
        }
    }

    /// Provenance belongs to the listener, never to the request: an adapter peer answers the
    /// adapter route table by construction, and the line the Touch ID sheet and the console
    /// prompt show names which adapter asked, which manifest build it is running, and which
    /// process the kernel says opened the socket.
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

        let mut ctx = OpContext {
            key: "TREASURY".to_string(),
            op: Operation::Sign,
            peer: adapter_peer(),
        };
        let reason = ctx.reason();
        assert!(reason.contains("safe_treasury_bot"), "{reason}");
        assert!(reason.contains("abababababababab"), "{reason}");
        assert!(reason.contains("peer process unknown"), "{reason}");

        ctx.peer = ctx.peer.with_process(Some(PeerCred {
            uid: 501,
            gid: 20,
            pid: Some(4242),
        }));
        let named = ctx.reason();
        assert!(named.contains("pid 4242, uid 501, gid 20"), "{named}");
        assert_eq!(
            ctx.peer.surface(),
            Surface::Adapter,
            "naming the process may not change which routes it reaches"
        );
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
        assert!(matches!(
            check_body(Operation::EvmAddress, b"not json"),
            Err(BodyErr::UnexpectedBody { .. })
        ));
        assert!(check_body(Operation::EvmAddress, b"").is_ok());

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
        let typed = format!("{TYPED}}}");
        let nested_types = typed.replace(
            "\"message\":{\"amount\":\"1\"}",
            "\"message\":{\"types\":{}}",
        );
        assert!(
            check_body(Operation::Sign, nested_types.as_bytes()).is_ok(),
            "a `types` key INSIDE the sole message parses, and is refused by the schema walk instead"
        );
        assert!(matches!(
            check_body(
                Operation::Sign,
                format!("{TYPED},\"message\":{{\"types\":{{}}}}}}").as_bytes()
            ),
            Err(BodyErr::Malformed(_))
        ));
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
            git: None,
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
        assert_eq!(
            parse_route(Surface::Local, "/evm_generate/policies"),
            Route::Unknown,
            "the policy directory is reserved and can never become a keystore"
        );
        assert_eq!(
            parse_route(Surface::Local, "/evm_generate/POLICIES"),
            Route::Unknown,
            "case variants must also be reserved on case-insensitive filesystems"
        );
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

    #[test]
    fn only_health_accepts_get_and_every_privileged_route_requires_post() {
        assert_eq!(required_method(&Route::Health), Some(Method::GET));
        for path in [
            "/read/K",
            "/sign/K",
            "/evm_generate/K",
            "/evm_address/K",
            "/solana_generate/K",
            "/solana_address/K",
        ] {
            assert_eq!(
                required_method(&parse_route(Surface::Local, path)),
                Some(Method::POST),
                "{path} must not be triggerable by a browser navigation or image GET"
            );
        }
        assert_eq!(required_method(&Route::Unknown), None);
    }

    /// A peer that finishes its handshake and then says nothing must never hold a request slot.
    /// With every connection slot but one taken by silent peers — far more of them than there
    /// are request slots — a real client still gets its answer.
    #[test]
    fn silent_connections_cannot_pin_the_request_slots() {
        use std::io::{Read, Write};

        // A unix socket path has to fit in `sun_path`, which the per-user temp directory does not.
        let socket = Path::new("/tmp").join(format!("hcd_silent_{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);

        let tokio = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let listener = {
            let _entered = tokio.enter();
            UnixListener::bind(&socket).unwrap()
        };
        let (tx, _ops) = mpsc::channel(PENDING_OPS);
        let (shutdown, rx) = watch::channel(false);
        let pending = Arc::new(live::Pending::default());
        tokio.spawn(serve_loop(
            Listener::Unix(listener),
            Peer::Loopback,
            tx,
            pending,
            rx,
        ));

        let mut silent = Vec::new();
        for _ in 0..MAX_CONNECTIONS - 1 {
            silent.push(std::os::unix::net::UnixStream::connect(&socket).unwrap());
        }
        assert!(
            silent.len() > MAX_REQUESTS,
            "the point is more silent peers than there are request slots"
        );

        let mut client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: hot_cheese\r\n\r\n")
            .unwrap();
        let mut answered = String::new();
        client.read_to_string(&mut answered).unwrap();
        assert!(answered.starts_with("HTTP/1.1 200 OK"), "{answered}");
        assert!(answered.ends_with("ok"), "{answered}");

        let _ = shutdown.send(true);
        tokio.shutdown_timeout(Duration::from_secs(2));
        std::fs::remove_file(&socket).unwrap();
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
