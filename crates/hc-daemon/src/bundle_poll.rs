//! The background bundle poller: one thread, one interval, and the one status both renderers
//! read.
//!
//! It runs on a plain `std::thread`, never on `spawn_blocking`. The work is subprocess,
//! filesystem and secp256k1 — none of which may sit on a tokio worker — and the loop is
//! long-lived, so a pool slot would be parked for the whole session beside the sign path.
//!
//! It touches no key, no approver and no store: everything it reads or writes is under
//! `home_dir()/bundles` and `home_dir()/bundle-quarantine`, which is why it needs neither
//! [`crate::flock::Claim`] nor a `LaContext`, and can never contend with the main-thread approver.
use alloy_primitives::B256;
use hc_bundle::ingest::MAX_FILES_PER_BUNDLE;
use hc_bundle::poll::{PeerTick, PollErr, Poller, Stock};
use hc_bundle::sync::SyncErr;
use hc_bundle::Arrival;
use hc_core::config::{BundlePeer, Config};
use hc_sign::grant::now_secs;
use parking_lot::{Mutex, MutexGuard};
use std::collections::VecDeque;
use std::sync::mpsc::{
    channel, sync_channel, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError,
};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Arrivals the status keeps for a renderer, newest last.
const ARRIVAL_RING: usize = 16;

/// Ticks a peer that floods us is skipped for, at most.
const MAX_SKIP_TICKS: u32 = 32;

/// Seconds a caller waiting on a tick gives up after. `ConnectTimeout` bounds only ssh's connect,
/// so a peer that answers and then stalls holds a transfer nothing else bounds, and the thread
/// that owns the terminal must not wait on that forever.
const POKE_DEADLINE_SECS: u64 = 30;

/// What a caller is asking the poller to do, and whether it waits.
pub enum Poke {
    /// Record a bundle this device wrote into, push it, and return without waiting.
    Push { hash: B256 },
    /// Block until a tick has finished.
    AwaitTick,
}

/// One message on the poller's channel.
enum PollRequest {
    Push(B256),
    Await(SyncSender<()>),
    Stop,
}

/// Whether the loop carries on.
enum Flow {
    Go,
    Stop,
}

/// What the poller has done, as of the last tick that finished.
#[derive(Default)]
pub struct PollStatus {
    /// Unix seconds the last tick finished; `None` before the first one.
    pub last_finished_at: Option<u64>,
    /// How long that tick took, in milliseconds. An elapsed duration, not an epoch stamp.
    pub last_took_ms: u64,
    /// Ticks finished since this runtime started.
    pub ticks: u64,
    /// Seconds between ticks, as the last tick read it from `config.toml`.
    pub interval_secs: u64,
    /// One row per enrolled peer, in `config.toml` order. Empty before the first tick, so a
    /// renderer must take "how many are enrolled" from `config.bundle_peers` and not from here.
    pub peers: Vec<PeerPoll>,
    /// Bundle directories this machine holds.
    pub bundles: usize,
    /// How many of them have met their threshold, which is what a human collecting waits for.
    pub ready: usize,
    /// Newest last, capped at [`ARRIVAL_RING`].
    pub arrivals: VecDeque<Arrival>,
    /// Signatures that have arrived since this runtime started.
    pub arrived: u64,
    /// Files moved to bundle-quarantine since this runtime started.
    pub quarantined: u64,
    /// Files and directories refused for breaking a cap since this runtime started.
    pub refused: u64,
    /// Why the last tick could not finish, when it could not.
    pub failure: Option<PollErr>,
}

/// One peer's row, as of the last tick that was not skipped for it.
pub struct PeerPoll {
    /// The peer's ssh target.
    pub host: String,
    /// What its last pull did.
    pub pull: Result<(), SyncErr>,
    /// What its last push of this device's own bundles did: the first failure, or `Ok`.
    pub push: Result<(), SyncErr>,
    /// Unix seconds of the last pull from it that succeeded.
    pub last_ok_at: Option<u64>,
    /// Signatures its last pull brought in.
    pub arrivals: usize,
    /// Files its last pull brought in that failed verification.
    pub quarantined: usize,
    /// Files and directories its last pull brought in that broke a cap.
    pub refused: usize,
    /// Consecutive ticks it flooded this machine, which is what sets `skip_ticks`.
    pub floods: u32,
    /// Ticks it stays skipped for after flooding; 0 when it is not backed off.
    pub skip_ticks: u32,
}

/// A peer nothing has been learned about yet.
fn fresh_peer(host: &str) -> PeerPoll {
    PeerPoll {
        host: host.to_string(),
        pull: Ok(()),
        push: Ok(()),
        last_ok_at: None,
        arrivals: 0,
        quarantined: 0,
        refused: 0,
        floods: 0,
        skip_ticks: 0,
    }
}

/// Fold one pass's stock into the shared totals and the arrivals ring, and hand back what one
/// peer's row shows of it.
fn absorb(status: &mut PollStatus, stock: Stock) -> (usize, usize, usize) {
    let arrivals = stock.arrivals.len();
    let quarantined = stock.verdict.rejected.len();
    let refused = stock.verdict.refused_dirs.len() + stock.verdict.refused_files;
    status.bundles = stock.bundles;
    status.ready = stock.ready;
    status.arrived += arrivals as u64;
    status.quarantined += quarantined as u64;
    status.refused += refused as u64;
    for arrival in stock.arrivals {
        if status.arrivals.len() == ARRIVAL_RING {
            status.arrivals.pop_front();
        }
        status.arrivals.push_back(arrival);
    }
    (arrivals, quarantined, refused)
}

/// The background poller: the channel its requests ride, and what it last did.
pub struct BundlePoll {
    status: Mutex<PollStatus>,
    requests: Sender<PollRequest>,
}

impl BundlePoll {
    /// Read the last tick. Never hold this across a prompt; `inquire` owns the terminal.
    pub fn status(&self) -> MutexGuard<'_, PollStatus> {
        self.status.lock()
    }

    /// Ask for a tick now, optionally waiting for one to finish.
    pub fn poke(&self, poke: Poke) -> Result<(), PollErr> {
        let (request, wait) = match poke {
            Poke::Push { hash } => (PollRequest::Push(hash), None),
            Poke::AwaitTick => {
                let (done, wait) = sync_channel(1);
                (PollRequest::Await(done), Some(wait))
            }
        };
        if self.requests.send(request).is_err() {
            return Err(PollErr::PollerGone);
        }
        let Some(wait) = wait else {
            return Ok(());
        };
        match wait.recv_timeout(Duration::from_secs(POKE_DEADLINE_SECS)) {
            Ok(()) => Ok(()),
            Err(RecvTimeoutError::Timeout) => Err(PollErr::PokeTimedOut {
                secs: POKE_DEADLINE_SECS,
            }),
            Err(RecvTimeoutError::Disconnected) => Err(PollErr::PollerGone),
        }
    }

    /// Ask the loop to leave. Explicit rather than dropping the sender, because a renderer may
    /// still hold a clone of this and shutdown may not depend on who else does.
    pub(crate) fn close(&self) {
        let _ = self.requests.send(PollRequest::Stop);
    }

    /// Make the recorded peers match `peers`, in that order, keeping everything already learned
    /// about one that is still enrolled — so an edited `config.toml` neither loses a backoff nor
    /// leaves a machine nobody talks to on the status.
    fn align(&self, peers: &[BundlePeer]) {
        let mut status = self.status.lock();
        let mut aligned = Vec::with_capacity(peers.len());
        for peer in peers {
            let known = status.peers.iter().position(|row| row.host == peer.host);
            aligned.push(match known {
                Some(i) => status.peers.swap_remove(i),
                None => fresh_peer(&peer.host),
            });
        }
        status.peers = aligned;
    }

    /// Whether this tick skips a peer, spending one of the ticks it is backed off for.
    fn skipping(&self, host: &str) -> bool {
        let mut status = self.status.lock();
        let Some(row) = status.peers.iter_mut().find(|row| row.host == host) else {
            return false;
        };
        if row.skip_ticks == 0 {
            return false;
        }
        row.skip_ticks -= 1;
        true
    }

    /// Record everything one peer's half of a tick did: its row, the arrivals it brought, and the
    /// backoff a flood earns it. The backoff is a rate limiter and not a trust decision — the peer
    /// stays enrolled, it self-clears, and the row says why the machine went quiet.
    fn peer_done(&self, host: &str, at: u64, done: PeerTick) {
        let mut status = self.status.lock();
        let (arrivals, quarantined, refused, judged) = match done.stock {
            Some(stock) => {
                let judged = stock.verdict.judged;
                let (arrivals, quarantined, refused) = absorb(&mut status, stock);
                (arrivals, quarantined, refused, judged)
            }
            None => (0, 0, 0, 0),
        };
        let flooded = refused > 0 || judged > MAX_FILES_PER_BUNDLE;
        let known = status.peers.iter().position(|row| row.host == host);
        let i = match known {
            Some(i) => i,
            None => {
                status.peers.push(fresh_peer(host));
                status.peers.len() - 1
            }
        };
        let row = &mut status.peers[i];
        if done.pull.is_ok() {
            row.last_ok_at = Some(at);
        }
        row.pull = done.pull;
        row.push = done.push;
        row.arrivals = arrivals;
        row.quarantined = quarantined;
        row.refused = refused;
        match flooded {
            true => {
                row.floods += 1;
                row.skip_ticks = 1u32
                    .checked_shl(row.floods)
                    .unwrap_or(MAX_SKIP_TICKS)
                    .min(MAX_SKIP_TICKS);
            }
            false => {
                row.floods = 0;
                row.skip_ticks = 0;
            }
        }
    }

    /// Record a pass this machine took with no peer, so a machine that has none still counts what
    /// it holds and how much of it is ready.
    fn stock_done(&self, stock: Stock) {
        absorb(&mut self.status.lock(), stock);
    }
}

/// The poller's thread, and the signal it sends as it leaves so shutdown can bound its wait.
pub struct PollThread {
    done: Receiver<()>,
    handle: JoinHandle<()>,
}

impl PollThread {
    /// Wait for the loop to leave, then join it. Nothing bounds an rsync a peer has answered and
    /// then stalled, so past `grace` the wait is abandoned and the child dies with this process's
    /// group — an unreachable peer must not be able to stop the daemon from stopping.
    pub fn join(self, grace: Duration) {
        match self.done.recv_timeout(grace) {
            Ok(()) => {
                let _ = self.handle.join();
            }
            Err(_) => {
                tracing::warn!("the bundle poller is still in a transfer; leaving without it")
            }
        }
    }
}

/// Start the poller and hand back what the runtime holds: the shared status and the thread.
pub fn start(interval_secs: u64) -> Result<(Arc<BundlePoll>, PollThread), std::io::Error> {
    let (requests, inbox) = channel();
    let (leaving, done) = sync_channel(1);
    let poll = Arc::new(BundlePoll {
        status: Mutex::new(PollStatus {
            interval_secs,
            ..PollStatus::default()
        }),
        requests,
    });
    let running = poll.clone();
    let handle = std::thread::Builder::new()
        .name("bundle-poll".to_string())
        .spawn(move || {
            Loop {
                poll: running,
                inbox,
                interval: Duration::from_secs(interval_secs),
                pushed: Vec::new(),
                pending: Vec::new(),
            }
            .run();
            let _ = leaving.try_send(());
        })?;
    Ok((poll, PollThread { done, handle }))
}

/// The poller thread's own state: everything one tick needs and nothing else.
struct Loop {
    poll: Arc<BundlePoll>,
    inbox: Receiver<PollRequest>,
    /// How long to wait between ticks, as the last tick read it from `config.toml`.
    interval: Duration,
    /// Digests a poke named, applied at the top of the next tick.
    pushed: Vec<B256>,
    /// Callers blocked until a tick finishes.
    pending: Vec<SyncSender<()>>,
}

impl Loop {
    /// Prime, then tick forever. The wait starts when a tick FINISHES, so ticks never overlap and
    /// never pile up: a tick runs long precisely because a peer is slow, and the answer to a slow
    /// peer is not a second rsync against it.
    fn run(mut self) {
        let mut poller = loop {
            match Poller::start() {
                Ok(poller) => break poller,
                Err(e) => {
                    tracing::warn!(error = %e, "the bundle poller could not take stock of its tree");
                    self.poll.status().failure = Some(e);
                    if matches!(self.wait(), Flow::Stop) {
                        return;
                    }
                }
            }
        };
        loop {
            if matches!(self.tick(&mut poller), Flow::Stop) {
                return;
            }
            if self.pushed.is_empty()
                && self.pending.is_empty()
                && matches!(self.wait(), Flow::Stop)
            {
                return;
            }
        }
    }

    fn take(&mut self, request: PollRequest) -> Flow {
        match request {
            PollRequest::Push(hash) => {
                self.pushed.push(hash);
                Flow::Go
            }
            PollRequest::Await(done) => {
                self.pending.push(done);
                Flow::Go
            }
            PollRequest::Stop => Flow::Stop,
        }
    }

    fn wait(&mut self) -> Flow {
        match self.inbox.recv_timeout(self.interval) {
            Ok(request) => self.take(request),
            Err(RecvTimeoutError::Timeout) => Flow::Go,
            Err(RecvTimeoutError::Disconnected) => Flow::Stop,
        }
    }

    /// Whether shutdown arrived while the tick was between peers. One peer's in-flight rsync is
    /// the most a stop ever waits on; the rest of the tick is abandoned.
    fn stopping(&mut self) -> bool {
        loop {
            match self.inbox.try_recv() {
                Ok(request) => {
                    if matches!(self.take(request), Flow::Stop) {
                        return true;
                    }
                }
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => return true,
            }
        }
    }

    /// One tick: reload the config, pull from every enrolled peer in turn, push back what this
    /// device wrote, and publish what all of it found.
    fn tick(&mut self, poller: &mut Poller) -> Flow {
        let started = Instant::now();
        let answering: Vec<SyncSender<()>> = self.pending.drain(..).collect();
        for hash in self.pushed.drain(..) {
            poller.contributed(hash);
        }
        let mut failure = None;
        let at = match now_secs() {
            Ok(at) => at,
            Err(e) => {
                self.poll.status().failure = Some(e.into());
                return Flow::Go;
            }
        };
        let mut took = false;
        match Config::load() {
            Err(e) => failure = Some(e.into()),
            Ok(cfg) => {
                self.interval = Duration::from_secs(cfg.bundle_watch_secs());
                self.poll.align(&cfg.bundle_peers);
                for peer in &cfg.bundle_peers {
                    if self.stopping() {
                        return Flow::Stop;
                    }
                    if self.poll.skipping(&peer.host) {
                        continue;
                    }
                    match poller.pull_from(peer) {
                        Ok(done) => {
                            took = took || done.stock.is_some();
                            report(&peer.host, &done);
                            self.poll.peer_done(&peer.host, at, done);
                        }
                        Err(e) => {
                            tracing::warn!(host = %peer.host, error = %e, "a peer's bundle poll failed");
                            failure = Some(e);
                        }
                    }
                }
            }
        }
        if !took {
            match poller.stock() {
                Ok(stock) => self.poll.stock_done(stock),
                Err(e) => {
                    tracing::warn!(error = %e, "the bundle poller could not judge its own tree");
                    failure = Some(e);
                }
            }
        }
        let took_ms = started.elapsed().as_millis() as u64;
        let mut status = self.poll.status();
        status.ticks += 1;
        status.last_took_ms = took_ms;
        status.interval_secs = self.interval.as_secs();
        match now_secs() {
            Ok(finished) => {
                status.last_finished_at = Some(finished);
                status.failure = failure;
            }
            Err(e) => status.failure = Some(e.into()),
        }
        tracing::debug!(
            bundles = status.bundles,
            ready = status.ready,
            arrived = status.arrived,
            took_ms,
            "bundle poll tick"
        );
        drop(status);
        for done in answering {
            let _ = done.try_send(());
        }
        Flow::Go
    }
}

/// One line per peer per tick, and only when that peer cost this machine something: the per-file
/// line is a `debug!` inside the validator, because a hostile peer would otherwise evict the
/// console's whole log ring every 30 seconds.
fn report(host: &str, done: &PeerTick) {
    let Some(stock) = &done.stock else {
        return;
    };
    if stock.verdict.rejected.is_empty()
        && stock.verdict.refused_dirs.is_empty()
        && stock.verdict.refused_files == 0
        && stock.verdict.crowded.is_empty()
    {
        return;
    }
    tracing::warn!(
        host,
        quarantined = stock.verdict.rejected.len(),
        refused_dirs = stock.verdict.refused_dirs.len(),
        refused_files = stock.verdict.refused_files,
        crowded = stock.verdict.crowded.len(),
        judged = stock.verdict.judged,
        "a peer's bundle pull broke a cap"
    );
}
