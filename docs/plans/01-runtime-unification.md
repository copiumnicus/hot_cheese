# Stage 1 — one runtime, two renderers, and the cross-cutting sweep

Implements locked decisions 1 and 2 of `00-design-decisions.md`. Nothing here touches git,
bundles, live status or the sign path; stages 2–5 build on the `Runtime` this stage creates.

---

## 0. Corrections to the brief

Verified against the code. Four of the stated facts need adjusting; everything else held.

| Claim | Verdict |
|---|---|
| Console backup-after-mutation is `menu.rs:811-814` | **Wrong.** `811-814` is the `Backup → Push` *screen action* (it guards `backup_remotes.is_empty()` and returns `MenuErr::NoBackupRemote`), not an after-mutation push. The console's two after-mutation copies are `menu.rs:566` (`generate`) and `menu.rs:622` (`add`). Both call `backup::push_all(...)?` with **no** `is_empty` guard and **propagate** the error, so on a machine with an unreachable remote a successful key creation is reported to the operator as a failure. That is the fourth copy, and it is the one that behaves differently from the other three. |
| `Config::load()` 8× in hc-cli | **9× in `lib.rs`** (`:472, :638, :669, :684, :714, :767, :845, :908, :943`), plus `bootstrap.rs:475`, `bootstrap.rs:658`, `bundle.rs:293` = 12 in the crate. But exactly one `dispatch` arm runs per process, so this is textual, not runtime, duplication. See §7g — I decline most of it and say why. |
| `hc-console/src/bundles.rs:890` should use the held `Arc<Config>` | **No.** `sync::peer_add` / `peer_rm` (`hc-bundle/src/sync.rs:361,432`) re-load `config.toml` (`:417,:433`) and re-save it (`:426,:457`); the console's `Arc<Config>` is stale the instant a peer is enrolled. `00-design-decisions.md` explicitly requires preserving the re-read. It stays, with a field doc saying why. |
| QR display loop duplicated `hc-cli/src/bundle.rs:277-286` / `hc-console/src/bundles.rs:463-487` | **Declined.** The only shared code is `hc_bundle::qr_frames` + `hc_daemon::qr_term::render`, both already shared functions. The CLI prints every frame to stdout unpaged; the console clears the screen, writes to stderr, and blocks on a keypress between frames so a frame is never replaced before it is scanned. Extracting a helper here would be a function with two behaviours and one caller each. |

Everything else in the brief was confirmed at the cited lines, including: `execute`
(`hc-daemon/src/lib.rs:505-528`) reaches an approver only through the `Operation::Sign` arm at
`:516`; `ConsoleApprover` drops the sequence number from the biometric reason at
`approval.rs:120-126` while `ServeApprover` keeps it at `approval.rs:73-76`; the store has no
lock and `socket.rs:96-108` holds the only `flock`.

### One fact the brief did not mention, and decision 8 has since settled it

`hc-console/src/lib.rs:40-46` binds an **ephemeral** port on purpose:

> A fixed port is the entire mechanism of the silent re-attach: an
> `ssh -R 7777:localhost:5555` that outlived its session serves every request to a remote the
> next session cannot see, because that tunnel is not in its `TunnelManager`.

An earlier reading of decision 1 put **both** renderers on `config.port()` and made
`exposure::scan_stranded` load-bearing. `00-design-decisions.md` decision 8 (revised) reverses
that:

> the terminal renderer binds an **ephemeral** TCP port, exactly as today, keeping the property
> that a stranded reverse tunnel from an earlier session points at nothing. The headless renderer
> binds `config.port()` for services. This is a `BindPort` enum on `Runtime`, not two runtimes —
> everything else stays unified.

> **Both** renderers bind the adapter unix sockets. Those are 0600 filesystem paths guarded by
> the existing flock (`crates/hc-daemon/src/socket.rs:25`), so they carry no port-unpredictability
> concern, and binding them in the terminal renderer closes a real capability gap: the console
> cannot serve adapters today.

So the unpredictability property is **not** lost, and `scan_stranded` carries no weight it cannot
bear. It is still repaired as a bug in its own right — decision 8's closing paragraph — and §10
risk 1 states exactly what it does and does not cover.

---

## 1. The `Runtime` type

### Crate: `hc-daemon`, new module `crates/hc-daemon/src/runtime.rs`

Justification:

- `hc-console` depends on `hc-daemon`; the reverse edge does not exist and must not be created
  (`crates/hc-console/Cargo.toml`, `crates/hc-daemon/Cargo.toml`).
- Putting `Runtime` in `hc-console` would make `hot_cheese serve` link `crossterm` + `inquire`
  and would break `hc-cli --no-default-features` (`hc-cli/Cargo.toml:7-9` + `:21` make the
  console optional; `hc-cli/src/lib.rs:404-407` fails closed without it). `serve` must keep
  building with no console. Moving `UnlockGate` into `hc-daemon` (§6) also *improves* that
  build: `cmd_console`'s `use hc_console::UnlockGate` (`hc-cli/src/lib.rs:386`) is the only
  `hc_console` type in a signature today, and it stops being one.
- A third crate would need `hc-console` for the terminal renderer — a cycle — unless the
  renderer is injected. The renderer *is* injected (§2), so the extra crate buys nothing.

New deps on `hc-daemon`: `hashbrown` (for the moved `TunnelManager`), `sha2` (for the moved
`body_digest`). Both are already workspace deps.

### Fields

```rust
pub struct Runtime {
    /// Store, port, pinned grant key, remotes and adapter pins, shared with the listeners.
    pub config: Arc<Config>,
    /// The privileged API. Every call on it runs on the thread that owns this Runtime.
    pub api: HotApi,
    /// Which KEK unlocked this session.
    pub gate: UnlockGate,
    /// Takes the human decision and mints the one biometric a sign reuses.
    pub approver: Approver,
    /// Where the listener bound, and the queue of requests waiting for this thread.
    pub serving: Serving,
    /// Reverse ssh tunnels opened from this process; consulted for request provenance.
    pub tunnels: Arc<exposure::TunnelManager>,
    /// Runs the accept loops, the connection tasks and the read-test client.
    pub tokio: tokio::runtime::Runtime,
    /// Unlinked when this drops or when a signal is caught.
    sockets: socket::AdapterSockets,
    /// Held for the whole session; a second runtime or a mutating subcommand refuses.
    /// Taken by the entry point above this, never here — decision 11.
    _store: flock::Claim,
}
```

### The one thing the renderer chooses: `BindPort`

```rust
// hc-daemon/src/runtime.rs

/// Which TCP port the loopback listener asks for. Decision 8: the terminal renderer keeps the
/// kernel-chosen port so a stranded reverse tunnel points at nothing; the headless renderer
/// takes the documented one so services can reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindPort {
    /// Whatever the kernel gives, read back with `local_addr()` after the bind.
    Ephemeral,
    /// `config.port()`, the `serve` daemon's contract with its clients.
    Configured,
}
```

`EPHEMERAL: u16 = 0` (`hc-console/src/lib.rs:46`) is **not** deleted: it moves to `runtime.rs`
as the constant `BindPort::Ephemeral` binds, carrying its doc comment, which is the only written
record of why the property exists.

This is one enum and one `match` in `start`. It is deliberately **not** two runtimes, two
listeners or two constructors: the adapter sockets, the approver, the signal task, the tunnel
manager, the background tasks and the store claim are identical for both renderers.

`Runtime` deliberately has **no** `Drop` impl, so `stop` can move `tokio` out. `AdapterSockets`
and `flock::Claim` carry their own `Drop`.

No config fields are mirrored (CLAUDE.md): the `Config` itself is held.

### Constructor and run methods

```rust
impl Runtime {
    /// `store` is taken by the caller, above the first store mutation, and handed in —
    /// decision 11. Nothing in this process may take it a second time.
    pub fn start(
        config: Config,
        backend: Box<dyn BackendImpl>,
        gate: UnlockGate,
        renderer: Arc<dyn Renderer>,
        bind: BindPort,
        store: flock::Claim,
    ) -> Result<Self, RuntimeErr>;

    /// Answer every queued request on this thread until every sender is gone.
    pub fn approve_forever(&mut self) -> Result<(), RuntimeErr>;

    /// Stop the accept loops, close the tunnels, give the terminal back, and let the tokio
    /// runtime finish what is in flight.
    pub fn stop(self);
}
```

`start` does, in order:

1. The claim is already held: `store` arrives as a parameter (decision 11, §4). `start` takes
   nothing.
2. `let config = Arc::new(config);`
3. `let tokio = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;`
   (exactly `hc-console/src/lib.rs:192-194`; `run_server`'s `#[tokio::main]` is deleted because
   the main OS thread must stay free for the renderer).
4. `let tunnels = Arc::new(TunnelManager::new());`
5. `match gate`:
   - `UnlockGate::Passphrase` → `Serving::Refused`, no manifests loaded, **no adapter sockets
     bound**, no TCP listener. (`00-design-decisions.md`: this behaviour is load-bearing. A
     session that can never answer a request must not accept one either.)
   - `UnlockGate::Biometric` →
     `let adapters = hc_sign::manifest::load_all(&config)?;` (the pin/policy intersection still
     runs before anything binds — `hc-daemon/src/lib.rs:90-93`), `tls_from_home()?`, bind
     `SocketAddr::new(Ipv4Addr::LOCALHOST, port)` where `port` is `0` for
     `BindPort::Ephemeral` and `config.port()` for `BindPort::Configured`;
     `let addr = listener.local_addr()?;` then `scan_stranded(addr.port())?` →
     `RuntimeErr::StrandedTunnels` on a hit; `mpsc::channel(PENDING_OPS)`,
     `watch::channel(false)`, `AdapterSockets::bind(adapters)?`, spawn one `serve_loop` per
     adapter socket plus the TCP one, `Serving::Live { addr, ops, shutdown }`.

   The scan runs **after** the bind and against `local_addr().port()`, not against the wanted
   port, because under `BindPort::Ephemeral` the real port is not known until the kernel picks
   it. That is exactly today's ordering (`hc-console/src/lib.rs:202-211`) and it is preserved
   verbatim for both renderers.

   **Both** gates' adapter-socket behaviour is now the same for both renderers: under
   `Biometric`, both bind every adapter socket; under `Passphrase`, neither binds anything.
   Decision 8: the sockets are 0600 paths under the existing flock
   (`crates/hc-daemon/src/socket.rs:25`), so they carry no port-unpredictability concern, and
   binding them in the terminal renderer closes a capability gap the console has today.
6. Spawn **one** signal task (§6, `ExitSignal`): on SIGINT/SIGTERM/SIGHUP →
   `tunnels.close_all(); renderer.restore(); paths.unlink(); let _ = shutdown.send(true);
   std::process::exit(caught.code());`
7. `Ok(Runtime { .. })` with `approver: Approver::new(gate, renderer)`.

> **AUDIT:** `signal(SignalKind::…)` in step 6 needs a runtime context, which is why
> `install_signal_teardown` (`hc-console/src/lib.rs:152`) holds a `runtime.enter()` guard. That
> guard MUST be dropped before `Runtime::start` returns: `blocking_recv` below calls tokio's
> `block_on`, which **panics** ("Cannot block the current thread from within a runtime") while
> an `EnterGuard` is alive on the thread. `cargo build` cannot catch this; it is a first-request
> panic on real hardware.

`approve_forever` is the headless renderer's whole main-thread program:

```rust
let Runtime { api, approver, serving, tunnels, .. } = self;
let Serving::Live { ops, .. } = serving else { return Err(RuntimeErr::NotServing) };
while let Some(mut op) = ops.blocking_recv() {
    op.ctx.peer = op.ctx.peer.with_tunnels(tunnels.list().len());
    service_one(api, approver, op);
}
Ok(())
```

The destructure is the same borrow-splitting `menu.rs:435-444` already uses. `blocking_recv`
is legal here and only here: the main thread is outside any async context, so the `!Send`
`LaContext` that `service_one` creates never sits across an `await` and never crosses a thread.

`stop(self)`: `if let Serving::Live { shutdown, .. } = &self.serving { let _ =
shutdown.send(true); }`, `self.tunnels.close_all()`, `self.approver.renderer().restore()`, then
`self.tokio.shutdown_timeout(SHUTDOWN_GRACE)`. Sockets and the claim drop with the struct.

### The two entry points

```rust
// hc-daemon/src/lib.rs — replaces run_server
pub fn serve(config: Config, backend: Box<dyn BackendImpl>, store: flock::Claim)
    -> Result<(), RuntimeErr>
{
    let mut rt = Runtime::start(
        config, backend, UnlockGate::Biometric, Arc::new(renderer::Headless::detect()),
        BindPort::Configured, store,
    )?;
    let result = rt.approve_forever();
    rt.stop();
    result
}

// hc-console/src/lib.rs — replaces run_console/session
pub fn run(config: Config, backend: Box<dyn BackendImpl>, gate: UnlockGate, store: flock::Claim)
    -> Result<(), ConsoleErr>;
```

`hc_console::run` passes `BindPort::Ephemeral`; `hc_daemon::serve` passes
`BindPort::Configured`. Both take the claim from their caller in `hc-cli` rather than taking it
themselves, because `cmd_serve` mutates the store *before* either is called (§4).

The terminal renderer installs its tracing subscriber (`status::install_subscriber`) **before**
`Runtime::start`, so the runtime's own `tracing::info!(%addr, …)` lands in the ring instead of
over the menu. The headless renderer leaves `hc-cli`'s stdout subscriber
(`hc-cli/src/lib.rs:338-342`) alone. The subscriber choice is therefore a renderer property,
which is why `LogRing` stays in `hc-console` and is not a `Runtime` field.

`hc-console`'s remaining session state:

```rust
pub struct Console {
    /// The one runtime: listener, adapter sockets, approver, tunnels, store claim.
    pub rt: Runtime,
    /// Recent log lines for the status view.
    pub log: Arc<status::LogRing>,
    /// Signer addresses this session produced, and the local keystore each came from.
    pub signers: HashMap<Address, String>,
}
```

Owning the `Runtime` by value (rather than borrowing it) keeps `Console` lifetime-free, so the
~40 `console: &Console` signatures across `menu.rs`, `status.rs`, `bundles.rs` change only in
their field paths: `console.config` → `console.rt.config`, `console.api` → `console.rt.api`,
`console.serving` → `console.rt.serving`, `console.gate` → `console.rt.gate`,
`console.tunnels` → `console.rt.tunnels`, `console.runtime` → `console.rt.tokio.handle()`.

---

## 2. The renderer abstraction

```rust
// hc-daemon/src/renderer.rs

/// What the operator did at one approval prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Answered yes.
    Approve,
    /// Answered no.
    Deny,
    /// Esc, or a prompt that could not be shown.
    Cancel,
    /// Ctrl-C at the prompt.
    Interrupt,
    /// There is no terminal to ask anyone on.
    NoTerminal,
}

/// The half of the front end that a privileged operation touches: asking the human, and
/// giving the terminal back on every ending.
pub trait Renderer: Send + Sync {
    /// Put one request in front of the operator and take their answer.
    fn ask(&self, seq: u64, ctx: &OpContext, summary: &str) -> Decision;
    /// Undo whatever this renderer did to the terminal. Idempotent.
    fn restore(&self);
}
```

`Send + Sync` is required because the signal task holds an `Arc<dyn Renderer>` and calls
`restore` from a tokio worker. Both impls are stateless apart from a `Copy` field, so this
costs nothing.

`ask` returns a `Decision` rather than a `Result`: the approver, not the renderer, decides
which decisions are typed refusals. That is what makes the `NoApprovalTerminal` guarantee
structural instead of duplicated.

### Why `run` is *not* on this trait

The main-thread program differs far more than `ask` does: the terminal one owns
`&mut Console` (the log ring, the signer map, the menu state machine), the headless one is
six lines. Nothing dispatches over it dynamically — `hc-cli` picks statically at
`lib.rs:325` vs `:368`, and one of the two is behind a cargo feature. A trait method nobody
dispatches over is ceremony, and it would force `Terminal` to carry `&mut` session state that
`restore` (called from another thread) must never touch.

### Implementation A — `hc_daemon::renderer::Headless`

```rust
/// Whether this process has a terminal to ask the operator on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tty { Interactive, Headless }

pub struct Headless {
    /// Whether stdin was a terminal when the runtime started.
    tty: Tty,
}

impl Headless { pub fn detect() -> Self; }
```

`ask`:

- `Tty::Headless` → `tracing::error!(seq, key = %ctx.key, op = ?ctx.op, "no terminal to approve
  on"); Decision::NoTerminal`. **This is how the typed `NoApprovalTerminal` refusal survives.**
  The decision is a distinct variant, not folded into `Deny`/`Cancel`, and the approver (§3) is
  the single place that turns it into `SignErr::NoApprovalTerminal`. `ConsoleApprover`'s
  present behaviour — `InquireError::NotTTY` → `Decision::Cancel` → `ApprovalDenied`
  (`hc-console/src/approval.rs:96-99, 114-116`) — is exactly what decision 2 forbids, and it
  disappears because the mapping no longer lives in a renderer.
- `Tty::Interactive` → one `write_all` of banner + `ctx.reason()` + summary + question to
  `stdout`, then `read_line` from stdin; `y` (case-insensitive, trimmed) → `Approve`, anything
  else → `Deny`; a failed write or read → `Cancel` (logged). This is
  `hc-daemon/src/approval.rs:34-59` with two text changes: the banner names `ctx.op` instead of
  hard-coding `SIGN`, and drops `(policy: ALLOWED)` — after §5 the prompt is reached by
  `Read`, `Generate` and `Address` too, none of which has a policy verdict.
  The tty test is on **stdin**, which stays a terminal under `serve … | tee` — the shape
  `scripts/dryrun.sh:1026` tells the operator to run — so the prompt is still answerable there,
  but it arrives through `tee`. Keep the trailing-space, no-newline question and the explicit
  `flush`; both already exist at `approval.rs:45`.

`restore` → no-op. The headless renderer never changes terminal modes.

### Implementation B — `hc_console::renderer::Terminal`

```rust
pub struct Terminal;
```

`ask` — `hc-console/src/approval.rs:86-109` with the seq bookkeeping lifted out (it is the
approver's now): write `\n=== hot_cheese request #{seq} ===` + summary to **stderr**, the same
stream `inquire` prompts on, then
`inquire::Confirm::new(&format!("#{seq} {} - approve?", ctx.reason())).with_default(false)`.
Mapping: `Ok(true)` → `Approve`, `Ok(false)` → `Deny`, `OperationCanceled` → `Cancel`,
`OperationInterrupted` → `Interrupt`, **`NotTTY` → `NoTerminal`** (new; the terminal renderer
gets the typed refusal too, for one extra match arm), any other → `Cancel` (logged).

`restore` → `let _ = disable_raw_mode(); let _ = execute!(io::stderr(), cursor::Show);` — the
single body that `teardown` (`hc-console/src/lib.rs:107-111`) and `RawScreen::drop`
(`approval.rs:263-268`) both spelled out. `RawScreen::drop` becomes `Terminal.restore();`
(`Terminal` is a unit struct, so this is free), and the signal task reaches the same body
through `Arc<dyn Renderer>`.

### How the seq-in-biometric-reason survives for both

It is not preserved *by* a renderer. The seq counter and the biometric evaluation both move
into the single `Approver` (§3), which builds the reason as
`format!("#{seq} {}\n{head}", ctx.reason())` — `ServeApprover`'s form
(`hc-daemon/src/approval.rs:72-76`), unconditionally. The console renderer therefore *gains*
the sequence number on its Touch ID sheet, which is the behaviour it lacks today
(`hc-console/src/approval.rs:120-126`). The renderers never see the biometric at all.

---

## 3. The single approver

```rust
// hc-daemon/src/approval.rs — the module survives, its contents are replaced

pub struct Approver {
    /// Which KEK opened this session: a passphrase session has no per-request biometric.
    gate: UnlockGate,
    /// Prompts shown this session, so no two prompts are byte-identical.
    shown: AtomicU64,
    /// How the operator left the last prompt.
    decision: parking_lot::Mutex<Decision>,
    /// How this session asks, and how it gives the terminal back.
    renderer: Arc<dyn Renderer>,
}

impl Approver {
    pub fn new(gate: UnlockGate, renderer: Arc<dyn Renderer>) -> Self;
    pub fn decision(&self) -> Decision;
    pub fn renderer(&self) -> &Arc<dyn Renderer>;
    pub fn approve(&self, ctx: &OpContext, summary: &str) -> Result<Option<LaContext>, SignErr>;
}
```

`approve`:

```rust
let seq = self.shown.fetch_add(1, Ordering::Relaxed);
let decision = self.renderer.ask(seq, ctx, summary);
*self.decision.lock() = decision;
match decision {
    Decision::Approve => {}
    Decision::NoTerminal => return Err(SignErr::NoApprovalTerminal),
    Decision::Deny | Decision::Cancel | Decision::Interrupt => return Err(SignErr::ApprovalDenied),
}
if self.gate == UnlockGate::Passphrase || ctx.op != Operation::Sign {
    return Ok(None);
}
let head = summary.lines().take(3).collect::<Vec<_>>().join("\n");
Ok(Some(LaContext::evaluate_biometric(&format!("#{seq} {}\n{head}", ctx.reason()))?))
```

The `gate`/`op` guard is `ConsoleApprover`'s (`approval.rs:117-119`) and it is correct for both
renderers: `ServeApprover` evaluates a biometric unconditionally today, but it is only ever
reached from `sign_intent` (so `op` is always `Sign`) and `serve` refuses
`--unlock passphrase` (`hc-cli/src/lib.rs:905-907`, so `gate` is always `Biometric`) — the
guard is a no-op for `serve` and a correctness requirement for the console. Under
`UnlockGate::Passphrase`, `Ok(None)` is what lets `hc_sign::grant::mint`
(`hc-sign/src/grant.rs:139-152`) take its own single biometric for the enclave grant while the
passphrase unlocker does the DEK unwrap.

### The `!Send` `LaContext` constraint, for both renderers

There is one rule and it is the same for both: **the thread that owns the `Runtime` is the only
thread that ever calls `Approver::approve`, and therefore the only thread that ever constructs
an `LaContext`.** Nothing else is needed, because after this stage no other path exists:

- `Approval::Inline { api, approver }` (`hc-daemon/src/lib.rs:489-498`) and the
  `spawn_blocking(move || execute(…))` at `:841-847` are **deleted**. `serve_io`, `serve_loop`
  and `service_impl` take `mpsc::Sender<PrivilegedOp>` directly; every privileged op goes
  through `delegate` (`:543-559`) to the main thread, for both renderers.
- The headless renderer's main thread sits in `approve_forever`'s `blocking_recv`, so it is
  always draining. The terminal renderer's main thread drains between menu screens
  (`menu::service_pending`) and inside the serve/watch screens, as it does today.
- `HotApi` stays on the main thread inside `Runtime`; the connection tasks hold only
  `Arc<Config>`, a `Sender`, and their `Peer`.

Consequences that must be stated because they are behaviour changes, not refactors:

- **`serve` inherits the bounded queue.** `PENDING_OPS = 4` and the `DelegateErr::Overloaded`
  → `503` path (`lib.rs:549-554, 862-865`) now apply to `serve`, which previously allowed up to
  `MAX_CONNECTIONS = 64` concurrent unlocks serialised only by the `PROMPT` mutex. A fifth
  queued request is refused with `503` instead of waiting. This is the flood bound the console
  was designed with and it is the right one for a human-gated daemon.
- **`/health` still answers while a prompt is up.** The connection task awaits a `oneshot`
  rather than blocking a worker, which is the property `Approval::Inline`'s doc claimed for
  `spawn_blocking`. No regression.
- `PROMPTS_PER_DRAIN = 2` and `refuse_queued` stay **terminal-renderer-only**: the console must
  be able to return to its menu, the headless daemon has nowhere to return to and prompts for
  everything, one at a time, forever.

### What happens to `PROMPT` and `SHOWN`

Both are **deleted**. `PROMPT: Mutex<()>` (`hc-daemon/src/approval.rs:10`) existed to serialise
prompts raised from arbitrary `spawn_blocking` threads; with one approver on one thread the
exclusion is structural and a lock that can never contend is a lie about the design.
`SHOWN: AtomicU64` (`:13`) becomes the `Approver::shown` field, so two runtimes in one process
(there cannot be, but the type stops claiming otherwise) do not share a counter.

The `Approver` **trait** (`hc-daemon/src/lib.rs:482-485`) and the `DrainApprover` trait
(`hc-console/src/approval.rs:59-61`) are deleted; the name `Approver` is reused by the concrete
struct. `Renderer` has no `Send + Sync` requirement forced on it *by the approver* — that bound
comes from the signal task alone.

---

## 4. The store lock

**This is a design decision with real UX consequences. Stated explicitly.**

### What, and where

One `flock(2)` advisory lock on `<home>/.store.lock`, taken with `try_lock` (never `lock`), via
a new shared helper:

```rust
// hc-daemon/src/flock.rs
create_err_with_impls!(
    #[derive(Debug)]
    pub FlockErr,
    StdIo(std::io::Error)
    ;
    Held { path: PathBuf }
);

/// An exclusive claim that lives on the descriptor, so the kernel drops it when this process
/// leaves — SIGKILL included — and a leftover lock file never blocks a later start.
pub struct Claim {
    _file: std::fs::File,
    /// Excludes this process's own background tasks from each other; the flock excludes
    /// other processes. Both are required and neither substitutes.
    mutations: parking_lot::Mutex<()>,
}

impl Claim {
    pub fn take(path: &Path) -> Result<Self, FlockErr>;
    /// Serialise one store mutation against every other in this process.
    pub fn mutate(&self) -> parking_lot::MutexGuard<'_, ()>;
}
```

`mutate()` is the answer to a question stage 2 asks and stage 1 must settle here: `flock(2)` is
per open-file-description, so a background task inside the Runtime cannot "take the store lock"
a second time — it would conflict with the claim its own process already holds. Decision 11:

> Background tasks that need mutual exclusion among themselves layer a `parking_lot::Mutex`
> *under* the flock.

That mutex belongs on `Claim`, not on each subsystem, because there is exactly one store and one
claim. `parking_lot` per CLAUDE.md; a guard from it must never straddle an `.await`, so every
caller holds it inside one blocking closure. Stage 2's commit chokepoint and its fast-forward
merge are the first two callers.

This is `socket::claim` (`hc-daemon/src/socket.rs:96-108`) generalised. `socket::claim` is
deleted and `bind_socket` calls `Claim::take(&dir.join(CLAIM_LOCK))`; `SocketErr::ClaimHeld`
(`socket.rs:35`) is deleted and replaced by `SocketErr::Flock(FlockErr)`. One flock
implementation in the crate, two files it is applied to.

### Why the home dir and not the store dir

The store dir is the wrong place, and the reason is concrete: `backup::pull`
(`hc-daemon/src/backup.rs:229-240`) rsyncs a remote store **over** the local one. rsync
replaces files by writing a temp and renaming, so a `.store.lock` inside the store would be
replaced by a new inode mid-session; our fd would still hold the old inode's lock while a
second process opening the path would get the new inode and succeed. The mutual exclusion
would silently evaporate exactly when the store is being overwritten. The home dir is never
replicated (`backup.rs:4-6`: "We replicate ONLY the store directory"), so it does not have this
problem, and it needs no `.gitignore` entry in stage 2.

**Accepted limitation, stated because it is real:** two installs with different
`HOT_CHEESE_HOME` pointed at the *same* `store` path are not excluded from each other. The lock
guards one install, not one directory. Nothing in the repo creates that configuration and
`config.toml` makes it possible; if it ever matters the answer is a second claim inside the
store taken *around* mutations only, not for the session.

### Who takes it, and for how long

Decision 11 settles the shape: **the claim is taken once, at the top of the entry point, and
shared.** `Runtime::start` *receives* it.

- **`hc_daemon::serve` and `hc_console::run` do not take it either** — their callers in `hc-cli`
  do, and hand it in. For `serve` that matters concretely: `cmd_serve` runs a store-mutating
  `backup::pull` at `hc-cli/src/lib.rs:930-936` (an rsync **over** the store) *before*
  `open_backend` (`:938`) and therefore before any runtime exists. Under decision 11 the claim
  is taken at the head of `cmd_serve`, **above** that auto-pull, and travels into
  `hc_daemon::serve`. The auto-pull is then covered, which closes the "no lock around store
  mutation versus push/pull" hazard `00-design-decisions.md` names. Stage 2 deletes that block
  outright, but the ordering rule is what makes stage 1 correct on its own.
- **Mutating CLI subcommands** take it for the duration of the subcommand:
  `add` (`hc-cli/src/lib.rs:632`), `generate` (`:663`), `seal` (`:839`), `migrate` (`:985`),
  `enroll se|passphrase` (`:587`), `backup pull` (`:949`), `backup adopt` (`:970`),
  `backup push` (`:945`), `bootstrap-from` (`:375`), and **`init --force`** (below).
  `backup push` is in the list because stage 2 turns it into a commit-and-push.
  The two writers `00-design-decisions.md` names as bypassing `atomic_write` —
  `hc-cli/src/migrate.rs:184-186` and `hc-cli/src/bootstrap.rs:628-633` (inside
  `bootstrap::persist`, `:609`) — are reached only through `migrate` and `bootstrap-from`, so
  both are covered.
- **`init --force` takes it; plain `init` does not.** `hc-cli/src/lib.rs:501` gates the entire
  prior-install check on `!force`, so `hot_cheese init --force` rewrites `config.toml`, the
  store and a fresh DEK with a live runtime holding the lock. Decision 11: "`init --force`
  takes it too: it is the most destructive mutator and was exempt." Plain `init` stays exempt
  because it creates the home dir the lock file lives in and already refuses when any prior
  install is visible (`lib.rs:499-523`) — there is nothing for it to race with.
- **Read-only subcommands do not take it**: `address`, `list`, `adapters`, `sign`, every
  `bundle` verb (bundles live under `bundles_dir()`, `hc-core/src/config.rs:249`, not the
  store), `backup list`, `se-selftest`, `bootstrap-serve`. An operator who wants an
  address while the console is open gets it.

  Stage 2 changes two entries in this list and says so in its own §7: `backup adopt` leaves it
  (deleted), `backup fetch` joins it (it can `merge --ff-only` into the worktree), and
  `backup status` stays out (no network, no write).

- **Nothing in-process re-takes it.** `backup::push_all` / the mutation chokepoint must never
  call `Claim::take`: the console calls them while the runtime holds the lock, and `flock` locks
  are per open-file-description (`crates/hc-daemon/src/socket.rs:103` is the existing
  precedent), so a second `open` in the same process conflicts with itself. A background task
  that needs exclusion against another background task calls `Claim::mutate()` instead. That is
  the standing rule and the one relaxation, both stated here rather than discovered in stage 2.

### What a blocked caller sees

`Err(FlockErr::Held { path })`, nested into `CliErr::Flock` / `RuntimeErr::Flock` by `#[from]`,
returned **immediately** — before any prompt, any unlock, any Touch ID and any write. Nothing
queues and nothing waits, which is deliberate: a CLI that blocked would sit invisibly behind a
console the operator is looking at, and the operator would conclude the CLI had hung.

The two runtimes case is what decision 1 requires: `hot_cheese` and `hot_cheese serve` can no
longer coexist, and the second one refuses with a typed error naming the lock file, instead of
an untyped `EADDRINUSE` from the TCP bind or a half-bound set of adapter sockets.

---

## 5. `Read | Generate | Address` reaching the approver

The policy that wins is the console's `service_one` (`hc-console/src/approval.rs:172-200`):
**a request that arrived from a peer prompts, whatever the operation.** It moves into
`execute`, which is the one place every peer request passes through, and the console's
compensating branch is deleted.

```rust
// hc-daemon/src/lib.rs, replacing :505-528
pub fn execute(api: &HotApi, approver: &Approver, ctx: &OpContext, body: &[u8])
    -> Result<Vec<u8>, OpErr>
{
    match ctx.op {
        Operation::Read => {
            let permit = api.export_permit(ctx)?;
            approver.approve(ctx, &format!("request body sha256 {}", body_digest(body)))?;
            Ok(api.read(ctx, body, permit)?)
        }
        Operation::Sign => Ok(api.sign_intent(ctx, body, approver)?),
        Operation::EvmGenerate => {
            approver.approve(ctx, "")?;
            api.generate(ctx, KeyUse::SignOnly)?;
            Ok(b"success".to_vec())
        }
        Operation::SolanaGenerate => { /* as EvmGenerate, generate_solana */ }
        Operation::EvmAddress => { approver.approve(ctx, "")?; Ok(api.address(ctx)?.into_bytes()) }
        Operation::SolanaAddress => { /* as EvmAddress, address_solana */ }
    }
}
```

`api.export_permit` stays **before** `approver.approve`. That ordering is the invariant the
existing test `read_refuses_a_sign_only_key_before_any_unlock` (`lib.rs:1019-1058`) and
`scripts/dryrun.sh:1055-1068` both depend on: a `sign_only` key is refused from its cleartext
header, costing zero prompts and zero biometrics.

`body_digest` (`hc-console/src/approval.rs:148-151`) and `DIGEST_CHARS` (`:42`) move to
`hc-daemon` with it; hc-daemon gains the `sha2` dependency it currently has only as a
dev-dependency. The digest is kept, not dropped in favour of the seq number, because it names
*which* ephemeral client public key is about to be handed a key — two concurrent `/read`s for
one keystore differ in nothing else.

### Every call site that changes

| File:line | Today | After |
|---|---|---|
| `hc-daemon/src/lib.rs:505-528` | `execute` prompts only via the `Sign` arm | prompts in all six arms, `Read` after the permit |
| `hc-daemon/src/lib.rs:839-850` | `match approval { Inline => spawn_blocking(execute), Console => delegate }` | `delegate(&tx, ctx, body).await` — one path |
| `hc-console/src/approval.rs:174-187` | `match ctx.op { Sign => execute, _ => approve-then-execute }` | `hc_daemon::execute(api, approver, &ctx, &body)` |
| `hc-cli/src/lib.rs:718-722` | `api.sign_intent(…, &hc_daemon::approval::ServeApprover)` | `api.sign_intent(…, &Approver::new(gate, Arc::new(Headless::detect())))`, with `gate` resolved from the keyring exactly as `cmd_console` does at `:394-397` |

### What deliberately does **not** change, and why

`hc-cli`'s `cmd_generate` (`:673,675`) and `cmd_address` (`:688,689`), and the console's
`menu::generate` (`:562-565`), `menu::address` (`:584-587`) and `menu::add` (`:621`) keep
calling `HotApi` directly with **no** approver. They are not peer requests; they are the
operator, at the keyboard, executing a command they just typed or a menu item they just
selected, and the Touch ID sheet raised by `unlock_dek` already names the key and the
operation. Prompting `approve? [y/N]` for a command the operator issued one keystroke ago is a
confirmation of a confirmation.

This is the line the console already draws — `service_one` approves what came over the mpsc
channel, never what the menu called directly — and it is the line
`00-design-decisions.md` **decision 10** settles: "Decision 2 governs requests arriving over
the network surface — loopback TLS and adapter sockets — which is where the console draws the
line today. A human running a CLI subcommand at their own terminal is not prompted twice; the
Secure Enclave gate already authenticated them." So this is locked, not open. The structural
guarantee is that the only constructors of a non-`Peer::Cli` `OpContext` are the two listeners
(`hc-daemon/src/lib.rs:838`, from `parse_route` + the listener's own `Peer`), and every one of
them reaches `execute`, which now prompts in all six arms.

---

## 6. Deletion list

No shims, no re-exports. Every caller listed is fixed in the same step.

### `hc-daemon/src/lib.rs`

| Lines | Item | Fate |
|---|---|---|
| 81-87 | `enum ExitSignal` | **Deleted.** `hc-console`'s copy (which also has `code()`) moves to `runtime.rs`. Callers: `:114-122`. |
| 89-152 | `run_server` (incl. `#[tokio::main]`) | **Deleted** → `Runtime::start` + `serve`. Caller: `hc-cli/src/lib.rs:32, :939`. |
| 483-485 | `trait Approver` | **Deleted.** Name reused by the struct in `approval.rs`. Callers: `:494, :507, :753`, `hc-console/src/approval.rs:11,59,112,415`, `hc-daemon/src/lib.rs:999`. |
| 487-498 | `enum Approval` | **Deleted.** Callers: `:106, :839-850`, `hc-console/src/lib.rs:27, :216`. |
| 536 | `DelegateErr::Join(tokio::task::JoinError)` | **Deleted** — dead once `spawn_blocking` goes. |
| 790-802 | `backup_after_mutation` | **Deleted** → `backup::after_mutation` (§7a). Caller: `:855`. |
| 998-1003 | test `struct DenyAll` + `impl Approver` | **Rewritten** as a `Renderer` returning `Decision::Deny`. |

`serve_loop`, `Listener`, `serve_io`, `service_impl`, `delegate`, `PrivilegedOp`,
`PENDING_OPS`, `OpContext`, `Peer`, `Surface`, `parse_route`, `check_body`,
`read_body_capped`, `HotApi` all **survive**; `serve_io`/`serve_loop`/`service_impl` change one
parameter from `Approval` to `mpsc::Sender<PrivilegedOp>`.

> **RECONCILED with stage 4.** `04-live-status.md` was written against `enum Approval` and
> evolved it into `Approval::Console { tx, pending }`. This stage deletes the enum outright, so
> that variant does not exist by the time stage 4 runs. Stage 4 §1.6 and its step 1 are now
> written against the post-stage-1 world instead: the pending gauge is a second parameter
> beside the `mpsc::Sender<PrivilegedOp>` on `serve_io`/`serve_loop`/`service_impl` and a
> second argument to `delegate`. Nothing in stage 1 changes as a result — the parameter stage 4
> adds is additive to the signatures this section already rewrites.

### `hc-daemon/src/approval.rs`

| Lines | Item | Fate |
|---|---|---|
| 10 | `static PROMPT: Mutex<()>` | **Deleted** (§3). |
| 13 | `static SHOWN: AtomicU64` | **Deleted** → `Approver::shown`. |
| 16-29 | `enum Console` + `Console::detect` | **Renamed and moved** to `renderer::Tty` + `Headless::detect`. `Console` is a bad name for "is there a tty" once `Console` means the terminal session. |
| 34-59 | `fn ask` | **Replaced** by `Headless::ask` (returns `Decision`, not `Result<(), SignErr>`). |
| 65-78 | `struct ServeApprover` + `impl Approver` | **Deleted.** Callers: `hc-daemon/src/lib.rs:108`, `hc-cli/src/lib.rs:721`. |
| 87-98 | test `headless_refuses_before_the_biometric` | **Kept**, retargeted at `Headless { tty: Tty::Headless }.ask(…) == Decision::NoTerminal` plus the approver mapping (§8). |

### `hc-daemon/src/socket.rs`

| Lines | Item | Fate |
|---|---|---|
| 35 | `SocketErr::ClaimHeld { path }` | **Deleted** → `SocketErr::Flock(FlockErr)`. |
| 96-108 | `fn claim` | **Deleted** → `flock::Claim::take`. Caller: `:119`. |
| 133-172 | `AdapterSockets.paths: Vec<PathBuf>` + `Drop` | **Changed**: `paths: Arc<SocketPaths>`, `SocketPaths::unlink(&self)` idempotent (ignores `NotFound`), called by both `Drop` and the signal task. |

### `hc-console/src/lib.rs`

| Lines | Item | Fate |
|---|---|---|
| 38 | `SHUTDOWN_GRACE` | **Moved** to `hc-daemon/src/runtime.rs` (`Runtime::stop`). |
| 40-46 | `EPHEMERAL` + its doc | **Moved** to `hc-daemon/src/runtime.rs` beside `BindPort` (§1). Decision 8 keeps the ephemeral bind for the terminal renderer, so the constant and the reasoning in its doc both survive; only their home changes. |
| 60-67 | `enum UnlockGate` | **Moved** to `hc-daemon`. Callers: `status.rs:3,155,156`, `approval.rs:4,67,75,117`, `menu.rs:7,462,465,963,964`, `hc-cli/src/lib.rs:386,395,396`. |
| 69-81 | `enum Serving` | **Moved** to `hc-daemon`. Callers: `menu.rs:388,422,441,450,472,473,655,656,921,944`, `status.rs:151,152`. |
| 83-103 | `struct Console` | **Replaced** by the three-field `Console` of §1. |
| 107-111 | `fn teardown` | **Deleted** → `Terminal::restore`. Callers: `:120` (`ExitGuard::drop`, below), `:163` (the signal task → `Runtime::start`, §1 step 6), `:242` (**the panic hook**, `:239-244`). `teardown` closes the tunnels *and* restores the terminal; `Renderer::restore` only restores the terminal, so each of the three callers must keep its own `tunnels.close_all()`. The panic hook is the one the rest of this plan never names again: its body becomes `panicking.close_all(); Terminal.restore(); previous_hook(info);` and it stays in `hc_console::run`. |
| 124-140 | `enum ExitSignal` + `code()` | **Moved** to `hc-daemon/src/runtime.rs` (the surviving copy). |
| 148-167 | `install_signal_teardown` | **Deleted** → the signal task inside `Runtime::start`. |
| 173-183 | `run_console` | **Replaced** by `hc_console::run`. Caller: `hc-cli/src/lib.rs:399`. |
| 185-268 | `fn session` | **Deleted**, split between `Runtime::start` and `hc_console::run`. |
| 113-122 | `struct ExitGuard` | **Kept.** The signal task holds an `Arc<TunnelManager>` clone forever, so `Drop for TunnelManager` never fires; `ExitGuard` is what closes the tunnels on an error return or a panic unwind before `stop` is reached. Its body becomes `self.tunnels.close_all(); Terminal.restore();`. |

### `hc-console/src/exposure.rs`

**Whole file moves to `hc-daemon/src/exposure.rs`.** The runtime needs `TunnelManager::list`
for `Peer::with_tunnels` and `scan_stranded` for the startup check both renderers now run, and
neither may live above `hc-daemon`. `-ww` and the widened argv match (§10 risk 1) land in this
same step. The file uses only `hashbrown`, `parking_lot`, `std::process`, `tracing` and
`err_mac` — no console dependency, and `hc-daemon` already has all but `hashbrown`.
`hc-console` imports `hc_daemon::exposure::{TunnelId,
TunnelSpec, TunnelErr, StrandedTunnel, validate_target}` for the Exposure screen, and
`ConsoleErr::Tunnel` / `MenuErr::Tunnel` re-point at `hc_daemon::exposure::TunnelErr`.
`ConsoleErr::StrandedTunnels { port, found }` (`lib.rs:57`) **moves to `RuntimeErr`**, which is
how `serve` gains the stranded-tunnel check it has never had.

### `hc-console/src/approval.rs`

| Lines | Item | Fate |
|---|---|---|
| 35 | `const TICK` | **Deleted** → one `TICK` in `hc-console/src/lib.rs` (§7c). |
| 45-55 | `enum Decision` | **Moved** to `hc-daemon`, gaining `NoTerminal`. |
| 59-61 | `trait DrainApprover` | **Deleted.** Callers: `:130, :172, :231, :310, :420`. |
| 65-134 | `struct ConsoleApprover` + both impls | **Deleted** → `hc_daemon::Approver` + `Terminal`. Callers: `menu.rs:4,371,433,486,637,653,746,914`, `bundles.rs:8,285,341,371,691`. |
| 137-144 | `fn show` | **Deleted**; folded into `Terminal::ask`. |
| 148-151 | `fn body_digest`, 42 `DIGEST_CHARS` | **Moved** to `hc-daemon` (§5). `hc-console` keeps its `sha2` dependency regardless: `readtest.rs:16,115` uses it. |
| 154-200 | `enum Outcome` (+ its `Display`, `:161-169`) + `fn service_one` | **Moved** to `hc-daemon/src/runtime.rs`; both renderers' loops call it, so `Outcome` becomes `pub` (it is private today). The `_ =>` branch at `:176-186` is **deleted** (§5). |
| 247-254, 335-345 | the twice-written 4-arm `match approver.decision()` | **Replaced** by one `fn after(Decision) -> After` (§7e). |
| 263-268 | `impl Drop for RawScreen` body | **Replaced** by `Terminal.restore()`. |
| 290 | `serving https://{addr}` in `draw` | **Replaced** by `Display for Serving` (§7f). |

`ApprovalErr`, `PROMPTS_PER_DRAIN`, `refuse_queued`, `Drained`, `drain`, `RawScreen`, `Tally`,
`draw`, `serve_and_approve` and both drain tests **survive** in `hc-console`: they are the
terminal renderer's flood policy and its serve screen, not runtime concerns.

### `hc-cli/src/lib.rs`

| Lines | Item | Fate |
|---|---|---|
| 32 | `use hc_daemon::{… run_server …}` | → `hc_daemon::serve` |
| 99 | `CliErr::Serve(hc_daemon::ServeErr)` | → `CliErr::Runtime(hc_daemon::RuntimeErr)` + `CliErr::Flock(hc_daemon::flock::FlockErr)` |
| 483-487 | `fn open_backend` | **Replaced** by `backend_for(config, unlock) -> Result<(MacBackend, UnlockGate), CliErr>` (§7g). Callers: `:398, :652, :670, :685, :716, :877, :938`. |
| 721 | `&hc_daemon::approval::ServeApprover` | → the unified `Approver` |
| 900-940 | `cmd_serve` tail | `run_server(Box::new(backend), config)` → `hc_daemon::serve(config, Box::new(backend), store)`, with `store` taken at the head of `cmd_serve`, above the auto-pull at `:930-936` (§4) |
| 1024-1031 | `fn cli_context` | **Deleted** → `OpContext::local` (§7h). Callers: `:673, :675, :688, :689, :719`. |
| 1033-1041 | `fn best_effort_backup_push` | **Deleted** → `backup::after_mutation` (§7a). Callers: `:659, :679, :896, :1020`. |

---

## 7. The cross-cutting sweep

### 7a. One backup chokepoint

Decision 13 fixes the signature, and it is **not** the infallible one an earlier draft of this
section specified:

> The mutation chokepoint commits fallibly and pushes best-effort. A failed commit is a real
> error the caller must see; a failed push is a warning the status band reports. These are two
> halves with two different failure dispositions, not one call.

```rust
// hc-daemon/src/backup.rs, next to push_all
/// Record the mutation, then replicate it. The record is the caller's problem when it fails;
/// the replication is not, because a store that was written must not be reported as a failure
/// because a remote was unreachable.
pub fn after_mutation(cfg: &Config) -> Result<(), BackupErr> {
    if let Err(e) = push_all(cfg) {
        tracing::warn!(error = %e, "backup push after a store mutation failed");
    }
    Ok(())
}
```

In stage 1 the commit half does not exist yet, so the body is the best-effort push alone and the
`Ok(())` is unconditional. **The `Result` is in the signature from the start on purpose**: stage
2 fills the commit half in without re-touching seven call sites, and every caller is already
written to propagate with `?`. Stage 2 renames nothing and moves nothing; it replaces the body.

`push_all` keeps its own `is_empty` early return (`backup.rs:250-252`), so the guard exists
**once**; the copies at `hc-daemon/src/lib.rs:793-795` and `hc-cli/src/lib.rs:1035-1037` go.

Call sites: `hc-cli` `cmd_add:659`, `cmd_generate:679`, `cmd_seal:896`, `cmd_migrate:1020`;
`hc-console` `menu::generate:566`, `menu::add:622`; `hc-daemon` `service_impl:854-856`, which
keeps its `tokio::task::spawn_blocking(move || backup::after_mutation(&cfg))` because that one
call site is on an async worker — the returned `Result` is logged there rather than propagated,
since there is no caller to propagate to inside a detached task and the HTTP response has already
been written. `menu.rs:811-814` (the explicit `Backup → Push` action) is **not** a caller — it
must keep failing loudly, because the operator asked for a push.

Both of those are the two entries stage 2's §7 lists under "Not deleted", and the two plans
agree: `hc-daemon/src/lib.rs:854-856` **is** this chokepoint's call site and stage 2 replaces the
callee's body, not the site; `hc-console/src/menu.rs:814` becomes the git push and keeps failing
loudly.

**Behaviour change, stated:** the console's `generate` and `add` stop failing when a remote is
unreachable. A key that was successfully written and sealed is no longer reported as an error
because rsync could not reach a host. This is the fix, not a side effect. It applies to the
**push** half only — once stage 2 adds the commit half, a mutation that could not be committed
still fails the caller (decision 13).

Stage 2 replaces this function's body with commit-and-push and touches nothing else.

### 7b. `teardown` / `RawScreen::drop` — done by `Renderer::restore` (§2).

### 7c. One `TICK`

`hc-console/src/lib.rs` grows `pub(crate) const TICK: Duration = Duration::from_millis(120);`
with one field-doc sentence. Deletes `approval.rs:35`, `pick.rs:40`, `bundles.rs:48`.

### 7d. The raw-mode event loops

`approval.rs:315-369` (serve screen) and `bundles.rs:702-760` (watch screen) share the
keyboard tail, not the work. Extract only the shared, testable part into `hc-console/src/lib.rs`:

```rust
/// What a keypress on a live screen means.
pub(crate) enum Key { Quit, Leave, Redraw, Ignore }

/// Wait one TICK for the keyboard and classify what arrived.
pub(crate) fn tick() -> Result<Key, std::io::Error>;
```

`Ctrl-C` → `Quit`, `q`/`Esc` → `Leave`, `Event::Resize` → `Redraw`, anything else and a poll
timeout → `Ignore`. Both loops keep their own bodies (drain-one vs sync-then-drain) because
those genuinely differ. `pick.rs` is **not** a caller: its keys include arrows, PageUp/Down and
the filter cursor, which is a different classification.

### 7e. One `Decision` → flow-control mapping

```rust
// hc-console/src/approval.rs
/// What the drain loops do after one prompt.
pub(crate) enum After { Continue, Stop, Leave }

pub(crate) fn after(decision: Decision) -> After;
```

`Approve | Deny` → `Continue`; `Cancel | NoTerminal` → `Stop`; `Interrupt` → `Leave`. Now that
`Decision` has five variants, writing the mapping twice is how `NoTerminal` ends up classified
one way in `drain` and another in `serve_and_approve`. A free function in `hc-console` rather
than a method, because `Decision` is a foreign type and the headless loop does not use this
mapping at all (it has no menu to stop into, and its `read_line` never sees Ctrl-C — that is a
real SIGINT the signal task handles).

### 7f. One "serving" format

`impl fmt::Display for Serving` in `hc-daemon`: `Live { addr, .. }` → `https://{addr}`,
`Refused` → `refused`. Used by `menu.rs:472` and `approval.rs:290`. `status.rs:150-153`
keeps its own `match` because its refusal line is a full sentence
("refused, this session may not release keys off-process"), not the terse label. Three
formats become one `Display` plus one deliberate site-specific sentence.

> **RECONCILED with stage 4.** `04-live-status.md`'s deletion list asserted that stage 1
> collapses *three* sites (`status.rs:151`, `menu.rs:472`, `approval.rs:291`) into one. It
> collapses **two**. `status.rs:150-153` keeps its own `match` because its refusal arm at
> `:152` is a full sentence, not the terse label. Stage 4's deletion list has been corrected to
> two, so it no longer deletes the sentence this section preserves on purpose.

### 7g. `OpContext::local`, `backend_for`, and what I decline

```rust
impl OpContext {
    /// Name an operation the operator invoked here. Nothing outside a listener may choose
    /// its own provenance.
    pub fn local(key: String, op: Operation) -> Self {
        Self { key, op, peer: Peer::Cli }
    }
}
```

Call sites: `hc-cli/src/lib.rs:673,675,688,689,719` (via the deleted `cli_context`),
`menu.rs:554-561`, `menu.rs:576-583`, `menu.rs:641-645`, `bundles.rs:378-382`.
`hc-daemon/src/lib.rs:838` keeps building the struct literally — its `peer` comes from the
listener and that is the whole point of the type.

```rust
// hc-cli, replacing open_backend at :483-487
fn backend_for(config: &Config, unlock: Option<UnlockMethod>)
    -> Result<(MacBackend, UnlockGate), CliErr>;
```

Loads the keyring once, resolves the gate (`resolve_unlock_method`, `:440-453`), builds the
unlocker and opens the backend. Seven call sites, and it removes the duplicated gate
resolution that `cmd_console` (`:394-397`) does by hand and `sign_intent_locally` (`:710-724`)
does not do at all. `MacBackend::new` re-loads the keyring internally
(`hc-core/src/mac/mod.rs:51`); leaving that is deliberate — changing `MacBackend`'s constructor
is not this stage's business.

**Declined, with reasons:**

- The other `Config::load()` sites. Exactly one `dispatch` arm runs per process, so the nine
  textual sites are at most one runtime load. Threading a single `Arc<Config>` through
  `dispatch` needs `cmd_init` (which runs when there is no config) and `Enroll::Grant` (which
  mutates and re-saves it) special-cased, and would force `cmd_serve`'s auto-pull
  (`:930-936`, which must precede `MacBackend::new` because the keyring may not exist yet) into
  an awkward shape. The cost exceeds the gain.
- `hc-console/src/bundles.rs:890`. Must keep re-loading — see §0.
- `hc-cli/src/bundle.rs:293`. Loads once, in `watch`, for `bundle_watch_secs()` alone.
- The QR loops. See §0.

---

## 8. Ordered steps

Each step is self-contained: the tree builds in release and the suite passes at every step
boundary. Verification for every step includes `cargo build --release` and
`cargo test --release`; the extra checks below are what makes each step *meaningful*.

**1. Move the session vocabulary into `hc-daemon`.**
This step **creates `crates/hc-daemon/src/runtime.rs`** holding nothing but the session
vocabulary; step 7 fills it in. Without that, §6's "moved to `hc-daemon/src/runtime.rs`" names
a file that does not exist until step 7 and this step cannot compile on its own.
`UnlockGate`, `Serving`, `ExitSignal` (+ `code()`) move from `hc-console/src/lib.rs:60-140`
into it. Delete `hc-daemon/src/lib.rs:81-87` and re-point `run_server`'s use at `:114-122`.
Fix the imports listed in §6. `Display for Serving` is **not** added here — it is step 10, with
the rest of the sweep. No behaviour change.
*Verify:* `grep -rn "enum ExitSignal" crates | wc -l` is `1`; `grep -rn "enum UnlockGate\|enum Serving" crates/hc-console` is empty.

**2. Move `exposure.rs` to `hc-daemon`.** Add `hashbrown` to `hc-daemon/Cargo.toml`. Re-point
`ConsoleErr::Tunnel`, `MenuErr::Tunnel`, and every `use super::exposure::…` in
`menu.rs`/`lib.rs`.
*Verify:* the four `exposure` tests still run, now under `hc-daemon`;
`cargo build --release -p hc-cli --no-default-features` succeeds.

**3. One flock helper.** Add `hc-daemon/src/flock.rs` (`Claim::take`, `Claim::mutate`); rewrite
`socket::claim`; delete `SocketErr::ClaimHeld`.
*Verify:* `socket::tests::a_second_bind_refuses_a_live_socket_and_leaves_it_reachable` passes
unchanged.

**4. `Decision`, `Renderer`, and the single `Approver`.**
Add `hc-daemon/src/renderer.rs` (`Decision`, `Renderer`, `Tty`, `Headless`); replace
`hc-daemon/src/approval.rs` with the concrete `Approver`; delete the `Approver` trait,
`ServeApprover`, `PROMPT`, `SHOWN`. Add `hc-console/src/renderer.rs` (`Terminal`); delete
`ConsoleApprover` and `DrainApprover`; `RawScreen::drop` → `Terminal.restore()`; delete
`teardown` and re-point its three callers. `execute` and `HotApi::sign_intent` take
`&Approver`. Fix `hc-cli:721`: `sign_intent_locally` resolves the gate inline here, the way
`cmd_console` does at `:394-397` — `backend_for` (§7g) does not exist until step 10, and this
step must compile without it. At this step `Approval::Inline` still exists, holding
`Arc<Approver>` (which is `Send + Sync`, so `spawn_blocking` still type-checks).
*Verify:* the two console drain tests pass with a stub `Renderer`; the hc-daemon headless test
now asserts `Decision::NoTerminal` **and** that `Approver::approve` maps it to
`SignErr::NoApprovalTerminal` and not `ApprovalDenied`.

**5. Every privileged operation reaches the approver.**
Move `body_digest`/`DIGEST_CHARS` to `hc-daemon`: promote `sha2` from its `[dev-dependencies]`
(`hc-daemon/Cargo.toml:38`) to `[dependencies]` and delete the dev-dependency line, which is
then redundant. Add `approve` to all six `execute` arms with `export_permit` first; delete
`service_one`'s `_ =>` branch so it is one unconditional `hc_daemon::execute` call.
*Verify:* `read_refuses_a_sign_only_key_before_any_unlock` still passes, extended to assert the
renderer was never asked; the new §9 policy test passes.

**6. `service_one` + `Outcome` move to `hc-daemon`.** `drain` and `serve_and_approve` call
`hc_daemon::service_one`.
*Verify:* both drain tests unchanged in meaning.

**7. The `Runtime`.**
Add `hc-daemon/src/runtime.rs` (`Runtime`, `BindPort`, `EPHEMERAL`, `start`, `approve_forever`,
`stop`, `RuntimeErr`, the signal task, `SHUTDOWN_GRACE`). `AdapterSockets` gains
`Arc<SocketPaths>`. Delete `Approval`, `DelegateErr::Join`, the `Approval::Inline` arm of
`service_impl`, and `run_server`; `serve_io`/`serve_loop`/`service_impl` take
`mpsc::Sender<PrivilegedOp>`. Add `hc_daemon::serve`. Rewrite `hc-console/src/lib.rs` around the
three-field `Console` and `hc_console::run`; delete `session`, `run_console`,
`install_signal_teardown`; move `EPHEMERAL` out. Re-point `cmd_console` and `cmd_serve`.
`Runtime::start` takes `bind: BindPort` and `store: flock::Claim` **in this step** — both
signature changes belong here, not in step 8.
*Verify:* `hot_cheese serve` on a software-enclave demo home
(`HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE=1`, throwaway `HOT_CHEESE_HOME`) binds `config.port()`,
answers `/health`, and prompts on `/read` of a shareable key; the console on the same home binds
a **kernel-chosen** port (`lsof -p <pid>` shows a high port, not `config.port()`) and binds every
adapter socket (`ls <home>/adapters` shows one `.sock` per manifest, which it does not today);
a second `hot_cheese` in another terminal refuses with `FlockErr::Held`; SIGTERM to the daemon
unlinks every adapter socket and exits `143`.

**8. Store lock on the mutating subcommands.** `Claim::take` at the head of the ten subcommands
in §4 — the nine mutators plus `init --force` — and at the head of `cmd_serve` **above** the
auto-pull at `hc-cli/src/lib.rs:930-936`, and at the head of `cmd_console`; both hand the claim
into the entry point. Add `CliErr::Flock`.
*Verify:* with a runtime live, `hot_cheese generate evm X` fails immediately with the lock
error and no Touch ID sheet; `hot_cheese list` and `hot_cheese address evm Y` still work.

**9. Backup chokepoint** (§7a). *Verify:* with a bogus `backup_remotes` entry, console
`Keys → Generate` reports the key as generated and logs a push warning instead of failing.

**10. `TICK`, `Key`/`tick`, `after`, `Display for Serving`, `OpContext::local`,
`backend_for`** (§7c–§7g). Six mechanical edits; keep them in one step only if each compiles
between edits.
*Verify:* `grep -rn "from_millis(120)" crates/hc-console | wc -l` is `1`;
`grep -rn "peer: Peer::Cli" crates | wc -l` is `1` (inside `OpContext::local`).

**11. Scripts and docs.** `scripts/dryrun.sh` phase 6 (`:1017-1105`) must tell the operator
that the live `/read` of the shareable key now raises an approval prompt in terminal B that
must be answered `y` before the Touch ID sheet appears; the sign-only refusal at `:1055-1068`
stays prompt-free and its `assert_taps … "0"` (`:1068`) must still hold. `README.md:124`,
`:371-380`, `:499-501`, `:506-518` and the `serve` row of the command table (`:411`) gain the
same fact. **`README.md:682-684` is the one this plan first missed and two of its three clauses
are now wrong** — "Adapter sockets belong to `hot_cheese serve`" and "opens no adapter sockets,
so a console session and a serving daemon never contend for the same path". Under decision 8 the
middle clause, "The interactive console binds a kernel-chosen loopback port", stays **true and
is now the documented design** rather than an implementation detail. After this stage the
console binds every adapter socket and the two **cannot** coexist: rewrite the paragraph around
the store claim and keep the ephemeral-port sentence, saying why it differs from `serve`'s.
*Verify:* a full `scripts/dryrun.sh` run on real hardware (this is the acceptance gate for the
stage; it is the only place the biometric counting is checked).

**12. Clippy and the final gate.**
*Verify:* `cargo clippy --release --all-targets -- -D warnings` clean with **no**
`#[allow(clippy::…)]` added anywhere; `cargo build --release -p hc-cli --no-default-features`;
`cargo test --release` green.

---

## 9. Tests worth writing

Four new tests. Everything else this stage adds is a `match` or a counter, and CLAUDE.md
forbids testing those.

**1. Every privileged operation reaches the approver, and nothing unlocks when it refuses.**
`hc-daemon/src/lib.rs` tests. A `Renderer` that records `(seq, ctx.op)` and returns
`Decision::Deny`, over the existing `NeverUnlocks` backend (`lib.rs:1007-1017`), driven through
`execute` once per `Operation` variant. Assert every variant came back
`Err(OpErr::Sign(SignErr::ApprovalDenied))` — never `UnlockErr::NoMatchingEnrollment`, which is
what would prove the backend was reached — and that the recorder saw all six. This is the
"approval policy covering every privileged operation" test `00-design-decisions.md` asks for,
and it is the one test that would catch a future arm added to `execute` without a prompt.

**The fixture matters and the sentence above under-specifies it.** Four arms
(`EvmGenerate`, `SolanaGenerate`, `EvmAddress`, `SolanaAddress`) hit `approve` first and pass
with an empty store. The other two do not, and would fail the assertion for the wrong reason:

- `Read` runs `api.export_permit(ctx)` first (that is the point of test 2), so it needs a key
  already sealed `KeyUse::Shareable` in the store or it returns `ApiBackendErr::KeyNotExists`
  and never reaches the renderer.
- `Sign` runs name validation, the body parse, the policy load, the `grant_public_key` lookup
  and `hc_sign::sign::prepare` before `approve` (`lib.rs:755-778`), so it needs a parseable
  intent **and** a matching `<store>/policies/<KEY>.toml` **and** a pinned grant key. All three
  already exist in `hc-console/src/approval.rs`'s `queue()` fixture (`:381-397, :435-446`) —
  `Config::for_test` pins a grant key at `hc-core/src/config.rs:370-374` — so lift that fixture
  rather than inventing one.

**2. A structural refusal still costs no prompt.** Extend
`read_refuses_a_sign_only_key_before_any_unlock` (`lib.rs:1019-1058`) with the recording
renderer: the `LOCKED` key must come back `EnvErr::ExportRefused` with the recorder **empty**,
while `OPEN` reaches the prompt. This pins the `export_permit`-before-`approve` ordering that
§5 depends on and that `dryrun.sh` asserts with a biometric counter on real hardware.

**3. No terminal is a typed refusal, not a denial.**
`Headless { tty: Tty::Headless }.ask(1, &ctx, "…") == Decision::NoTerminal`, and
`Approver::new(UnlockGate::Biometric, Arc::new(that)).approve(&ctx, "…")` is
`Err(SignErr::NoApprovalTerminal)` — asserted `matches!`-style so `ApprovalDenied` fails the
test. This is decision 2's "must not degrade into a generic denial", and it is the exact
behaviour `ConsoleApprover` gets wrong today.

**4. A refused session may not reach the screens that expose keys off-process.**
`00-design-decisions.md` names this invariant twice — "A passphrase session currently refuses to
serve (`Serving::Refused`). That behaviour is load-bearing and must survive" and "Under
`UnlockGate::Passphrase` the console must still not expose or read-test". Today it lives in
`run()` (`hc-console/src/menu.rs:421-426`) as a guard over the transition the state machine just
computed, and **no test reaches it**: `menu.rs`'s only two tests (`:1041`, `:1066`) exercise
`next(state, choice)`, the pure transition table, which does not consult `serving` at all.

The guard's pure part is extracted so `run` and a test call the same thing:

```rust
// hc-console/src/menu.rs, beside `next`
/// Whether a session that is not serving may enter `target`. The two screens that open a
/// tunnel or read a key off-process are the ones a refused session must not reach.
pub(crate) fn allowed(target: MenuState, serving: &Serving) -> bool {
    !matches!(target, MenuState::Exposure | MenuState::ServeAndApprove)
        || !matches!(serving, Serving::Refused)
}
```

`run`'s body becomes `let refused = !allowed(target, &console.rt.serving);` — the same two
`matches!` it already has, in one place instead of inline. This is legitimate under CLAUDE.md's
"or to prove non-trivial properties (more than an if or arithmetic) with a test": the property is
*which* screens are gated, and the failure mode of getting it wrong is a passphrase session
opening a reverse tunnel to a key API it is not allowed to serve.

The test asserts both directions across every `MenuState`, so a screen added later defaults to
being considered: `allowed` is `false` for exactly `Exposure` and `ServeAndApprove` under
`Serving::Refused`, and `true` for every state under `Serving::Live`. Written as a loop over the
same `MenuState` list `transitions_enter_and_leave_submenus` already enumerates, so the two
tests cannot drift apart on the state set.

**Ported unchanged in meaning:** `a_drain_pass_bounds_prompts_and_denies_the_rest` and
`escaping_a_prompt_stops_the_pass_and_still_answers_everyone`
(`hc-console/src/approval.rs:487-543`) — the flood bound and fail-closed guarantees survive the
refactor and their `Stub` becomes a stub `Renderer`.

**Deliberately not written:**

- `Decision → After` and `Event → Key`: both are matches.
- `Approver::shown` incrementing: that is testing `fetch_add`.
- `Display for Serving`: formatting.
- `flock` mutual exclusion: that tests the kernel, not our logic. See risk 4.
- "A passphrase session binds nothing": in `Runtime::start` this is a single `match gate` arm,
  and a real test would need a fixture home with a TLS cert and a keyring to reach it. Testing
  it would be testing an `if` at the cost of an integration fixture. What that arm *guarantees*
  — that a refused session cannot reach the screens which expose keys off-process — is pinned
  by test 4 instead, on the pure predicate, with no fixture at all.
- `BindPort`: a two-arm `match` choosing an integer. Test 4's sibling property — that the
  console's port is unpredictable — is a property of the kernel, not of our code.

---

## 10. Risks and open questions

**1. `scan_stranded` is broken, and after decision 8 that is a bug rather than a hole in the
design.**
An earlier revision of this section ran to a page, because the plan then put **both** renderers
on `config.port()` and `scan_stranded` was the only thing standing between a stranded
`ssh -R 7777:localhost:5555` and the next session's key API. Decision 8 reversed that. The
terminal renderer keeps the ephemeral bind, so the *unpredictability* property — nobody can
point `-R` at a port they cannot guess — is retained, not traded, and nothing is built on the
scan. **The risk this section carries is therefore much smaller than it was, and the text says
so rather than keeping alarm that no longer applies.**

What is left is a real defect in `scan_stranded` itself, which decision 8 requires fixing on its
own merits:

- **`ps` truncates.** `scan_stranded` (`hc-console/src/exposure.rs:165-166`) runs
  `/bin/ps -axo pid=,args=` with piped stdout. BSD/macOS `ps` falls back to a **79-column**
  width when stdout is not a tty, and the argv this repo's own `ssh_reverse_args` (`:74-90`)
  produces — `ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o
  ServerAliveCountMax=3 -R localhost:7777:localhost:5555 user@host` — puts the `-R` token past
  column 90. The token the parser looks for is cut off before the parser ever sees it, so the
  check misses the exact tunnel shape it exists to find. The existing test (`:355-374`) cannot
  catch this: it feeds `stranded_tunnels` a synthetic string and never runs `ps`.
  **Fix: `-ww`**, i.e. `/bin/ps -ww -axo pid=,args=`.
- **Only `ssh` matches** (`:133` compares the basename of argv[0] against `"ssh"` exactly).
  `autossh`, `socat`, an editor's remote-dev helper, or any Go/Rust forwarder holds the same
  forward and is skipped by construction. Widen the match beyond bare `ssh`.
- **Other uids are invisible.** macOS restricts `KERN_PROCARGS2`, so `ps` shows another user's
  process with no arguments at all. A tunnel held by a second account on the machine, or by
  root, never matches. Not fixable from here; state it.
- **It is one-shot at startup** and does not see a forward established from the remote side.
  Also not fixable from here.

Both fixes land in the same step that moves the file (step 2), and the existing test is
re-pointed at the real command shape — with one live test that spawns a real `ssh -N -R …`
against a sleeping port and asserts `scan_stranded` finds it, since that is the case the
synthetic test cannot cover.

Two things must still be said plainly, because the scan is belt-and-braces for **both**
renderers and `serve` is on a fixed, publicly documented port:

1. In the log line, and in the README paragraph rewritten in step 11: the check is a best-effort
   scan of *this uid's* forwarding processes at *startup only*. Nothing is built on top of it.
2. The failure mode is a **false provenance claim, not an unprompted release**.
   `Peer::with_tunnels` (`hc-daemon/src/lib.rs:342-347`) counts only tunnels *this process*
   opened, so a request arriving through a stranded or foreign tunnel is reported to the human
   as `Peer::Loopback` — "the loopback socket" — on both the approval prompt and the Touch ID
   sheet. After §5 a human still approves every operation; what they are shown is wrong.

For `serve` that residual is inherent: a daemon whose clients must find it cannot have an
unpredictable port. For the console it does not arise, which is the whole of decision 8.

**2. ~~Whether the CLI and menu paths should prompt.~~ Closed by decision 10.** This was
written against decision 2 alone. `00-design-decisions.md:100-103` (decision 10) now scopes
decision 2 to "the network surface — loopback TLS and adapter sockets" and states that "a human
running a CLI subcommand at their own terminal is not prompted twice". §5's line is the locked
one; nothing to confirm. Keeping it listed only so the reasoning is not re-litigated.

**3. `serve`'s bounded queue and exit code both change.** With every op crossing the mpsc
channel, `serve` inherits `PENDING_OPS = 4` and 503s a fifth queued request that it would
previously have serialised behind `PROMPT`. And the unified signal task `process::exit`s with
`128 + signal` where `run_server` returned `0`. The exit-code change loses nothing: `run_server`
is `#[tokio::main]`, so its `block_on` returning already dropped the runtime and cancelled every
in-flight connection task without draining — there was no graceful drain to lose. Nothing in
`scripts/` checks `serve`'s exit status, but anything an operator wrote around it might.

**4. Same-process `flock` semantics.** `std::fs::File::try_lock` (stable since 1.89;
`rust-toolchain.toml` pins 1.96.1) lowers to `flock(2)` on Unix, so the lock lives on the open
file description and two independent `open`s in one process **do** conflict. That is the
behaviour `socket::claim` (`socket.rs:96-108`) already relies on, and it is why decision 11 has
the claim taken once at the top and handed down. It is also why `Claim::mutate()` exists rather
than a second `Claim::take`: a background task in the Runtime process cannot take the store lock
a second time, and stage 2 has two such tasks that must exclude each other. Cross-process
exclusion — the property this design actually needs — holds regardless. Confirm empirically
before adding any nested claim.

**5. `menu.rs`/`bundles.rs`/`status.rs` field churn.** Roughly 40 signatures change
`console.X` to `console.rt.X`. Mechanical, but it is where a mis-merge would hide. Step 7 is
the one step that cannot be split further, and it is the one to review most carefully.

**6. The terminal renderer cannot observe a signal cooperatively.** The menu blocks inside
`inquire` prompts with no repaint or cancel hook (`00-design-decisions.md` names this hazard
for stage 4). That is why the signal task `process::exit`s rather than flipping a flag both
renderers poll, and why `SocketPaths::unlink` must run *inside* the signal task rather than
relying on `Drop`. If stage 4 ever gives the console a cooperative tick that survives an
`inquire` prompt, this can be revisited.

**7. `Runtime::start` under `UnlockGate::Passphrase` binds nothing at all, including adapter
sockets.** Today the console binds no adapter sockets under either gate, so this is not a
regression — but it means a passphrase console will not surface a broken adapter manifest the
way `serve` does. That is the correct trade (a session that cannot answer must not accept), and
`hot_cheese adapters` (`hc-cli/src/lib.rs:766-816`) is the command that checks manifests
without binding anything.

**8. The console gaining adapter sockets is a capability change, not a refactor.** Under
decision 8 a biometric console binds one unix socket per manifest, which it has never done. Two
consequences the operator will notice: an adapter manifest that fails `load_all`'s pin/policy
intersection (`hc-daemon/src/lib.rs:90-93`) now refuses to *start the console*, where before it
only refused to start `serve`; and a service configured against an adapter socket starts working
while the console is open, which is the gap decision 8 closes deliberately. Neither is a
regression, both belong in the README paragraph rewritten in step 11.

---

## IMPLEMENTED

Stage 1 is implemented on branch `upgrade_v1`. `cargo check --workspace --release` and
`cargo clippy --workspace --release --all-targets` both pass with zero errors and no new
warnings. **Nothing was executed**: this box is Linux, so `cargo test` cannot link the Apple
frameworks. The tests below type-check under `--all-targets` and have never run.

### Divergences from the plan, and why

1. **`Display for Serving` landed in step 1, not step 10.** Its two call sites (`menu::draw`,
   `approval::draw`) were re-pointed in step 10 as written. Cosmetic ordering only.
2. **The signal task does not `shutdown.send(true)`.** `Serving::Refused` carries no sender, so
   the send would need an `Option`, and `std::process::exit` on the next line makes it
   unobservable. The task is `tunnels.close_all(); renderer.restore(); paths.unlink(); exit`.
3. **`Runtime.sockets` is `_sockets`.** `start` drains `bound`, so the field is never read again
   and the plan's name raises `dead_code`. Silencing a lint is banned.
4. **`Drop` stays on `AdapterSockets`, not on `SocketPaths`.** The signal task holds an
   `Arc<SocketPaths>` clone forever, so an `Arc`-drop-based unlink would never fire on a normal
   exit. `Drop for AdapterSockets` calls `paths.unlink()`; the signal task calls it directly;
   `unlink` ignores `NotFound` so both may run.
5. **`body_digest` was inlined, not moved.** Deleting `service_one`'s `_ =>` branch left it with
   one caller and no test; CLAUDE.md forbids a single-use no-logic function. `DIGEST_CHARS`
   survives beside `execute`.
6. **`ServeErr` lost `Manifest` and `Socket`.** With `run_server` gone nothing produced them.
   `RuntimeErr` carries `NotServing`, `StdIo`, `Manifest`, `Socket`, `Tunnel`, `Flock`,
   `StrandedTunnels` and nests `Serve(ServeErr)`.
7. **`ConsoleErr` lost `Tunnel` and `StdIo`.** Both became unproduced once the bind and
   `scan_stranded` moved into `Runtime::start`. It is now `Runtime | Status | Menu`.
8. **`hc_console::session` survives as a private helper** under `hc_console::run`: `run` must
   print the failure on the terminal on every path, which needs an inner function to `?` into.
9. **The `approver` parameter was deleted from eleven console signatures** rather than
   re-pointed, because the approver now lives in `console.rt.approver`.
10. **`scan_stranded` drops the program-name check entirely** rather than widening it to a list:
    "any Go/Rust forwarder" cannot be enumerated. The synthetic test's `notssh` line is now
    `autossh` and is expected to match.
11. **The new live `scan_stranded` test spawns `/bin/sh -c 'sleep 30' <ssh reverse argv>`**, not
    a real `ssh`. It reproduces the past-column-90 argv the `-ww` fix exists for, with no
    network, no ssh key and no race on connection failure.
12. **Test 4 enumerates all eleven `MenuState` variants** in its own `EVERY_STATE` const rather
    than reusing `transitions_enter_and_leave_submenus`' eight `(choice, state)` pairs, which
    omit `Root`, `BundlePeers` and `Quit`.
13. **`init --force` takes the claim after `create_dir_all(&home)`**, not at the very top, so
    `init --force` on a machine with no home dir still works.
14. **`ApprovalErr::Inquire` and `ApprovalErr::Sign` were left in place.** Both were already
    unproduced BEFORE this stage, so they are not paths this upgrade made dead. §6 says
    `ApprovalErr` survives; flagged rather than deleted.

### Not done

- Step 11's acceptance gate: a full `scripts/dryrun.sh` run on real hardware. The script's
  phase-6 text and `README.md` were edited as specified, but only macOS can run either.
