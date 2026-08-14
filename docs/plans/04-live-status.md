# Stage 4 — live status in the console

The console re-renders status without a keypress: last backup push, last fetch and divergence,
last bundle poll, peer reachability, pending approvals.

Bound by `00-design-decisions.md` and `CLAUDE.md`.

`02-git-store.md` and `03-bundle-autopoll.md` did not exist when this was first written, so it
invented its own `StoreState`, `BundleState` and `PeerState`. **Both plans now exist and both
define their own status types, owned by their own subsystems.** This revision deletes the
invented mirrors: stage 4 no longer publishes store, bundle or peer state — it **reads** what
stages 2 and 3 already publish, and owns only the one gauge nothing else has (pending
approvals). Mirroring a live subsystem's state into a second struct is the same mistake
`CLAUDE.md` bans for config, and it would have needed a third writer on every path.

This revision is what locked decision 14 requires:

> Stage 4 owns no status of its own. It reads what stages 2 and 3 already publish and owns only
> the pending-approvals gauge. Three parallel status structs with three writers was the third
> copy of the same idea.

What the other two plans establish, verified by reading them:

| Owner | Type | Where | Clock | Shape |
|---|---|---|---|---|
| stage 2 | `GitStatus` → `GitState` → `Vec<RemoteState>` + `Relation` | `hc-daemon/src/git_store.rs` (`02-git-store.md` §6) | `u64` Unix **seconds** | **per remote** |
| stage 3 | `BundlePoll` → `PollStatus` → `Vec<PeerPoll>` | `hc-daemon/src/bundle_poll.rs` (`03-bundle-autopoll.md` §8) | `u64` Unix **seconds** | **per peer** |
| stage 4 | pending-approval gauge | `hc-daemon` | — | one counter |

Both already follow the `LogRing` pattern the design doc points at: an `Arc<_>`, a `parking_lot`
lock inside, shared with whoever renders. Stage 4 adds no fourth pattern.

**Neither shape is restated here.** `02-git-store.md` §6 and `03-bundle-autopoll.md` §8 are the
single definitions; this file names their fields where it renders them and nowhere else. Every
cross-plan reference below is by **section**, not by line number, because both documents have
been edited since this one was written and line numbers in a sibling plan rot silently.

Where stage 4 requires something the other plans did not originally provide, it is written as a
numbered **contract**. Those requirements have since been written into stage 2 itself
(`02-git-store.md` §4.0), so §5.3 now references them rather than asserting them.

---

## 0. What exists today, verified by reading

| Fact | Evidence |
|---|---|
| UI is hybrid: raw-mode crossterm lists via `pick()`, `inquire` for text/password/confirm/number | `pick.rs:442-486`; `menu.rs:20,545,610-613,825-829` |
| Everything writes to STDERR; no alternate screen, no ratatui | `pick.rs:413,430`; `menu.rs:458`; `approval.rs:138,296` |
| Outer loop `menu::run` has **no tick**; it blocks in `screen()` | `menu.rs:374-427` |
| `pick` already has a 120 ms timeout loop and a `dirty` flag | `pick.rs:458-475`, `TICK` at `pick.rs:40` |
| Only keys and `Event::Resize` set `dirty`; a poll timeout `continue`s without drawing | `pick.rs:463-474` |
| Two panels already self-repaint on their own 120 ms loops | `approval.rs:308-369`; `bundles.rs:691-761` |
| The anchor invariant: never write above `start`, never overdraw the budget | `pick.rs:406-417,419-437`, tested `pick.rs:524-561` |
| `inquire` prompts own the terminal absolutely; the console drops to cooked mode around each approval | `approval.rs:324-327`; `bundles.rs:719-722` |
| Status is computed only on entry/Refresh and reads the filesystem directly | `menu.rs:897-912`; `status.rs:115` (`read_dir`), `status.rs:125` (`Keyring::load`) |
| No timestamps anywhere in `status.rs`; the only `elapsed()` is the read-test idle clock | `status.rs` (none); `menu.rs:779` |
| `Arc<LogRing>` is the one already-shared, already-mutating thing the status screen shows | `status.rs:40-59`, written by `TeeWriter` `status.rs:63-80`, read `status.rs:207` |
| `Console` lives on the main OS thread and never moves | `lib.rs:84-103` |
| Crate graph: `hc-core` ← `hc-sign` ← `hc-bundle`; `hc-daemon` → core+sign; `hc-console` → all four | each `Cargo.toml` |
| `hc-daemon` has `parking_lot`; `hc-core` does not | `crates/hc-daemon/Cargo.toml`, `crates/hc-core/Cargo.toml` |
| The console's queue: `mpsc::channel(PENDING_OPS)` → `Approval::Console(tx)`; the sender is cloned into every connection task, which is why an empty queue reads `Empty` and a dead listener reads `Disconnected` | `lib.rs:212-217`; `hc-daemon/src/lib.rs:489-498,543-559,849`; the property spelled out at `approval.rs:429-430` |
| `push_all` logs and returns `Ok(())` even when every remote failed | `hc-daemon/src/backup.rs:249-269` |
| 22 `pick` call sites outside `pick.rs`, in 16 functions; 4 of those hold no `Console`, and 2 more reach `pick` through `pick_json` | `menu.rs` ×14, `bundles.rs` ×8; the six helpers are listed in step 5 |
| `RawScreen`'s `Drop` is the only thing that leaves raw mode on a screen's error path | `approval.rs:261-268`, used at `:316`, `bundles.rs:703`, `pick.rs:456` |

The repo is macOS-only (`objc`/`block`/`dispatch` in `hc-core`). **Nothing in this plan was
compiled.** Every verification step below runs on the Mac, in release.

---

## 1. What the band reads

### 1.1 Nothing new is published; one handle bundles what already is

Stage 4 owns no store state, no bundle state and no peer state. It reads:

- `Arc<GitStatus>` — stage 2, `hc-daemon/src/git_store.rs`. `snapshot() -> GitState`, carrying
  `fetching: bool` and one `RemoteState` per configured remote with `relation: Relation`,
  `remote_head`, `last_push_ok_at`, `last_fetch_ok_at`, `last_failure: Option<Failure>`.
- `Arc<BundlePoll>` — stage 3, `hc-daemon/src/bundle_poll.rs`. `status() -> MutexGuard<PollStatus>`,
  carrying `last_finished_at`, `arrived`, `quarantined`, `refused`, `failure`, and one `PeerPoll`
  per enrolled peer **that a tick has already visited**.
- `Arc<Config>` — stage 1, already on the `Runtime`. It is what says how many remotes and peers
  are *configured*, which is what decides whether a chip exists at all (§4.1). The two status
  objects say what happened to them, which is a different question: `PollStatus.peers` is empty
  until the first tick completes (`03-bundle-autopoll.md` §8 states this outright), so deriving
  chip presence from it would make the peers chip appear one tick late and shift the band
  sideways — exactly the jitter §4.1's presence rule and §10's test exist to prevent.
- the pending-approval gauge (§1.6), which nothing else has.

Threading four separate handles through 22 `pick` call sites is not acceptable, so they sit
in one handle, in `hc-daemon`, owned by stage 1's `Runtime`:

```rust
/// Every live subsystem a renderer reads, in one handle, so a widget takes one argument.
#[derive(Clone)]
pub struct Live {
    /// Remote and peer enrolment: what decides which chips exist at all.
    pub config: Arc<Config>,
    /// The git store's own status object.
    pub git: Arc<git_store::GitStatus>,
    /// The bundle poller's own status object and poke channel.
    pub bundles: Arc<bundle_poll::BundlePoll>,
    /// Requests queued for this session's approver, right now.
    pub pending: Arc<Pending>,
    /// Asks stage 2's background task for a fetch now; ignored when the task is gone (§5.3).
    pub fetch_wanted: tokio::sync::watch::Sender<u64>,
}
```

`config` is the same `Arc<Config>` stage 1's `Runtime` already holds — a second handle to one
value, not a copy of its fields, so CLAUDE.md's "don't mirror a config struct" rule is not in
play. `fetch_wanted` is stage 2's own sender (`02-git-store.md` §4.0 item 1) cloned here; stage 4
does not create it.

`Live` holds handles; it does not copy their contents. It is `Clone` because it is four `Arc`s
and a `watch::Sender`, all cheap to clone. That mattered more before stage 3: the two screens
holding `&mut Console` were `bundles::watch` and `menu::read_test`, and `watch` needed an owned
copy so the band's reader did not conflict with `service_pending(&mut Console, ..)`. Stage 3
deletes `watch` (§2.4), and `read_test` reaches `pick` before it borrows mutably, so no screen
in this revision has to clone. `Clone` stays anyway — a `&Runtime` argument would not compile in
a screen that borrows `Console` mutably, and keeping the escape hatch costs nothing.

`hc-daemon/src/lib.rs:6-9` gains `pub mod live;` for `Live` and `Pending`. It does **not** need
`hc-core` to grow `parking_lot` (verified absent from `crates/hc-core/Cargo.toml`;
`crates/hc-daemon/Cargo.toml` has it), because stage 3 already places `BundlePoll` in
`hc-daemon` and adds `hc-daemon → hc-bundle` (`03-bundle-autopoll.md` §1) — the cycle this plan
previously worried about is resolved by stage 3 in stage 4's favour.

### 1.2 One clock

Locked decision 12: **`u64` Unix seconds everywhere.** An earlier revision of this section
described stage 2 stamping seconds and stage 3 stamping milliseconds, and flagged the mismatch
as a foot-gun — a future edit passing a millisecond stamp where seconds are expected renders a
40-year-old poll and nothing catches it. That is now settled the right way: stage 3 stamps
seconds too, from the same `hc_sign::grant::now_secs()` stage 2 uses
(`02-git-store.md` §6, `03-bundle-autopoll.md` §8). Stage 4 converts nothing.

```rust
/// How long ago a Unix-epoch stamp was, as the band and the panel say it.
fn age(then: u64, now: u64) -> Age
```

Both arguments are seconds. `now.saturating_sub(then)` renders `now` when the clock has stepped
backwards past the event, which is the only truthful thing a relative age can say (§1.7).

The one `_ms` field either plan still carries is `PollStatus.last_took_ms`, and it is an elapsed
**duration**, not an epoch stamp — a tick that takes 300 ms would be `0` in seconds. Stage 4 does
not render it; if it ever does, it renders it as a duration and never feeds it to `age`.

### 1.3 Why stage 4 stores no error text

Because it stores nothing. The failure detail already exists, typed, in the other two plans'
own status objects: stage 2's `Failure { at, op, cause: Arc<GitErr>, stderr }`
(`02-git-store.md` §6) and stage 3's `PeerPoll { pull: Result<(), SyncErr>, push: … }`
(`03-bundle-autopoll.md` §8). Both deliberately keep the **typed** cause, and stage 2
additionally keeps the child's `stderr` as a display field.

An earlier draft of this plan argued that no snapshot could hold a cause because `BackupErr` and
`SyncErr` wrap `io::Error` and are therefore not `Clone`. That argument is **wrong and is
retracted**: stage 2 solves it with `Arc<GitErr>` and stage 3 solves it by handing back a
`MutexGuard` instead of a snapshot so the renderer formats under the lock. Stage 4 renders
whichever of the two each subsystem offers and invents neither. Note that `BackupErr` does not
survive stage 2 at all — the type stage 4 formats is `GitErr`.

What stage 4 does keep from that reasoning is the layout consequence, which is still right: the
band shows *that* something broke, and the log tail two lines below it — `tracing` →
`TeeWriter` (`status.rs:63-80`) → `LogRing` — says *why*, in the same frame.

### 1.4 The read API

```rust
impl Live {
    /// Everything the band needs, taken in one pass so each lock is taken once.
    pub fn band_source(&self, now: u64) -> BandSource;
}

/// Reduced to exactly what one band line renders from; owns nothing shared.
pub struct BandSource {
    /// Unix seconds the band was built at, so a render is pure over its argument.
    pub now: u64,
    /// `config.backup_remotes.len()`, which decides whether the store chips exist at all.
    pub remotes: usize,
    /// The worst relation across the remotes, and when it was learned.
    pub store: Option<(Relation, u64)>,
    /// Whether a fetch is running right now, from `GitState.fetching`.
    pub fetching: bool,
    /// Newest successful push, and how many remotes have a push failure recorded.
    pub push: (Option<u64>, usize),
    /// `config.bundle_peers.len()`, which decides whether the bundle chips exist at all.
    pub peers: usize,
    /// Peers whose last pull succeeded, from the `PollStatus.peers` rows that exist.
    pub peers_ok: usize,
    /// Last poll's finish stamp, its arrivals and its quarantines. All seconds and counts.
    pub poll: Option<(u64, u64, u64)>,
    /// Whether the last poll failed outright.
    pub poll_failed: bool,
    /// Requests waiting for approval.
    pub pending: usize,
}

pub struct Pending {
    count: AtomicUsize,
}

impl Pending {
    pub fn get(&self) -> usize;
    fn enter(&self);
    fn leave(&self);
}
```

There is no `publish`, no `Update` enum and no closure API: stage 4 writes nothing but the
gauge, and the gauge's two writes are the drop guard's (§1.6).

The band is a pure function of `BandSource`, which is a plain owned value — counts, relations and
stamps, no `Arc`, no guard, no borrow. That is what keeps the render out of both locks and what
makes `render_band` testable without a runtime, a clock or a filesystem.

`remotes` and `peers` come from `live.config`, **never** from the length of `GitState.remotes`
or `PollStatus.peers` (§1.1). For the store that would be harmless — stage 2 writes one
`RemoteState` per configured remote in config order — but for peers it is wrong: stage 3's
`peers` is empty until the first tick finishes. Reading both from config keeps the rule uniform
and makes the presence test independent of whether any background work has happened yet.

AUDIT: `BandSource` is a projection, and a projection is exactly the kind of thing that rots
against its source. It is justified here only because it is what stops the render happening
under two foreign locks. If stage 2 or 3 changes a field it feeds, the compiler catches it at
`band_source` and nowhere else — keep that function the single place either plan's types are
read. Both plans now name this file as their one consumer, so the coupling is declared on both
sides rather than assumed on one.

AUDIT: `band_source` takes stage 2's lock (via `snapshot()`) and then stage 3's (via
`status()`), in that order, ~8×/s. No writer in either plan takes the other's lock, so no
ordering hazard exists today — but nothing enforces it. If a later stage makes one subsystem
read the other's status, fix the order here first.

AUDIT: stage 2's `snapshot()` deep-clones `GitState`, including every remote's `last_failure`
and its `stderr: String`. At 8×/s that is more allocation than §6.1's "one allocation" claims.
Either stage 2 grows a cheap projection for the band, or `band_source` is called only when the
frame is about to be drawn rather than on every tick. Owner's call; §6.1 is corrected to state
the real cost. Stage 2 §6 records the same trade-off from its side and points here, so whichever
way it is settled, one edit covers both plans.

### 1.5 Who writes what

| Fact the band shows | Writer | Where it already lives |
|---|---|---|
| store relation, last push/fetch, failures, `fetching` | stage 2's background task | `GitStatus`, `02-git-store.md` §4, §4.0 |
| bundle poll age, arrivals, quarantined | stage 3's poller thread | `PollStatus`, `03-bundle-autopoll.md` §8 |
| peer reachability | stage 3's poller thread | `PeerPoll`, `03-bundle-autopoll.md` §8 |
| pending approvals | `hc_daemon::delegate` + drop guard (§1.6) | new, stage 4 |

Note the thread kinds differ and stage 4 must not assume otherwise: stage 2's writer is a
**tokio task** (`02-git-store.md` §4), stage 3's is a **dedicated OS thread** with a `SyncSender`
request channel joined at shutdown (`03-bundle-autopoll.md` §1). Anything stage 4 asks either of
them to do must suit its own concurrency model — which is why §5.3's `[p]` fetch signals a
`watch` channel while the bundle side would need a `Poke`.

The console's own three `backup::push_all` sites — `menu.rs:566` (generate), `menu.rs:622` (add),
`menu.rs:814` (Backup → Push) — publish nothing under this revision, and two of the three do not
survive: stage 1 §7a routes `menu.rs:566` and `:622` through the mutation chokepoint and stage 2
§7 deletes them, while `menu.rs:814` stays and becomes the git push, still failing loudly because
the operator asked for it. Whichever of them runs, stage 2 records the outcome into `GitStatus`
per remote, so the band picks the result up with no stage-4 write at all. This removes the old
ordering constraint on `push_all`'s return value: stage 2's `Err(AllRemotesFailed)` is fired only
when *every* remote failed, which would never have been enough to render a partial failure — the
per-remote `RemoteState.last_failure` is.

### 1.6 Pending approvals — the one cross-crate change

The console cannot count its own queue. Options considered:

- **Read `Receiver::len()` from the main thread.** The receiver is inside `Console.serving`
  (`lib.rs:75`), which `pick` does not have. It could be sampled in `service_pending`
  (`menu.rs:431-445`), but that runs only between screens — the count would be frozen at 0 for
  the whole time the operator sits on a list, which is exactly when a request queues and
  exactly when the operator needs to know. Rejected.
- **Keep a clone of the `mpsc::Sender` in `Console` and read `max_capacity() - capacity()`.**
  A retained sender means the receiver never observes `Disconnected`, and
  `ApprovalErr::ListenerGone` (`approval.rs:240,347`; handled at `menu.rs:387-390`,
  `menu.rs:943-949`) is built on exactly that. The codebase already states the mechanism
  outright: `approval.rs:429-430` holds a sender open in a test precisely so "an emptied queue
  still reads as `Empty`, not `Disconnected`". This would silently break listener-exit
  detection. **Rejected — do not do this.**
- **A gauge in `hc-daemon`, incremented at the single choke point.** Chosen.

**RECONCILED with stage 1.** An earlier revision of this section evolved `enum Approval`
(`hc-daemon/src/lib.rs:487-498`) into `Approval::Console { tx, pending }`. **Stage 1 deletes that
enum outright**: `Approval::Inline` and the `spawn_blocking(execute)` path go, `serve_io`,
`serve_loop` and `service_impl` take an `mpsc::Sender<PrivilegedOp>` directly, and every
privileged op — both renderers — crosses the channel (`01-runtime-unification.md` §3, §6). So
there is no variant left to evolve. The gauge is instead a **second parameter carried beside the
`Sender`** along the same path stage 1 already rewrites:

```rust
// hc-daemon/src/lib.rs — post-stage-1
struct Outstanding {
    pending: Arc<live::Pending>,
}

impl Drop for Outstanding {
    fn drop(&mut self) {
        self.pending.leave();
    }
}

async fn delegate(
    tx: &mpsc::Sender<PrivilegedOp>,
    pending: &Arc<live::Pending>,
    ctx: OpContext,
    body: Bytes,
) -> Result<Vec<u8>, DelegateErr>;
```

`serve_io` / `serve_loop` / `service_impl` each gain the `Arc<Pending>` beside the `Sender` they
already gained in stage 1, and `Runtime::start` passes it when it spawns them. Threading two
`Arc`-ish values instead of one is the whole cost, and it is smaller than the enum edit was: it
touches the same four signatures stage 1 touches, in the same step's shape, with no type to
keep `Clone`.

`delegate` builds `Outstanding` **before** `try_send`, not after: on the `Full`/`Closed` arms the
guard drops on the `return`, so the net effect is zero, and there is no window in which an op is
queued but uncounted. It is held across `answer.await`. The drop guard is what makes it
leak-free — a connection task cancelled mid-await, or unwinding, still decrements.

`Pending::enter`/`leave` are private to the module and reached only through `Outstanding`, so the
counter has exactly one increment site and exactly one decrement site. `AtomicUsize` with
`Ordering::Relaxed` — a display counter, no ordering is needed against anything.

Under `UnlockGate::Passphrase` the runtime binds no listener and no adapter socket at all
(`01-runtime-unification.md` §1 step 5; today's equivalent is `hc-console/src/lib.rs:198-200`),
so nothing ever reaches `delegate` and the count stays 0. Truthful.

### 1.7 Clock: wall clock, not `Instant`

Settled by stages 2 and 3, which both stamp Unix epoch integers (§1.2); this section records why
that is right and what stage 4 must not do with it. Two reasons, in order of strength:

1. **The band and the log file must agree.** A failure shows as `push FAILED 2m` in the band
   and as a typed error line in the log tail directly below it (§1.3). `tracing`'s default fmt
   timer, installed at `status.rs:102-107`, is wall-clock. If the band's clock is monotonic and
   the log's is wall-clock, cross-referencing the two is guesswork. Same clock, or the design
   in §1.3 does not work.
2. **`Instant` cannot produce an absolute stamp at all.** The panel wants
   `pushed 3m ago (14:29:41)`. There is no path from `Instant` to a wall-clock time.
3. *(Unverified — confirm on the target Mac.)* Rust's `Instant` on macOS is believed to be
   based on `mach_absolute_time`/`CLOCK_UPTIME_RAW`, which does not advance while the lid is
   shut. A laptop that slept eight hours would render an overnight-stale push as minutes old.
   This corroborates the choice but is not what it rests on.

The backwards-clock case: `now.saturating_sub(then)` on the epoch integers renders `now` after an
NTP step backwards past the event. This is not swallowing a failure — zero elapsed is the only
truthful thing a *relative* age can say once the clock has moved behind the stamp. It cannot go
negative and it cannot render an absurd age, which is what `Duration`-subtraction without the
saturate would do.

**`Instant` stays where it already is and must not be converted:** the read-test idle clock
(`menu.rs:755,777,779`) and the watch poll deadline (`bundles.rs:704,707,716`). Those are
deadlines, not displayed timestamps, and a clock step must not fool them. The rule:
`Instant` for deadlines, the wall clock for anything a human reads.

**No new dependency.** Stage 4 renders relative ages only (`3m`), which `std` can do. Absolute
stamps (`14:29:41`) need calendar formatting, which `std` cannot do; `chrono 0.4.45` and
`time 0.3.49` are already in `Cargo.lock` as transitive deps, so promoting one to a direct
dependency of `hc-console` is cheap when the owner wants absolute stamps. Epoch integers keep
that a one-line change instead of a redesign. The panel layouts in §4 show the absolute stamps in
parentheses; **omit the parenthesised part until that dependency is added**, and say so in the
commit rather than shipping a half-rendered line.

AUDIT: when they are added they must be **UTC**, not local. `tracing_subscriber::fmt`'s default
timer writes UTC (`2026-08-12T14:32:45.123456Z`), and §4.2's mock log tail shows exactly that.
A local-time stamp beside a UTC log line reintroduces the guesswork reason 1 exists to remove —
in any non-UTC timezone the two would disagree by hours. Either render UTC, or move the
subscriber to a local timer as well; do not mix.

---

## 2. How the repaint is driven

### 2.1 The rule

**Repaint when the rendered band text differs from what is on screen.**

Not a generation counter, not a timer. A generation counter would miss the ageing case: nothing
mutates for three minutes but `push 2m` must become `push 3m`. A timer would repaint when
nothing changed. Comparing the rendered text is exact: the band is a pure function of
`(BandSource, now)`, so if the render is byte-identical there is nothing to repaint, and if
it differs there is.

The reusable unit, in `hc-console/src/status.rs`:

```rust
#[derive(Default)]
pub(crate) struct BandCache {
    line: String,
}

impl BandCache {
    pub(crate) fn tick(&mut self, live: &Live) -> bool {
        let next = render_band(&live.band_source(unix_now()));
        if next == self.line {
            return false;
        }
        self.line = next;
        true
    }

    pub(crate) fn line(&self) -> &str {
        &self.line
    }
}
```

Used in three loops (`pick`, `serve_and_approve`, the Status panel) — `bundles::watch` was a
fourth before stage 3 deleted it (§2.4) — which is what justifies it as a function under
`CLAUDE.md`.

Two properties this shape has and a cheaper one would not:

- **No starvation under a held key.** The tick is the first statement of the loop body, so it
  runs once per iteration whether the iteration was woken by a key or by the 120 ms timeout. Key
  auto-repeat tops out around 30/s, so the tick runs *more* often under a held key, not less.
  Putting it in the `!poll(TICK)` branch — the obvious placement — is the bug this avoids: a held
  arrow key would freeze the band for as long as it is held.
- **No repaint when nothing changed.** `tick` returns `false` on a byte-identical render, so the
  loop leaves `dirty` alone and `draw` is not called. An idle console with nothing configured
  renders an empty band, which never changes, and repaints zero times.

The cost is one `BandSource` build plus one `String` per tick even when the answer is "no
change" — ≤ 8/s while a list is on screen and nothing while it is not. See §1.4's AUDIT on
`snapshot()`'s deep clone, which is the part of that cost worth arguing about; the `String` is
not. A cheaper formulation exists — render into a reused buffer with `write!` and compare in
place, avoiding the allocation — and is a drop-in change to this struct alone if it ever
matters. It is not specified here because it makes `render_band`'s signature worse for no
measured gain.

### 2.2 In `pick`

The tick goes at the **top** of the loop, not in the poll-timeout branch. In the timeout branch
it would never run while a key is held down.

```rust
let mut state = State::new(&rows, filter);
let outcome = loop {
    if state.band.tick(live) {
        state.dirty = true;
    }
    if state.dirty {
        draw(&state, title, start)?;
        state.dirty = false;
    }
    if !crossterm::event::poll(TICK)? {
        continue;
    }
    ...
};
```

`BandCache` is a field on `State` (`pick.rs:71-86`) — `State` is documented as "what the widget
is showing right now", and the band is part of that. `render` (`pick.rs:342-401`) reads
`state.band.line()` and keeps its five arguments.

Signature: `pick(live: &Live, title, options, filter)`. `Live` is three `Arc`s, `Send + Sync`,
and carries no `!Send` handle, so passing it into the widget costs nothing.

### 2.3 Where the band is drawn, and the budget it must respect

Above the anchor is forbidden (`pick.rs:406-417`) and below the anchor is cleared on every
frame (`Clear(ClearType::FromCursorDown)`, `pick.rs:429-437`). **The band must therefore be
inside the pick frame, paid for by the budget.** There is no third option.

Position: directly under the title, above the list. Fixed position, no jitter.

The budget as it stands, `pick.rs:216-229`:

```rust
fn budget(rows: usize, start: usize, options: usize, wanted: usize) -> Budget {
    let mut left = rows.saturating_sub(start).saturating_sub(TITLE);
    let page = options.min(MAX_PAGE).min(left);
    left -= page;
    let help = left >= HELP;
    if help {
        left -= HELP;
    }
    Budget {
        page,
        room: wanted.min(left),
        help,
    }
}
```

and the invariant it is tested against, `pick.rs:552-557`:

```rust
let b = budget(rows, start, options, 40);
let chrome = TITLE + usize::from(b.help);
assert!(
    b.page + b.room + chrome <= rows - start,
    "frame overdrew {rows}x{start} with {options} options: {b:?}"
);
```

The band is paid **after the list and after the help line** — last of everything except the
description panel:

```rust
fn budget(rows: usize, start: usize, options: usize, band: usize, wanted: usize) -> Budget {
    let mut left = rows.saturating_sub(start).saturating_sub(TITLE);
    let page = options.min(MAX_PAGE).min(left);
    left -= page;
    let help = left >= HELP;
    if help {
        left -= HELP;
    }
    let band = band.min(left);
    left -= band;
    Budget {
        page,
        band,
        room: wanted.min(left),
        help,
    }
}
```

`band` in is 0 or 1: `usize::from(!state.band.line().is_empty())`. `band` out is what the frame
may draw. Payment order is priority; draw order is layout; they are independent.

**Why the band is paid after the help line, not before it.** An earlier draft paid it before,
which contradicts the degradation below: at `MIN_FRAME` with exactly three options,
`budget(5, 0, 3, 1, w)` leaves one row after the page, and paying the band first takes it — the
frame loses `esc back   ctrl-c quit` and keeps a status line. The help line is how the operator
leaves the screen; the band is decoration. Paying help first is the only ordering under which the
stated degradation is true. The ordering is observable **only** in that one-row-left case: for
every other `(rows, start, options)` both orders produce an identical `Budget`, which is why the
two whole-struct assertions below are the same either way.

`MIN_FRAME` (`pick.rs:34`, `= TITLE + MIN_PAGE + HELP = 5`) **does not change.** A frame with
exactly the minimum rows keeps its three list rows and its help line and drops the band. That is
the correct degradation.

Re-derived, not taken from the sketch. Let `R = rows - start` (`anchor()` guarantees `R >= 1`,
and the sweep's `start in 0..rows` never produces `R = 0`). With `left0 = R - 1` after `TITLE`:
`page <= left0`; `help <= left1`; `band <= left2`; `room <= left3`. So
`page + room + TITLE + band + help <= page + left3 + 1 + band + help = left0 + 1 = R`. The
band is genuinely subtracted, so it cannot be double-spent — and if a future edit computed
`band` without the matching `left -= band`, the sum becomes `R + band`, which the amended
assertion below catches at `band = 1` for every terminal size where `room` is the binding term
(the sweep's `wanted = 40` makes it binding everywhere).

The invariant test at `pick.rs:524-561` must be amended:

- `chrome` becomes `TITLE + b.band + usize::from(b.help)`.
- The two whole-struct `assert_eq!`s (`tight` at `:525-533`, `roomy` at `:539-547`) gain
  the `band` field: `budget(6, 1, 9, 1, 6)` is `{ page: 4, band: 0, room: 0, help: false }`
  and `budget(40, 8, 9, 1, 6)` is `{ page: 9, band: 1, room: 6, help: true }`.
- The exhaustive sweep at `:549-560` gains a `band` dimension: `for band in [0usize, 1]`.
- One added case pins the ordering the sweep cannot see, because the sweep only checks the
  inequality: `budget(5, 0, 3, 1, 6)` must be `{ page: 3, band: 0, room: 0, help: true }` — at
  `MIN_FRAME` the help line survives and the band is what goes.

AUDIT: when `budget.band == 0` the band text is still recomputed and still sets `dirty`, so a
terminal too short to show it repaints the whole frame every time an age string rolls over,
drawing nothing new. Correct but wasteful. The cheap fix is for `render` to hand the drawn
band height back to the loop, or for the loop to skip the tick once the last frame paid 0 rows
for it; neither is specified here. Owner's call whether it is worth the coupling.

Nothing else in `pick.rs` moves. `anchor()` (`:406-417`), the `MoveTo(0, start)` +
`Clear(FromCursorDown)` in `draw` (`:429-437`), and the erase on exit (`:476-480`) are untouched.

### 2.4 In the one surviving existing panel

Today there are two self-repainting panels — `approval.rs:308-369` (`serve_and_approve`) and
`bundles.rs:691-761` (`watch`). **Stage 3 deletes `watch`** and everything around it
(`03-bundle-autopoll.md` §10 lists `bundles.rs:616-685` `WatchView`/`draw_watch` and `:687-761`
`fn watch`), because a background poller makes a foreground poll loop redundant. Stage 4 lands
after stage 3, so only one pre-existing panel is left to touch. An earlier revision of this
section specified both; adding a band to a screen the previous stage deletes is work that would
be reverted in the same release.

The survivor already has a 120 ms loop, a `dirty` flag and a header block. It gets one band line
and one tick:

- `approval.rs:283-303` (`draw`) — band line into the panel string; `serve_and_approve`
  (`:308-369`) gains `live: &Live` (6 args, under clippy's threshold of 7; see §11.9), a
  `BandCache`, and `if band.tick(live) { dirty = true; }` before `:350`.

With `watch` gone, **no screen needs the clone-on-entry technique** the old entry described: it
was needed only because `watch` held `&mut Console` and called `service_pending(console, ..)` on
every pass while wanting to read `live` in the same loop. The Status panel takes `&Console` and
deliberately does not drain (§5.1), and `read_test` reaches `pick` before it starts borrowing
mutably (step 5). `Live` stays `Clone` regardless — it is four `Arc`s and a `watch::Sender` —
but nothing in this revision has to use that.

---

## 3. The screens `pick` does not own — the honest limits

### 3.1 The outer `menu::run` loop: no tick needed, do not add one

`run` (`menu.rs:374-427`) does `draw(console, &notice)` then blocks in `screen()`. `screen()`
(`menu.rs:484-505`) dispatches every `MenuState` to something that either enters a `pick` or is
a self-repainting panel. The blocking time is spent *inside* a ticking loop. Adding a tick to
the outer loop would repaint a header that has nothing live in it.

The header (`menu.rs:457-482`) shows unlock, serving, store, notice. Of those only `serving` can
change mid-session, and that transition is already detected by the drain
(`menu.rs:387-390`, `menu.rs:943-949`) which sets the notice and redraws on the next pass.

**One exception:** `MenuState::Sign` (`menu.rs:637-651`) goes straight to
`Text::new("JSON intent file").prompt()` with no pick at all. Decision 5 deletes that screen in
stage 5, so it resolves itself. Do not build anything for it.

### 3.2 `inquire` prompts: frozen, and not worth fixing now

While a `Text`, `Password`, `Confirm` or `CustomType` prompt is up, `inquire` owns the terminal
absolutely. It has no timeout hook and no repaint callback. The band is stale for the whole
duration of the prompt and refreshes the instant the prompt returns — it re-renders from the
clock at that moment, so it is never *wrong*, only *absent*.

Affected: `menu.rs:545,595,610-613,638,668-669,825-829,867-870,878-880` and
`bundles.rs:540-544,605-607`, plus every approval prompt — `approval.rs:91` is the prompt itself,
and `approval.rs:324-327` and `bundles.rs:719-722` deliberately drop to cooked mode around
`service_one` precisely so `inquire` can run.

**Not worth fixing now.** Fixing it means replacing inquire's four prompt types with
hand-written raw-mode widgets. That is a whole workstream, and one of the four is the masked
password prompt on the recovery-passphrase path — a security-sensitive input that should not be
re-implemented as a side effect of a status feature. Approval prompts are seconds long anyway.

State this in the release note rather than implying the console is live everywhere.

---

## 4. Rendered layout

### 4.1 The band

One line, indented by `INDENT` (2), so it lines up with the `› ` row prefixes and the
`↑ N more` markers (`pick.rs:362,379`). Chips joined by ` · `. Non-ASCII is already in use and
`clip()` (`pick.rs:312-322`) counts chars, not bytes.

**Chip presence is decided by configuration, never by value.** A chip whose subject is not
configured — no backup remote, no enrolled bundle peer — is absent for the whole session; a chip
whose subject is configured is always present, only its text changes. This is what stops the band
shifting sideways under the operator, and it is the one property in this section worth a test
(§10). If nothing is configured and nothing is serving, the band renders empty and costs zero
rows.

The band is a projection of stage 2's and stage 3's own vocabulary. It does not introduce a
parallel set of states; every row below names the source field.

**Store** — worst `RemoteState` across `GitState.remotes`, because one diverged remote out of
three is the fact the operator has to act on. The count in parentheses appears only when the
remotes disagree.

| Source | Chip |
|---|---|
| `remotes` empty | *(absent)* |
| every `relation == InSync` | `store ok 12s` |
| any `Absent` | `store new` |
| any `Unknown` | `store unknown` |
| any `LocalAhead` | `store +2 12s` |
| any `RemoteAhead` | `store BEHIND 12s` |
| any `Diverged` | `store DIVERGED (1/3)` |
| any `last_failure` newer than that remote's last success | `store FAILED 4m (1/3)` |

**Push** — the same `Vec<RemoteState>`, read through `last_push_ok_at` and any `last_failure`
whose `op` is `GitOp::Push`. It stays a chip of its own because a store that fetches fine and
cannot push is the exact silent failure this stage exists to surface.

| Source | Chip |
|---|---|
| `remotes` empty | *(absent)* |
| every `last_push_ok_at: None`, no failure | `push never` |
| newest `last_push_ok_at` | `push 3m` |
| any `last_failure` with `op: Push` | `push FAILED 2m (1/2)` |

Ages come from `last_fetch_ok_at` / `last_push_ok_at` / `Failure.at`, all `u64` Unix seconds.

**RESOLVED — `Relation::RemoteAhead` is the pre-merge relation, and the chip stays.** An earlier
revision flagged this as undecidable from stage 4's side: stage 2 applies a fast-forward the
moment it finds `RemoteAhead`, so a chip built on it would render for milliseconds a day.
`02-git-store.md` §4.0 item 4 settles it — `Relation` records the relation **as the fetch found
it, before the merge**, and `RemoteAhead` therefore means "a fast-forward is due or in progress",
which is exactly the state an operator can act on and is observable whenever `fetching` is true
or a merge has failed. Recording the post-merge relation instead would make the field a duplicate
of `InSync` and lose the failed-merge case entirely.

**Bundles and peers** — from `PollStatus`, `u64` Unix **seconds** (§1.2).

| Source | Chip |
|---|---|
| `config.bundle_peers` empty | *(absent)* |
| `last_finished_at: None` | `bundles never` |
| `last_finished_at: Some` | `bundles 28s`, `+2` when `arrived` moved, `!1` when `quarantined` moved |
| `failure: Some(PollErr)` | `bundles FAILED 28s` |
| `peers` rows whose last `pull` is `Ok`, over `config.bundle_peers.len()` | `peers 2/3` |

Presence is `config.bundle_peers`, **not** `PollStatus.peers.len()` — that vector is empty until
the first tick finishes (§1.1), and a chip that appeared one tick in would shift the band. On a
machine with three peers and no completed tick the chip is present and reads `peers 0/3`, which
is true.

**Store in flight** — `GitState.fetching` (`02-git-store.md` §4.0 item 3) is the one field either
plan writes *before* the work rather than after, and it exists precisely so this can be rendered
honestly. When it is true the store chip appends ` …`: `store ok 12s …`. Nothing else in the band
gets an in-flight form, because nothing else has a marker: stage 3 publishes only on tick
completion, so there is no `bundles …`. A "…" on the bundle chip would be inventing state stage 4
cannot observe, and this revision does not.

**Pending** — `pending 1`, from §1.6's gauge. Always present while the session is serving,
because a request can arrive at any moment; absent under `UnlockGate::Passphrase`, where nothing
is served at all.

`age(then, now)`: `<5s` → `now`; `<60s` → `12s`; `<60m` → `3m`; `<24h` → `2h`; else `3d`. Both
arguments are Unix seconds and the subtraction saturates (§1.7).

Main screen, healthy, 100 cols:

```
hot_cheese
unlock:  Secure Enclave, Touch ID gates every request
serving: https://127.0.0.1:52341
store:   /Users/mat/.hot_cheese/store

answered 1 request(s), denied 0 unprompted

hot_cheese
  push 3m · store ok 12s · bundles 28s · peers 3/3 · pending 0
› Keys
  Sign
  Bundles
  Exposure
  Backup
  Enroll
  Status
  Serve and approve
  Quit
↑↓ move   → describe   enter select   esc back   ctrl-c quit
```

Everything from `hot_cheese` (the second one, the pick title) down is inside the frame and
repaints without a keypress. Everything above it is the header written by `menu::draw` above the
anchor and is not live.

Nothing configured yet, nothing serving — the band is empty and costs no row:

```
hot_cheese
› Keys
  Sign
  ...
```

Never pushed, a request waiting:

```
hot_cheese
  push never · store unknown · bundles never · peers 0/2 · pending 1
› Keys
```

Everything broken at once:

```
hot_cheese
  push FAILED 2m (1/2) · store DIVERGED (1/3) · bundles FAILED 28s · peers 0/3 · pending 4
› Keys
```

That worst case is 88 chars plus the 2-space indent = 90. On an 80-column terminal `clip()`
truncates it with `…`. See §11.3.

### 4.2 The Status screen

A self-repainting panel, not a pick. See §5 for why.

```
hot_cheese - status

  serving      https://127.0.0.1:52341
  unlock       secure enclave, Touch ID gates every request
  store        /Users/mat/.hot_cheese/store (7 keystores)
  enrollments  2 (1 secure enclave, 1 passphrase)

  backup       2 remote(s)
               pushed 3m ago (14:29:41), 2 of 2 took it
  git          up to date, fetched 12s ago (14:32:45)
  bundles      polled 28s ago (14:32:29), 2 arrived, 0 quarantined
  peers        3 of 3 reached
  pending      0 requests waiting for approval
  tunnels      1 open
               #1 mat@box remote localhost:7777 -> local :52341
  log          /Users/mat/.hot_cheese/console.log

  recent log   12 lines
    2026-08-12T14:32:45Z  INFO store fetch: up to date
    2026-08-12T14:32:29Z  INFO bundle poll: 2 signatures arrived
    ...

  [p] pull the store now   [r] re-read the store   [q] back   [ctrl-c] quit
```

The failure forms, which are the point of the screen:

```
  backup       2 remote(s)
               never pushed this session
```

```
  backup       2 remote(s)
               push FAILED 2m ago (14:30:41), 1 of 2 remotes refused - see the log below
```

```
  git          DIVERGED as of 12s ago (14:32:45): local 4f1c2ab, remote 9d30e77.
               Nothing was overwritten and [p] will not resolve this.
```

```
  git          the remote did not answer, 4m ago (14:28:31)
```

```
  git          fetching…
```

```
  peers        0 of 3 reached; silent: mac-mini, studio, mini-2
```

```
  enrollments  the keyring could not be read
```

The divergence line names the two `CommitId`s rather than an ahead/behind count. `Relation` is a
unit variant, so the ids come from `GitState.head` (local) and `RemoteState.remote_head`
(remote) — the latter is `rev-parse FETCH_HEAD`, which stage 2's §4.1 already computes on every
fetch and §6 records for exactly this line. It is **not** taken from
`GitErr::Diverged { host, local, remote }`: that variant exists (`02-git-store.md` §5) but the
background task's divergence is a *state* written into `Relation`, never an error returned to
anyone, so nothing in `GitStatus` would hold it. Counting commits either side would be a third
`git` invocation from the render path, which §6.1 forbids.

The silent-peer list is `PollStatus.peers` filtered to rows whose `pull` is `Err`, naming
`PeerPoll.host` — the panel formats the typed `SyncErr` under stage 3's guard rather than storing
a rendered string (§1.3). Its denominator is `config.bundle_peers.len()`, so a peer that no tick
has reached yet is counted as not reached rather than as not enrolled.

`git fetching…` renders from `GitState.fetching`, which `02-git-store.md` §4.0 item 3 writes
before the `spawn_blocking` and clears on every exit including the error path. The panel needs no
local flag of its own for it, and `[p]` is acknowledged by the marker going true rather than by
stage 4 guessing.

The divergence line naming `[p]` as insufficient is load-bearing: decision 3 says divergence is
a surfaced state, never a silent overwrite, and the screen must not imply a key exists that
papers over it.

The panel takes the whole terminal — `MoveTo(0, 0)` + `Clear(ClearType::FromCursorDown)`, the
same as `approval.rs:296-303` and `bundles.rs:677-684` — so `menu::draw`'s header is wiped on
entry and redrawn by the outer loop on exit. That is already how the serve and watch screens
behave.

---

## 5. Refresh, and the `[p]` fetch

### 5.1 Refresh does not survive

Today: `menu::draw` header (above anchor) → `status::view()` written to stderr (above anchor,
`menu.rs:898-900`) → `pick("Status", [Refresh, Back])`. The body is above the anchor, so `pick`
can never repaint it.

Moving the body inside the pick frame does not work: the body is ~25 lines including the log
tail, and the budget (§2.3) pays the list first — in a 24-row terminal the list would take its
rows and the body would get nothing.

**The Status screen becomes a self-repainting panel** with the shape the codebase already uses —
today in two places (`approval.rs:308-369`, `bundles.rs:691-761`), and in one by the time stage 4
lands, since stage 3 deletes the second (§2.4): raw mode via `RawScreen` (`approval.rs:261-268`,
already `pub(crate)`), one full repaint in place per dirty pass,
`crossterm::event::poll(TICK)` at 120 ms, keys between any two passes.

Raw mode is entered exactly once, immediately followed by `let _screen = RawScreen;`, exactly as
`serve_and_approve` (`:315-316`) does it. `RawScreen`'s `Drop` (`approval.rs:263-268`, whose body
stage 1 replaces with `Terminal.restore()`) then restores cooked mode and the cursor on **every**
exit: `[q]`, ctrl-c, an early `?` on a crossterm write, and a panic unwind. Nothing in the panel
may `return` before that binding exists, and nothing may `std::mem::forget` it. Two further
backstops already exist and must not be weakened: `ExitGuard`'s `Drop` and the panic hook
(`lib.rs:113-122,239-247`), and the signal handler (`lib.rs:148-167`). Stage 1 deletes
`teardown` and moves the signal handler into `Runtime::start`, but all three still reach
`disable_raw_mode` unconditionally, now through `Renderer::restore`
(`01-runtime-unification.md` §2, §6).

The panel runs **no** `inquire` prompt and therefore needs no cooked-mode window inside its loop
— unlike today's `watch` (`bundles.rs:719-722`), which is the screen stage 3 deletes. It does not
call `service_pending` either — the outer `menu::run` drains on the pass after it returns. That
keeps the panel's raw-mode handling a single enter and a single guarded exit, and it is why the
panel needs no clone of `Live` (§2.4).

`StatusAction::Refresh` (`menu.rs:293-294`) is replaced by the panel repainting itself.
`StatusAction::Back` (`:295-296`) is replaced by `[q]`/`esc`. The whole `menu_enum!` goes.

Signature: `status::panel(console: &Console) -> Result<Step, MenuErr>`, called from
`menu.rs:498`. It returns `Step { choice: MenuChoice::Back, notice }` on `[q]`/`esc` and
`Step { choice: MenuChoice::Quit, .. }` on ctrl-c, matching `serve_screen` (`menu.rs:931-951`).

Nothing else in the menu state machine changes. `MenuChoice::Status` is still produced by
`root_screen`'s option list (`menu.rs:515`), so the `(_, MenuChoice::Status)` arm of `next`
(`menu.rs:203`) stays live and `transitions_enter_and_leave_submenus` (`menu.rs:1041-1060`)
still passes unamended. The only producer that disappears is `status_screen`'s
`MenuChoice::Status` on Refresh (`menu.rs:904`).

### 5.2 Keys

| Key | Does |
|---|---|
| `p` | Asks for a store fetch+merge now |
| `r` | Rebuilds the entry-cached filesystem facts (§6) |
| `q`, `esc` | Back to the root menu |
| `ctrl-c` | Leave the console |

`[p]` is shown in the help line only when `config.backup_remotes` is non-empty.

### 5.3 The `[p]` fetch does not block the panel

**`[p]` is a fetch plus a fast-forward-only merge — `02-git-store.md` §4.1 — and it is
emphatically NOT `backup pull --force` (§4.3 there), which discards local history and is the one
operation in the whole upgrade that can destroy key material.** An earlier revision of this plan
called this section "the forced pull", which is the wrong name for what the key does and could
have been read as wiring `[p]` to the destructive verb. The destructive verb keeps its existing
home: the console's Backup screen, behind the `Confirm` at `menu.rs:825-835` that stage 2 rewords
to name the files it will delete. §4.2's divergence line saying "`[p]` will not resolve this" is
the same fact from the operator's side.

A `git fetch` + merge is a subprocess and can hang on an unreachable host for as long as the ssh
connect timeout. It must not run on the main thread — the panel would freeze exactly when the
operator is watching it for progress.

**This was the one hard cross-plan dependency in stage 4, and it is now written into stage 2.**
An earlier draft of this section asserted that stage 2 provided a `pull_requested()` future. It
did not: stage 2 specified one tokio task with a `tokio::select!` over a **push-wanted**
`watch` receiver (signalled by the commit chokepoint) and a `tokio::time::interval`, with the
only operator-driven pull being the `backup pull --force` **CLI verb**, unreachable from inside
a running console. It also wrote every `GitState` field on *completion*, so an in-flight
indicator could not be rendered honestly at all.

That requirement was raised as a four-item contract and is now specified on stage 2's side, in
`02-git-store.md` §4.0:

1. A fetch-wanted `watch::Sender<u64>`, mirroring the push-wanted one, reachable from `Runtime`.
2. A third `select!` arm on it, calling the same §4.1 fetch-and-fast-forward function the
   interval arm calls. Coalescing is free with `watch` — several presses before the task wakes
   are one wake.
3. `GitState.fetching: bool`, written before the `spawn_blocking` and cleared on **every** exit
   including the error path, on both the timed and the forced path.
4. `Relation::RemoteAhead` fixed as the **pre-merge** relation (§4.1).

Stage 4 consumes them: `Live.fetch_wanted` (§1.1) is the sender, `BandSource.fetching` (§1.4) is
the marker. It adds nothing to stage 2 and duplicates nothing.

`watch::Sender::send` returns `Err` only when every receiver is gone, i.e. the task is dead — so
`[p]` still has no failure the operator can cause, and §7's "stage 4 adds no error variant" holds.
Ignoring that `Err` is correct here and must be written as such rather than `?`-propagated.

**There is no equivalent bundle trigger, and this revision does not add a key that needs one.**
Stage 3's `BundlePoll::poke` (`03-bundle-autopoll.md` §8) takes `Poke::Push { hash }` — which
needs a digest — or `Poke::AwaitTick`, which **blocks the calling thread for up to one tick**.
Neither is bindable to a panel key without freezing the panel, which is the whole point of this
section; stage 3 §13 open question 1 says the same thing from its side. If a "poll bundles now"
key is ever wanted, stage 3 must first grow a non-blocking variant, and §7 gains a row for
`PollErr` (`PollerGone`, `PokeTimedOut`) because unlike the store trigger that call *can* fail.

If stage 2 somehow lands without items 1–3, the fallback is `console.rt.tokio.handle()`'s
`spawn_blocking` from the panel with `handle.is_finished()` polled on the 120 ms tick — the shape
`read_test` already uses at `menu.rs:754-785`. That fallback is worse: two code paths run git,
and neither knows about the other's in-process store guard, which stage 2 requires for the merge
(`02-git-store.md` §4.1). Prefer the trigger.

Pressing `p` with no configured remote sets a fixed panel note (`no git remote is configured`)
on the last line. That is a UI label, not an error — see §7.

---

## 6. What is recomputed per repaint

### 6.1 The band — never touches the filesystem

Per tick (≤ 8×/s, and only while a list or panel is on screen):

- one wall-clock read
- one uncontended `parking_lot::Mutex::lock()` on stage 2's `GitStatus`, plus the deep clone
  `GitState: Clone` implies — one `Vec<RemoteState>`, and per remote two `String`s and, when a
  failure is recorded, an `Arc` bump plus its `stderr: String`
- one uncontended `parking_lot::Mutex::lock()` on stage 3's `BundlePoll`, held only long enough
  to read counts and a per-peer `Ok`/`Err` tally out of the guard
- one relaxed `AtomicUsize` load
- one `format!` producing ≤ ~95 chars — one allocation
- one `String` equality compare

**Zero syscalls beyond the clock read, zero filesystem access, zero subprocesses.** Every fact in
the band was computed by a background task on its own cadence and stored; the band only formats
what is already in memory. This is the whole point of the design: the render is decoupled from
the cost of producing the data.

The honest cost is therefore *not* one allocation — the earlier draft said so and was wrong. It
is one allocation plus whatever `GitState::clone` costs, which grows with the number of configured
remotes and with the length of the last recorded `stderr`. At one or two remotes it is still
microseconds; see §1.4's AUDIT for the projection that removes it if the owner wants the band
free.

Locks are held across the *extraction*, not across the render: the band string is built from an
owned `BandSource` after both guards are dropped. Stage 3's `status()` hands back a
`MutexGuard`, so the extraction happens inside it and only the extraction does
(`03-bundle-autopoll.md` §8). Stage 2 states the same rule outright — "the lock is never held
across a render" (`02-git-store.md` §6). Writers are background tasks on 30- to 300-second
cadences; contention is nil.

### 6.2 The Status panel

The hazard is real: `status::view` (`status.rs:112-224`) calls `read_dir(store)` at
`status.rs:115` and `Keyring::load` at `status.rs:125` on **every** call. At 120 ms that is
8 directory scans and 8 keyring parses a second.

Split by how the data changes:

**Cached in a `Facts` struct, built on panel entry and rebuilt only on `[r]`:**

| Fact | Today |
|---|---|
| keystore count | `status.rs:115-123` (`read_dir`) |
| enrollment counts, passphrase presence | `status.rs:125-148` (`Keyring::load`) |
| store path, backup remote list | `console.config`, immutable `Arc` |

These change only when the operator adds a key or an enrollment, which they cannot do while
sitting on this panel. `[r]` exists for the case where another process changed the store.

**Recomputed per dirty repaint:**

| Fact | Cost |
|---|---|
| `GitStatus::snapshot()` | one lock + the `GitState` deep clone (§6.1) |
| `BundlePoll::status()` | one lock, held across the panel's extraction of its rows |
| `console.tunnels.list()` | one lock + a small `Vec` clone |
| `console.log.recent(LOG_TAIL)` | one lock + ≤12 `String` clones |
| `crossterm::terminal::size()` | one ioctl, for the clip width at `status.rs:212-215` |

### 6.3 An idle console repaints only when a rendered string changes

The panel's dirty rule:

```rust
if band.tick(live) || log.written() != drawn { dirty = true; }
```

`log.written()` is a new `AtomicU64` on `LogRing` (`status.rs:40-42`), incremented in
`LogRing::push` (`status.rs:52-58`). Comparing counters costs an atomic load; the alternative
— calling `recent(12)` every tick to discover nothing changed — allocates 12 strings 8×/s for
nothing.

There is **no live wall-clock in the panel header**, deliberately. A ticking `14:32:57` would
force a repaint every second forever.

An earlier draft claimed "a genuinely idle console repaints zero times". That is only true when
nothing is configured, so every chip is absent and the band is the empty string. With anything
configured the band carries an age, and an age *is* a clock — just a coarse one. The real
frequency, which is the property that matters and which the `age` buckets were chosen for:

| Newest event | Repaints |
|---|---|
| under 5 s old | none — `now` is a fixed string |
| 5–60 s old | once a second |
| 1–60 min old | once a minute |
| 1–24 h old | once an hour |
| over a day old | once a day |

So a console left alone overnight repaints hourly, not 8×/s, and a console with nothing
configured repaints never. That is the claim to put in the commit message.

---

## 7. Errors

`MenuErr` (`menu.rs:37-71`) already exists, already has `StdIo(std::io::Error)` with `#[from]`,
`NotATerminal { source }`, and the `NoKeystores`/`NoTunnels`/`NoBackupRemote`/`NoDiscoveredPeers`
family of unit variants.

**Stage 4 adds no new error variants,** because it introduces no new failure mode:

| Possible failure | Already typed as |
|---|---|
| Panel crossterm writes fail | `MenuErr::StdIo`, via `#[from]` on `std::io::Error` |
| `terminal::size()` / `cursor::position()` fail | `MenuErr::NotATerminal { source }`, the pattern at `pick.rs:407,420` |
| `Keyring::load` fails when building `Facts` | **not** a `MenuErr` — see below; it becomes `Enrollments::Unreadable` and the panel stays up |
| reading `GitStatus` / `BundlePoll` / the gauge | cannot fail — `parking_lot` does not poison and `format!` is infallible |
| `[p]` signalling a dead store task | `watch::Sender::send`'s `Err`, deliberately ignored (§5.3): the task being gone is already surfaced by the store chip freezing |
| `[p]` with no git remote | not a failure; a fixed `&'static str` panel note |

Inventing a stage-4 error enum with no constructor would be worse than nothing.

The `Keyring::load` row is the one place an earlier draft contradicted itself: it listed the
failure as `MenuErr::Keyring` *and*, two paragraphs later, required the panel to survive it as a
view variant. It cannot be both — propagating `MenuErr::Keyring` out of `panel` returns to
`menu::run`, which renders `error: …` and drops the screen. The panel is where an operator goes
*because* something is wrong, so it must not be the screen that a broken keyring closes. The view
variant wins; `MenuErr::Keyring` (`menu.rs:58`) stays untouched for the screens that legitimately
abort on it.

**One stringly error the rewrite must fix.** `status.rs:144-148` today does:

```rust
Err(e) => {
    tracing::warn!(error = ?e, "status could not read the keyring");
    "unreadable".to_string()
}
```

A failed keyring read must not kill the panel — that behaviour is right — but the result must be
a variant of the panel's own view type, not the string `"unreadable"`:

```rust
enum Enrollments {
    Counted { total: usize, se: usize, passphrase: usize },
    Unreadable,
}
```

The typed `KeyringErr` still goes to `tracing`, which the log tail shows two lines below.

---

## 8. Steps

Every build and test command runs **on the Mac, in release**. This repo cannot compile on Linux
(`objc`/`block`/`dispatch` in `hc-core`), so none of it was verified while writing this plan.

Standing verification after each step:

```
cargo build --release
cargo clippy --release --all-targets -- -D warnings
cargo test --release -p hc-console -p hc-daemon
```

No `#[allow(clippy::...)]` anywhere, including `too_many_arguments`.

### Step 1 — the pending gauge into the delegate path
`crates/hc-daemon/src/lib.rs`, `crates/hc-daemon/src/live.rs` (new)

- `pub mod live;` in `lib.rs:6-9`; `Pending` and `Outstanding` per §1.6.
- `delegate` gains `pending: &Arc<Pending>` beside the `tx: &mpsc::Sender<PrivilegedOp>` stage 1
  gave it, builds `Outstanding` **before** `try_send`, holds it across `answer.await`.
- `serve_io` / `serve_loop` / `service_impl` carry the `Arc<Pending>` beside the `Sender` stage 1
  put there; `Runtime::start` passes it when it spawns them. **There is no `Approval` enum to
  edit** — stage 1 deleted it (§1.6).

Verify: builds; `hot_cheese serve` and the console both start; a `/health` call still answers.
Do **not** call `/read`, `/evm_address` or `/solana_address` to test this — each costs the owner
a Touch ID.

### Step 2 — `Live`, the handle
`crates/hc-daemon/src/live.rs`

`Live` and `band_source` per §1.1 and §1.4. Requires stages 2 and 3 to have landed, since it
holds their `Arc`s and stage 2's fetch-wanted sender. Add the `live: Live` field to stage 1's
`Runtime` beside the `git` and `bundles` fields those stages put there.

Verify: builds. No consumer yet, nothing else can change.

### Step 3 — the console reaches it
`crates/hc-console/src/lib.rs`

- Nothing new is stored on `Console`: after stage 1 it holds `rt: Runtime`
  (`01-runtime-unification.md` §1), and `Live` is a `Runtime` field, so the console reads
  `console.rt.live`.
- Nothing in `hc-console` constructs the listener any more either — stage 1 moved that into
  `Runtime::start` — so the gauge is wired entirely inside `hc-daemon` and this step is purely
  the console reading `console.rt.live`.

Verify: builds; the console runs unchanged. Nothing renders yet.

### Step 4 — the pure render
`crates/hc-console/src/status.rs`

`age(then, now)`, `render_band(&BandSource) -> String`, `BandCache`. All three pure over their
arguments — `BandSource` is built by the caller and carries `now`, which is what makes
`render_band` testable with no runtime, no clock and no lock.

**Test (one):** `the_band_keeps_its_chips_in_place`. See §10 for what it pins and why the chip
list itself is not the point.

Verify: `cargo test --release -p hc-console`.

### Step 5 — the band inside the pick frame
`crates/hc-console/src/pick.rs`, then every call site.

- `State` (`:71-86`) gains `band: BandCache`.
- `budget` (`:216-229`) gains the `band` parameter and the `band` field on `Budget` (`:206-214`),
  exactly as in §2.3 — band paid **after** the help line.
- `render` (`:342-401`) draws `clip(&state.band.line(), cols)` under the title when
  `budget.band == 1`, indented by `INDENT`; argument count unchanged.
- The loop (`:458-475`) ticks the band at the top.
- `pick` (`:442-486`) gains `live: &Live` as its first parameter.
- **Amend** the invariant test (`:524-561`) per §2.3. This test is the anchor contract; it must
  still pass and must now also cover the band row and the MIN_FRAME ordering.

All 22 call sites, each passing `&console.rt.live`:

| File | Lines |
|---|---|
| `menu.rs` | 519, 527, 544, 553, 574, 575, 604, 609, 658, 702, 749, 802, 850 (901 is deleted in step 7) |
| `bundles.rs` | 324, 344, 373, 477, 598, 834, 880, 897 |

**Six** helper signatures must gain the handle, not the three an earlier draft listed. Every
function that reaches `pick` — directly or through `pick_json` — and has no `Console` in scope:

| Function | Reaches `pick` at | Caller, which has `console` |
|---|---|---|
| `menu.rs:507 root_screen()` | `:519` | `screen`, `menu.rs:490` |
| `bundles.rs:463 qr(hash)` | `:477` | `open`, `bundles.rs:357` |
| `bundles.rs:493 import(hash)` | `pick_json` at `:494` | `open`, `bundles.rs:362` |
| `bundles.rs:525 new_bundle()` | `pick_json` at `:527` | `screen`, `bundles.rs:334` |
| `bundles.rs:592 pick_json(prompt)` | `:598` | `import`, `new_bundle` |
| `bundles.rs:826 peers_screen()` | `:834, :880, :897` | `screen`, `menu.rs:494` |

`qr`, `import` and `new_bundle` were missed. `peers_screen` was cited as `bundles.rs:834`, which
is a `pick` call inside it, not its definition.

Every other call site already has `console` in scope. `serve_screen` (`menu.rs:914-920`) and
`service_pending` (`menu.rs:435-440`) destructure `&mut Console`; after stage 1 they destructure
through `rt`, and neither calls `pick`, so neither needs the handle. `read_test`
(`menu.rs:744-799`) calls `pick` at `:749` **before** it starts borrowing `console` mutably in
the drain loop, so a borrow is fine there. No site has to clone the handle — `bundles::watch`
was the one that did, and stage 3 deletes it (§2.4).

**Every `bundles.rs` line number in this table is pre-stage-3 and several of these functions move
or vanish.** Stage 3 rewrites the landing screen and removes `Landing::Watch`, `BundleAction::Watch`,
`sync_note` and the whole watch screen; stage 5 deletes `sign_screen`. Re-derive this table by
grep at implementation time (§11.5).

Verify: `cargo test --release -p hc-console`; run the console, sit on the root menu, and confirm
the band row appears and the list below it does not shift.

### Step 6 — the band in the one surviving existing panel
`crates/hc-console/src/approval.rs`

- `serve_and_approve` (`:308-369`) gains `live: &Live`; `draw` (`:283-303`) gains the band
  line; tick before `:350`. Caller `menu.rs:931` passes it.

`bundles::watch` (`:691-761`) and `draw_watch` (`:649-685`) are **not** touched: stage 3 deletes
both (`03-bundle-autopoll.md` §10). An earlier revision of this step added a band to them, which
would have been reverted in the same release. Re-derive by grep at implementation time — after
stage 3 the second panel is gone and this step has one bullet, not two.

Verify: run `Serve and approve` with nothing incoming and confirm the panel repaints when a
background task publishes, with no keypress.

### Step 7 — the Status panel
`crates/hc-console/src/status.rs`, `crates/hc-console/src/menu.rs`

- `LogRing` (`:40-59`) gains `written: AtomicU64` and `written()`.
- New `Facts` struct: the entry-cached `read_dir` and `Keyring::load` results (§6.2), with
  `Enrollments` as an enum (§7).
- New `status::panel(console) -> Result<Step, MenuErr>` implementing §4.2 and §5.
- `menu.rs:498` dispatches to it.
- **Delete** `menu_enum!(StatusAction { ... })` (`menu.rs:292-297`).
- **Delete** `fn status_screen` (`menu.rs:897-912`).
- **Replace** `pub fn view(console: &Console) -> String` (`status.rs:112-224`). No shim, no
  reexport — the whole path is fixed.
- **Reword** `MenuChoice::Status`'s description (`menu.rs:155-158`); "Prompts for nothing" is
  false once the panel takes keys.
- Nothing in `next` (`menu.rs:190-206`) or its tests (`menu.rs:1034-1091`) changes — see §9.

Verify: sit on the Status screen with nothing configured and confirm it does not repaint at all
(no cursor flicker); with a remote configured, confirm it repaints on the cadence in §6.3 and not
faster; trigger a background push from another terminal and confirm the backup line changes with
no keypress; press `[r]` after adding a key from a second console and confirm the keystore count
moves; press `[q]`, then ctrl-c from the panel, then force an `io::Error` mid-repaint (resize to
one row), and confirm the shell is in cooked mode with a visible cursor after each — that is
`RawScreen`'s `Drop` doing its job on all three paths (§5.1).

### Step 8 — the `[p]` fetch

No writers to wire: stages 2 and 3 already write their own status, and the console's three
`backup::push_all` sites become stage 2's git push, which records itself (§1.5).

What remains is the §5.3 trigger, which is stage 2's to provide and stage 4's to consume:

- Stage 2 provides the fetch-wanted channel, the third `select!` arm, the `fetching` marker and
  the pre-merge `Relation` semantics — all four are specified in `02-git-store.md` §4.0, so this
  step wires rather than negotiates.
- The panel's `[p]` sends on `live.fetch_wanted`, ignoring the `Err` that means the task is gone;
  the band and the panel show `fetching` immediately and the result when the task publishes.
- Stage 3's `poke` is used unchanged by whatever already calls it
  (`03-bundle-autopoll.md` §6); stage 4 adds no new poke and binds no bundle key (§5.3).

Verify: from the Backup screen, push to a remote that is deliberately unreachable, back out to
the root menu, and confirm the band shows `push FAILED …` without a keypress and the log tail on
the Status panel names the typed `GitErr`.

---

## 9. Deletion list

Everything stage 4 makes dead, with `file:line` as of this writing.

| What | Where | Why |
|---|---|---|
| `menu_enum!(StatusAction { Refresh, Back })` | `menu.rs:292-297` | The panel repaints itself; `Back` becomes `[q]`. Both variants and the whole macro invocation go. |
| `fn status_screen` | `menu.rs:897-912` | Replaced by `status::panel`. |
| `pub fn view(console: &Console) -> String` | `status.rs:112-224` | Replaced by the panel renderer. Its `read_dir` (`:115`) and `Keyring::load` (`:125`) move behind `Facts`; its `"unreadable"` string (`:146`) becomes an enum variant. Delete, do not keep alongside. |
| `MenuChoice::Status` describe text | `menu.rs:155-158` | "Prompts for nothing" is false. Reword, not delete. |
| ~~`Serving::Live { addr, .. } => format!("https://{addr}")`~~ | `status.rs:151` | **Not deleted — corrected.** Stage 1 collapses **two** sites (`menu.rs:472`, `approval.rs:291`) into one `Display for Serving`, and deliberately keeps `status.rs:150-153`'s own `match` because its `Refused` arm at `:152` is a full sentence ("refused, this session may not release keys off-process"), not the terse label (`01-runtime-unification.md` §7f). The rewritten panel keeps that sentence. Stage 4 must not reintroduce a third format in the band. |

The complete symbol list, checked by grep: `StatusAction` appears at `menu.rs:292, 901, 903, 907`
and nowhere else in the workspace; `status::view` at `menu.rs:899` only. `MenuChoice::Status`
**survives** — it is still an option in `root_screen` (`menu.rs:515`), so `next`'s
`(_, MenuChoice::Status)` arm (`menu.rs:203`), its `Display` arm (`:115`) and its `describe` arm
(`:155-158`) all stay, and the menu tests (`menu.rs:1041-1091`) need no amendment. The only
producer that dies is `status_screen`'s Refresh arm (`menu.rs:903-906`).

**Not stage 4's to delete, but blocked on it or blocking it:**

- `bundles.rs:286` — `sync_note(&sync::pull(Scope::All))` runs a blocking sync on every render
  of the bundle landing screen. Stage 3 deletes it (`03-bundle-autopoll.md` §6, §10). Until it
  does, the landing screen synchronously pulls while the band claims the last poll was 28 s ago,
  which is self-contradicting. Note in the commit; do not delete it here.
- `bundles.rs:616-685` (`WatchView`, `draw_watch`) and `:687-761` (`fn watch`) — stage 3 deletes
  the whole watch screen (`03-bundle-autopoll.md` §10). Stage 4 must **not** add a band to it
  (§2.4, step 6). Listed here because an earlier revision of this plan did.
- `hc-daemon/src/backup.rs:249-269` — `push_all`'s unconditional `Ok(())`. Stage 2 deletes the
  whole module (`02-git-store.md` §7, §8.6) and replaces it with `git_store.rs`, which records
  per-remote outcomes in `GitStatus`. Under this revision stage 4 no longer needs a fix to
  `push_all`'s *return value* — the per-remote record is what the band reads — but it does need
  `git_store.rs` to exist, so the ordering dependency stands.

---

## 10. Tests

Per `CLAUDE.md`: only new non-trivial logic and crucial invariants. Rendering is not testable
without a tty and this plan does not pretend otherwise — there is no golden-frame test, no fake
terminal, no assertion that `crossterm::execute!` was called.

**New — one test:**

`the_band_keeps_its_chips_in_place` in `hc-console/src/status.rs`. Purpose, one sentence: a chip's
presence must depend on configuration alone, never on its value, or the band shifts sideways
under an operator who is reading it.

An earlier draft proposed `band_names_every_bad_state`, asserting the exact text of every chip
and every `age` bucket. Most of that is a golden test of `format!` and a chain of `>=`, which
`CLAUDE.md` calls out by name as waste — it would need editing every time a label is reworded,
and it would fail for reasons nobody cares about. The property that is genuinely non-trivial, and
the only one whose violation is invisible in a screenshot, is the no-jitter rule: for a fixed
configuration, every `BandSource` — healthy, failed, never-run, mid-flight — must produce a band
with the **same chips in the same order**, differing only in each chip's text. Assert on the chip
*keys* (`split(" · ")` then the leading word), not on the rendered values.

Two `age` boundaries are worth one line each inside the same test, because they are the boundary
where the string *length* changes and therefore where a repaint is triggered: `59s` → `1m` and the
saturating case where `then > now`. The other buckets are arithmetic.

**Amended — one test:**

`the_budget_pays_the_list_first_and_never_overdraws` at `pick.rs:524-561`. The anchor contract.
`chrome` gains `b.band`; the sweep gains a `band` dimension; the two whole-struct comparisons
gain the field; one case pins the MIN_FRAME ordering (§2.3). It must still prove
`page + room + chrome <= rows - start` for every terminal size, start row, option count **and
band height** — and it does catch a missing `left -= band`, which would make the sum `R + band`
at `band = 1` (derivation in §2.3).

**Deliberately not written:**

- `BandCache::tick` — a `String` inequality.
- The pending gauge — an `AtomicUsize` and a `Drop` impl. What would be worth testing is that a
  cancelled connection task decrements, and that needs a live tokio runtime plus a queue with no
  console behind it; it is `Drop`, and `Drop` runs.
- That `parking_lot` locks work, that `watch` channels wake.
- Any serde round-trip; nothing here is serialised.

---

## 11. Risks and open questions

1. **~~Stage 2 must grow a fetch trigger.~~ Closed — it is written into stage 2.** The
   four-item contract (fetch-wanted channel, third `select!` arm, `GitState.fetching`, pre-merge
   `Relation`) is now specified on stage 2's side at `02-git-store.md` §4.0, so it is built where
   the `spawn_blocking` boundary already is rather than retrofitted. What remains is an
   **ordering** hazard, not a design one: stage 2 must land with §4.0 in it. If stage 2 ships
   without item 3, the `fetching` marker and the `git fetching…` line silently become
   unrenderable and §5.3's fallback is the only option. Check `02-git-store.md` §4.0 exists in
   the delivered stage 2 before starting stage 4 step 8.

2. **~~The two epoch units disagree.~~ Closed by decision 12.** Both stages stamp `u64` Unix
   seconds from `hc_sign::grant::now_secs()` (§1.2). The one surviving `_ms` field is
   `PollStatus.last_took_ms`, an elapsed duration that stage 4 does not render and must never
   feed to `age`.

3. **~~`Relation::RemoteAhead` may be unobservable.~~ Closed.** `02-git-store.md` §4.0 item 4
   fixes `Relation` as the **pre-merge** relation, so `RemoteAhead` means "a fast-forward is due
   or in progress" and is observable whenever `fetching` is true or a merge has failed. The
   `store BEHIND` chip stays.

4. **Band overflow at 80 columns.** The all-broken case in §4.1 is 90 columns and gets `…`-clipped
   on an 80-column terminal — and the clip falls on `pending`, the chip most likely to need
   action. Options, none chosen here: (a) accept it, since the Status panel carries the full
   detail; (b) two-row band, which doubles the budget cost and complicates §2.3; (c) shorten the
   separator from ` · ` to two spaces, saving 4 columns, which is not enough on its own;
   (d) reorder chips so bad news is leftmost, which makes the band jitter and is worse.
   **Owner's call.** Recommendation: (a), and note it.

5. **22 `pick` call sites and six helper signatures is a merge-conflict magnet, and the table is
   already known to be stale.** Stage 3 rewrites the bundle landing screen and **deletes the
   whole watch screen** (`03-bundle-autopoll.md` §6, §10), and stage 5 deletes `sign_screen`;
   both touch `bundles.rs`. Every `bundles.rs` line number in step 5's table is therefore a
   pre-stage-3 number. Land stage 4 after both, as the design doc's ordering already says, and
   **re-derive the call-site table by grep at implementation time** rather than trusting the line
   numbers here. This is the largest remaining ordering hazard in the four-stage sequence.

11. **AUDIT — stage 3 justifies deleting `bundle watch` partly on a stage-4 feature this plan
    does not have.** `03-bundle-autopoll.md` §5 says the watch subcommand's unique behaviour —
    "stop once this bundle's threshold is met" — is fine to delete because "stage 4 puts arrivals
    and `met` on the console's live status". Stage 4 renders arrivals (band chip, Status panel
    line) but has **no per-bundle threshold state at all**: `BandSource` carries counts, not
    bundles, and the panel's bundle line is one aggregate row. Adding a `met` line is one derived
    boolean over `PollStatus.arrivals`, but it is a scope addition, not a reconciliation, so it
    is not written here. **Owner's call:** either stage 4 gains that line, or stage 3's rationale
    drops the `met` clause and its "What is lost" paragraph states the narrowing plainly. Flagged
    identically in `03-bundle-autopoll.md` §5.

6. **A process-wide `OnceLock<Live>` was considered and not chosen.** It would need zero
   changes to those 22 call sites, and `hc-daemon/src/approval.rs:10-13` already uses
   process-wide statics (`static PROMPT: Mutex<()>`, `static SHOWN: AtomicU64`), so it is not
   foreign to the codebase. It was rejected because the task's instruction is to follow the
   `Arc<LogRing>` pattern, and because a global makes any future test that touches the plumbing
   race. If the owner would rather have the smaller diff, this is the trade to revisit — the
   pure functions in step 4 are unaffected either way, since they take `&BandSource` by argument.

7. **The macOS `Instant`-during-sleep claim is unverified** (§1.7, reason 3). The wall-clock
   choice does not rest on it — reasons 1 and 2 are sufficient and verified, and stages 2 and 3
   have already made it — but do not repeat reason 3 as fact until someone confirms it on the
   target Mac.

8. **Absolute timestamps need a dependency that is not yet direct, and must be UTC.** §4.2 shows
   `(14:29:41)` stamps. `std` cannot format calendar time. `chrono 0.4.45` and `time 0.3.49` are
   in `Cargo.lock` transitively, so promoting one is cheap, but stage 4 as specified renders
   relative ages only. Ship it that way and add the stamps deliberately — in UTC, matching
   `tracing`'s default timer (§1.7's AUDIT) — or the panel ships with half a line rendered and
   the half it does render disagrees with the log beneath it.

9. **`serve_and_approve` reaches 6 arguments** (`api, approver, ops, addr, tunnels, live`).
   Under clippy's threshold of 7, so it compiles clean, but it is the signal `CLAUDE.md` warns
   about. Stage 1 does give five of them a home — `Runtime` (`01-runtime-unification.md` §1) holds `api`, `approver`,
   `serving` and `tunnels` — so take the struct instead of adding a sixth argument. The obstacle
   is the same borrow split `menu.rs:435-444` already performs, which is why this is a note and
   not a specified change.

10. **Nothing here was compiled.** Linux cannot build this workspace. Every line of sketched code
    is a specification, not a verified snippet. The line numbers in this file were re-verified
    against the working tree by reading it; the cross-plan citations (`02:…`, `03:…`) are line
    numbers in those documents, not in code.
