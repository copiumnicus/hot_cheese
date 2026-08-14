# Stage 3 — Background bundle polling from tailnet peers

Input: `00-design-decisions.md` (locked) and `CLAUDE.md` (binding). Stage 1's unified
`Runtime` is assumed to exist; §2 states exactly what this stage needs from it.

## 0. What changes

Today nothing in hot_cheese polls. Every `rsync` runs as a side effect of a foreground
verb (`hc-bundle/src/lib.rs:390,399,423,430,473,507,516,615`), and the only loops are
foreground ones a human is sitting in front of (`hc-cli/src/bundle.rs:291-316`,
`hc-console/src/bundles.rs:691-761`). `hc-bundle`'s own doc says so:
"Nothing here spawns or backgrounds anything" (`lib.rs:588-591`).

After this stage:

- One background thread, owned by the `Runtime`, pulls `Scope::All` from every enrolled
  peer on a config interval (default 30s), and pushes back only the bundles this device
  wrote a file into (locked decision 9 — this machine is not a relay).
- Ingest validation becomes **incremental**: a pass ecrecovers only the files whose
  on-disk identity changed since the last pass, not all 4096.
- Peer attribution becomes possible, because each peer's pull is validated on its own.
- The two foreground pollers are deleted.
- The caps that today only *report* a flood (`crowded`, `capped`) start *enforcing*,
  because a flood is now continuous and unattended.

Non-goals: no wire protocol, nothing listens, rsync-over-ssh stays the transport
(locked decision 4), no change to the union-merge model.

---

## 1. Where the poller lives

### Crate placement

| Piece | Crate | Why |
|---|---|---|
| One tick's work (pull, validate, diff, push) | `hc-bundle` | It is bundle domain logic and must be testable without a thread, a clock, or a network. |
| The thread, the interval, the shared status | `hc-daemon`, new module `crates/hc-daemon/src/bundle_poll.rs` | Locked decision 1: "A single `Runtime` owns … the background tasks". |

This is the same split `Watch` already uses — "The loop belongs to the caller … Nothing
here spawns or backgrounds anything" (`hc-bundle/src/lib.rs:588-591`) — so the crate
boundary does not move, only the caller does.

### The dependency and the cycle check

`hc-daemon/Cargo.toml` gains `hc-bundle.workspace = true`.

Verified from the workspace manifests:

```
hc-core    -> (no internal deps)
hc-sign    -> hc-core
hc-bundle  -> hc-core, hc-sign
hc-daemon  -> hc-core, hc-sign            [+ hc-bundle, new]
hc-console -> hc-bundle, hc-core, hc-daemon, hc-sign
hc-cli     -> hc-bundle, hc-console, hc-core, hc-daemon, hc-sign
hc-mcp     -> hc-bundle, hc-core, hc-sign
```

`hc-bundle` depends on `hc-core` and `hc-sign` only; neither depends on `hc-daemon`.
**No cycle.** `hc-console` and `hc-cli` already depend on both crates, so nothing
downstream changes shape.

### Getting a blocking thread

The tick shells out to `rsync` and `ssh` (`sync.rs:200-210,215-239`), reads and
JSON-parses files, and ecrecovers secp256k1 signatures (`ingest.rs:129-158`). None of
that may sit on a tokio worker.

It runs on a plain `std::thread`, **not** `spawn_blocking`:

- `hc-bundle` has no tokio dependency and must not gain one.
- The loop is long-lived. `spawn_blocking` tasks occupy a pool slot for their whole
  life, and the daemon's pool already carries the sign path (`hc-daemon/src/lib.rs:842`,
  `spawn_blocking(move || execute(..))`) and the post-mutation backup rsync
  (`hc-daemon/src/lib.rs:797`). A permanently-parked slot is exactly the starvation
  `CLAUDE.md`'s rayon rule is about.
- A dedicated thread gives free shutdown: the loop blocks in
  `Receiver::recv_timeout(interval)`, so dropping the sender ends it with
  `RecvTimeoutError::Disconnected`. No second signal handler, no watch channel.

### What this stage needs from stage 1's `Runtime`

Three things, and nothing else:

1. A field to own `Arc<BundlePoll>` plus the `JoinHandle<()>` and the request
   `SyncSender`, constructed once at startup for both renderers.
2. Shutdown ordering: drop the request sender, then `join()` the thread, before the
   process exits.

   **The naive join is unbounded, and the first draft of this plan got its bound wrong.**
   It claimed a join costs at most `CONNECT_TIMEOUT_SECS` (5s, `sync.rs:36`) per peer and
   that this matches the console's `SHUTDOWN_GRACE`. Both halves are false. `SHUTDOWN_GRACE`
   is **2s** (`hc-console/src/lib.rs:37`) and it bounds the tokio runtime's in-flight
   *connections*, not a thread join. And `ConnectTimeout` bounds only the ssh **connect**:
   once a peer has answered, nothing in `flags()` (`sync.rs:169-177`) or `run_rsync`
   (`sync.rs:200-210`) bounds the transfer, so a peer that answers and then stalls holds
   `Command::output()` forever. A join placed in the shutdown path would hang the process
   on a peer's whim.

   So the loop checks for disconnect **between peers**, not only at the top of the tick:
   one peer's in-flight `rsync` is the most that shutdown ever waits on, and the tick
   abandons the remaining peers. Shutdown then `join`s with a deadline of `SHUTDOWN_GRACE`
   and, if it expires, stops waiting and lets the process exit; the `rsync` child dies with
   its parent's process group exactly as `bundle watch`'s doc already relies on
   (`hc-cli/src/bundle.rs:289-290`). This is the one place the plan trades a clean join for
   a bounded exit, and it is deliberate: an unreachable peer must not be able to prevent
   the daemon from stopping.

   *AUDIT: an overall wall-clock timeout on `run_rsync` would fix this properly and would
   also bound a foreground `bundle sync`, which has the same hang today. It is out of this
   stage's scope because it changes `sync.rs`'s transport contract; raise it separately.*
3. `&Arc<BundlePoll>` reachable from both renderers, so the terminal renderer can render
   its status and poke it, and the headless renderer can log it.

The poller does **not** need the approver, the store lock, `LaContext`, or any key
material. `hc-bundle` reaches no key at all (`lib.rs:17-20`); ingest is a pure data
write. So the poller can never contend with the main-thread approver.

It also never touches the store, so it needs no store lock and nothing it writes can land
in stage 2's git repo: everything it reads or writes is under `bundles_dir()` =
`home_dir()/bundles` (`hc-core/src/config.rs:249-251`) or `bundle_quarantine_dir()` =
`home_dir()/bundle-quarantine` (`config.rs:255-257`), while the store is
`Config::store_path()`, a separate config key. Nothing the poller holds is `!Send`: its
state is `HashMap`/`HashSet` of `B256`/`Address`/`String`.

---

## 2. Incremental validation — the crux

### The cost problem, restated with evidence

`sync::pull` ends in `ingest::validate(scope)` (`sync.rs:287-291`). `validate`
(`ingest.rs:175-211`) walks every bundle directory in scope, and for every `*.json` file
calls `judge` (`ingest.rs:129-158`), which stats it, reads it, `serde_json`-parses it,
recomputes `bundle.digest()`, and then calls `SafeTxBundle::add` once per signature —
an ecrecover each. Bounded only by `MAX_INGEST_FILES = 4096` (`ingest.rs:34`).

At `Scope::All` on a 30s interval that is O(all bundles × all signatures) secp256k1
recoveries every 30s, forever, on one thread, to learn about the handful of files rsync
actually wrote. It must become incremental.

### Option A — parse rsync's own change list

I tested this against rsync 3.4.1 rather than guessing.

`rsync -az --exclude=safes.toml --exclude='*.hctmp' --out-format='%i %n' --max-size=65536 SRC/ DST/`

emits one line per changed entry on **stdout** (already captured by `Command::output()`
at `sync.rs:201`), exit status unaffected:

```
cd+++++++++ 0xaaa/                 <- directory created
>f+++++++++ 0xaaa/0x1111.json      <- file transferred, new
>f..t...... f.json                 <- file transferred, mtime differed
.d..t...... 0xaaa/                 <- directory, only its mtime changed
```

`%i` is a fixed 11-character field `YXcstpoguax`, then one space, then `%n`, the path
relative to the destination root. A second run over an unchanged tree prints **nothing**
— the list is exactly "what changed", which is what we want. `-i` alone (no
`--out-format`) prints the same itemize plus a `./` row.

Three findings that decide against it:

1. **The filenames are escaped, and a peer chooses them.** Re-verified against rsync
   3.4.1 with real control characters in the names, `%n` emitted:

   ```
   >f+++++++++ 0xaaa/we ird\#012name.json     <- name held a literal newline
   >f+++++++++ 0xaaa/back\#134slash.json      <- name held a literal backslash
   >f+++++++++ 0xaaa/tab<TAB>here.json        <- a tab is NOT escaped
   ```

   A newline becomes `\#012` and a backslash becomes `\#134` — the escape is `\#` plus
   three octal digits, not the doubling an earlier draft of this section claimed. `-i`
   alone, `--out-format='%i %n'` and `--8-bit-output` all produce identical text. So
   parsing `%n` back to a path means writing an un-escaper for an undocumented octal
   escape format, applied to an attacker-chosen string, to decide which files to
   security-check. Any bug there is a validation bypass. Worse, the escape is applied
   selectively — a tab survives raw — so a name can carry whitespace that no fixed-offset
   split and no `split_whitespace` handles correctly. This is the worst possible place for
   a hand-rolled parser.

2. **It raises the rsync floor.** `--out-format` is a rsync 3.x spelling (2.6.x has
   `--log-format`), and hot_cheese runs natively on macOS, where `/usr/bin/rsync` has
   historically been 2.6.9 and on recent releases is openrsync. An unknown option makes
   `rsync` exit non-zero, and `run_rsync` (`sync.rs:200-210`) turns that into
   `SyncErr::RsyncFailed`, i.e. **sync stops working entirely**. I could not verify the
   macOS binaries from this machine, and I will not build a security-critical path on an
   unverified flag when a flag-free alternative exists.

3. **It is not crash-safe.** rsync writes the file, then the process is killed before
   `validate` runs. Next tick, rsync sees the file already present and up to date and
   says nothing about it — so it is never judged, and `load_dir` (`lib.rs:236-274`) then
   refuses the whole directory forever. That is precisely the denial-of-service
   `ingest.rs:1-16` exists to prevent, made permanent.

### Option B — an mtime watermark

Rejected on evidence. `-a` implies `-t`, so rsync preserves the **sender's** mtime.
A hostile peer sets a file's mtime to 1970 and it is never re-validated. Dropping `-t`
is worse: rsync's quick check is size+mtime, so without it every file is re-transferred
every tick.

Both halves re-verified against rsync 3.4.1, not assumed:

- `touch -t 197001020304 src/f.json` then `rsync -az src/ dst/` leaves `dst/f.json` with
  mtime `97440`, byte-identical to the sender's. The peer sets our mtime.
- With `dst/f.json` holding `AAAA` and `src/f.json` holding `BBBB` at the same size and
  the same forced mtime, `rsync -azi src/ dst/` prints **nothing** and `dst/f.json` still
  reads `AAAA`. Same size + same mtime ⇒ skipped, content ignored. `--checksum` notices
  (`>fc........`), at the price of hashing the whole tree every tick.

mtime is a peer-controlled input, not a local fact.

### Option C — a per-file identity record. **This is the design.**

Key on the local file identity that only the local kernel can set:

```rust
/// Identity of the exact bytes a pass judged. Every field is set by the local kernel on
/// write, so nothing a peer sends can forge a match.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileId {
    /// Inode; rsync writes a temp file and renames, so a replacement is a new one.
    ino: u64,
    /// Inode change time, which a rename or a write always advances.
    ctime: i64,
    ctime_nsec: i64,
    len: u64,
}
```

`std::os::unix::fs::MetadataExt` supplies all four on macOS.

`ctime` is the load-bearing choice: `mtime` is whatever the peer sent, `ctime` is when
*this* kernel last changed the inode, and no userspace API sets it. `ino` catches
replacement, `len` catches the case of a same-inode in-place rewrite, and the three
together make an accidental collision require an attacker to control local inode
allocation *and* hit a nanosecond.

**Can a peer change the bytes without changing all four?** Checked, not assumed:

- rsync's default update strategy is temp-file-plus-rename, so the destination gets a
  *new* inode on every write. Reproduced: overwriting `f.json` through `rsync -az` moved
  the destination from ino `69993543` to `69993544` and advanced ctime by 110 ms.
- `--inplace`, `--append` and `--append-verify` would defeat `ino`, and none of them is in
  the argv: `flags()` is exactly `-az`, two `--exclude`s and `-e ssh …`
  (`sync.rs:169-177`), plus `--max-size` on the pull (`sync.rs:191`). The argv test
  (`sync.rs:482-523`) pins that list byte-for-byte, so a later `--inplace` cannot be added
  without failing a test. Even under `--inplace`, ctime still advances on the write.
- Inode-number reuse after an unlink is the only remaining route, and it must coincide with
  an identical `ctime_nsec` and an identical length. APFS allocates file IDs from a
  monotonically increasing counter, so it does not arise there; and the plan does not rest
  on that, because the ctime match is the part an attacker cannot arrange.

**The map is in memory only.** `Ingest` is never serialised and nothing on disk mirrors
it. That is deliberate: a persisted index would sit in the same tree a peer writes to, and
a peer who could edit it could mark unjudged bytes as judged. The cost is a full pass after
every restart, which §2's "First run" note already accepts and which is exactly today's
behaviour.

```rust
/// What a previous pass already judged, so the next pass ecrecovers only what changed.
pub struct Ingest {
    /// Identity of the last accepted bytes at (bundle digest, file name).
    seen: HashMap<(B256, String), FileId>,
    /// Bundle directories a previous pass has already accounted for.
    dirs: HashSet<B256>,
    /// False until the first pass has taken stock of the tree that was already here.
    primed: bool,
    /// Files currently sitting in the quarantine tree.
    quarantined: usize,
}

impl Ingest {
    pub fn new() -> Self;
    pub fn validate(&mut self, scope: Scope) -> Result<Verdict, IngestErr>;
}
```

Per pass, for each directory in `dirs(scope)` (`ingest.rs:85-110`, unchanged), for each
`*.json` file:

1. `open` the file **once**. Take `FileId` from `File::metadata()` on the open handle. The
   handle, not the path: everything afterwards then describes one inode, so a concurrent
   replacement cannot make us record the identity of bytes we did not read.
2. If `seen[(hash, name)] == id`, skip. **Nothing is read.** No parse, no digest, no
   ecrecover.
3. If `id.len > MAX_FILE_BYTES`, `Reject::Size` — still without reading. This ordering is
   not cosmetic: today `judge` stats before it reads (`ingest.rs:134` before `:137`), and
   reading first would let one oversized file in the tree be slurped into memory by a
   background thread every time it changed.
4. Otherwise read the bytes from the open handle and run the existing `judge` logic. On
   `None`, record `seen[(hash, name)] = id`. On a `Reject`, quarantine and record nothing.
5. Build the pass's map from what the pass saw and swap it in, which prunes entries for
   files that no longer exist (`bundle rm` at `lib.rs:548-560`, a quarantine) with no
   extra bookkeeping. That is also what bounds the map: it can never hold more entries
   than the tree holds files, which §7's caps bound.

`judge`'s current signature `fn judge(path, name, hash)` (`ingest.rs:129`) changes to take
the bytes the caller already read: `fn judge(bytes: &[u8], name: &str, hash: B256) ->
Option<Reject>`. It takes no `len` — `bytes.len()` is the same number, and a parameter that
restates an argument's own field is the boilerplate `CLAUDE.md` bans. The size check moves
out to step 3 with the rest of the io. Note it loses its `Result`: with the io gone,
nothing in it can fail. Its existing test (`ingest.rs:223-309`) is rewritten to pass bytes;
every case it pins survives unchanged except `Reject::Size`, which moves to the caller and
is asserted there.

#### Why C beats A on every axis that matters

| | A (parse itemize) | C (identity record) |
|---|---|---|
| Trusts attacker-chosen strings from a subprocess | yes | no |
| New rsync flag / version floor | yes, unverified on macOS | none; argv is byte-identical |
| Survives a crash between transfer and validation | no, permanent hole | yes, self-heals |
| First run | needs a special "have I ever done a full pass" flag | falls out: empty map ⇒ full pass |
| Peer added later | needs the same flag | nothing to do; the map is keyed on local paths, not peers |
| A file changed by something other than rsync | invisible | caught |
| Per-peer attribution | needs one rsync per peer anyway | needs one rsync per peer anyway |
| Steady-state cost | O(changed) | O(files) `open`+`fstat` + O(changed) ecrecover |

The one thing A wins is that it avoids the metadata walk. That walk is not a cost worth a
parser, and C is strictly cheaper than today per file, not merely comparable: today
`judge` does `metadata(path)` then `read(path)` — a `stat`, an `open`, a `read` and a
`close` — for **every** file (`ingest.rs:134,137`). C does `open` + `fstat` + `close` for
an unchanged file and adds the read only when the identity moved. So C removes a syscall
per unchanged file as well as the parse, the digest and every ecrecover. 4096 warm
`open`/`fstat` pairs is a few milliseconds, once per 30s, on a background thread.

#### First run, restart, and a peer added later

- **First run / restart.** `Ingest::new()` has an empty map, so pass one judges
  everything — exactly today's `validate(Scope::All)`. The `primed` flag is set at the
  end of that pass; see §7 for what it gates.
- **Peer added later.** Nothing special. The map is keyed on local paths. Whatever the
  new peer writes is new or changed locally and is therefore judged.
- **Bytes a peer re-sends identically.** rsync skips them, the local inode is untouched,
  the identity matches, and we do not re-judge. Correct: they are the bytes we already
  judged.
- **Our own writes.** `write_one` (`lib.rs:362-368`) goes through `atomic_write`, which is
  `fs::write` to a `*.hctmp` then `fs::rename` over the destination
  (`hc-core/src/crypto/envelope.rs:313-318`), so our own new signature has a new inode and
  gets judged once. One wasted ecrecover per local signature, and it keeps the invariant
  "everything in the tree has been judged" free of exceptions.

---

## 3. The interval

`Config::bundle_watch_secs()` already exists (`config.rs:283-285`), reading the
`bundle_watch_secs` TOML key with a default of 15.

**Keep the key name. Change the default to 30. Clamp the floor.**

```rust
/// Seconds the background poller waits between ticks.
const MIN_BUNDLE_POLL_SECS: u64 = 5;
const DEFAULT_BUNDLE_POLL_SECS: u64 = 30;

pub fn bundle_watch_secs(&self) -> u64 {
    self.bundle_watch_secs
        .unwrap_or(DEFAULT_BUNDLE_POLL_SECS)
        .max(MIN_BUNDLE_POLL_SECS)
}
```

- The key is **not** renamed. `Config` has no `deny_unknown_fields` (`config.rs:11-12`),
  so a rename would make an operator's existing `bundle_watch_secs = 20` silently
  ignored. A silently ignored interval is exactly the class of bug this repo refuses.
  The name still says what it now configures.
- The default moves 15 → 30 because the poller is continuous and unattended rather than
  a screen someone is staring at; halving the ssh handshakes matters more than five
  seconds of latency.
- The floor exists because `bundle_watch_secs = 0` would otherwise spin `rsync`
  subprocesses as fast as ssh can connect. 5s matches `CONNECT_TIMEOUT_SECS`
  (`sync.rs:36`), so a tick can never be scheduled faster than one peer's own timeout.

**One interval, one subsystem.** This interval covers bundle polling and nothing else.
Stage 2's git-store fetch is a separate background task with its own cadence, its own
failure surface and a completely different cost profile (`git fetch` against a bare repo
vs. `rsync` against N laptops). Sharing a knob would make one of them wrong.

**Re-read per tick.** The tick opens with **one** `Config::load()` and takes both
`bundle_watch_secs` and `bundle_peers` from it. This preserves the property the hazard list
requires — enrolment changes take effect without a restart (`sync.rs:241-252`) — and
extends it to the interval, so `peer add` and a retune both land at the next tick.

The poller does **not** call `enrolled()` (`sync.rs:244-252`) and that function does not
become `pub`: it exists to give the aggregate `each_peer` loop a fresh list, the poller
drives peers one at a time (§4), and routing through it would mean a second TOML parse per
tick and a `tracing::warn!` where the poller wants a typed value. `enrolled()` stays
private and unchanged, still serving `pull`/`push`/`sync_now` and `peer_list`. If the
poller's own load fails, the `ConfigErr` becomes `PollErr::Config` in `PollStatus.failure`,
the poller keeps its last known interval, and no peer is contacted that tick — the same
outcome `enrolled()` produces, but visible in the status instead of only in the log.

**When a tick runs long.** The loop is:

```
loop {
    tick();
    match requests.recv_timeout(interval) { ... }
}
```

The wait starts when the tick *finishes*, so ticks never overlap and never pile up. The
effective period is `interval + tick_duration`. This is deliberate: a tick runs long
precisely because peers are slow or unreachable, and the correct response to a slow peer
is not to start a second `rsync` against it. Fixed-rate scheduling with catch-up is
rejected for that reason. `last_took_ms` in the status makes the drift visible.

---

## 4. What one tick does

```rust
// crates/hc-bundle/src/poll.rs
/// One machine's view of the bundle tree between ticks.
pub struct Poller {
    ingest: Ingest,
    /// Signers each bundle held at the previous tick, so a tick can name what arrived.
    seen: HashMap<B256, HashSet<Address>>,
    /// Bundles this device wrote a file into, and the only ones a tick pushes.
    contributed: HashSet<B256>,
}

impl Poller {
    /// Prime from what is already on this disk, judging it once, without touching a peer.
    pub fn start() -> Result<Self, PollErr>;

    /// Record that this device wrote a file into a bundle, so the tick may push it.
    pub fn contributed(&mut self, hash: B256);

    /// Pull from one peer, judge only what that pull changed, and name what arrived.
    pub fn pull_from(&mut self, peer: &BundlePeer) -> PeerTick;
}

/// What one peer's half of a tick did.
pub struct PeerTick {
    /// The one `Scope::All` pull.
    pub pull: Result<(), SyncErr>,
    /// Every contributed bundle pushed to this peer: the first failure, or `Ok` for all.
    pub push: Result<(), SyncErr>,
    /// Bundles pushed to this peer this tick.
    pub pushed: usize,
    pub arrivals: Vec<Arrival>,
    pub verdict: Verdict,
}
```

Per tick, in order:

1. `Config::load()`. Take `bundle_watch_secs` and `bundle_peers`.
2. **For each enrolled peer, in `config.toml` order** (not concurrently — one thread,
   and a serial order makes attribution exact), checking for shutdown between peers:
   a. `sync::pull_from(peer, Scope::All)` — one `rsync`, argv unchanged.
   b. `ingest.validate(Scope::All)` — incremental, so this costs only what *this peer*
      just wrote.
   c. Diff loaded signers against `self.seen` to produce `Arrival`s.
   d. For each hash in `self.contributed`, `sync::push_to(peer, Scope::One(hash))`.
3. Publish the assembled `PollStatus` under the lock.

**Pull scope: `All`.** `Scope::One(hash)` can only fetch a directory whose digest we
already know, and the entire point of polling is to learn about a bundle a co-signer just
created and we have never seen. `Scope::All` is the only scope that can do that.

**Push scope: only what we wrote — locked decision 9.** A periodic `push(Scope::All)`
would make this machine an automatic relay: a bundle peer A injected into us would be
pushed on to peer C, unattended, 2,880 times a day. Decision 9 rules that out — "This
machine never redistributes, unattended, something a hostile peer injected" — so the tick
pushes `Scope::One(hash)` for the digests in `Poller::contributed` and nothing else.

`contributed` holds exactly the bundles **this device wrote a file into**:

- fed by `Poke::Push { hash }`, which the console's `new`, `collect` and `merge` send
  after the write returns (§6), and by nothing else;
- **never** fed from a pull, from `Ingest`, or from what a directory happens to contain;
- empty at startup, so a restarted daemon pushes nothing until this device writes again.

*AUDIT: `hc_bundle::new` writes a seed carrying no signature, and decision 9's words are
"contributed a signature to". A bundle we created but have not yet signed still has to
reach its co-signers, so the seed is included here. This is a widening of decision 9's
letter, never of its intent — a seed we authored is not something a peer injected. Flagged
for the repo owner rather than decided silently.*

**Convergence without a relay, stated as an argument rather than a hope.** Every device
pulls `Scope::All` from every enrolled peer every tick, and the union merge is commutative
and idempotent (locked decision 4, tested in `crates/hc-sign/src/bundle.rs`), so a
signature reaches every device that has a pull edge to the device that wrote it. The push
in step 2d is therefore **not** what makes the system converge; it only shortens the window
for a peer that is awake and idle. Convergence rests on the pull.

The cost, stated plainly: **enrolment must be mutual, and it is now load-bearing.** If B is
enrolled with A but A is not enrolled with B, A's signatures still reach B (B pulls) but
B's never reach A. Before decision 9 a third machine enrolled with both would have relayed
around that hole; now nothing does. `bundle peer list` already shows which side of an
enrolment exists (`sync.rs:324-353`, `orphans`), and the README's peer section must say
that both machines run `bundle peer add`.

**Direction: pull then push.** Pull first is the established ordering (`sync.rs:299-306`)
— what we send then already includes what they had.

A push writes nothing locally, so it costs zero validation. Its marginal cost is one ssh
handshake and file-list exchange per contributed bundle per peer per tick; `contributed` is
bounded by how many bundles this operator has personally signed since the daemon started,
which is a human-scale number.

---

## 5. Interaction with the foreground

Two foreground pollers exist today. Both are superseded, and `CLAUDE.md` says dead paths
are deleted, not left alongside.

### `hot_cheese bundle watch` — **delete**

`hc-cli/src/bundle.rs:85-89` (the subcommand), `:158` (dispatch), `:289-317` (the
`loop { poll; thread::sleep }`).

Rationale:

- It is a second poller in a second process against the *same* tree. Both would run
  `rsync` against the same peers, and both would race on `std::fs::rename` in
  `quarantine` (`ingest.rs:161-171`) — one process can rename a file out from under the
  other's `judge`.
- Its incremental map would be per-process and cold on every start, so it would ecrecover
  the whole tree on launch and then duplicate the daemon's work forever.
- Its remaining unique behaviour — "stop once this bundle's threshold is met"
  (`bundle.rs:310-313`) — is a notification, and §8's `PollStatus` publishes the arrivals it
  would have watched for.

  > **AUDIT — one clause of this rationale is not backed by stage 4.** `04-live-status.md` reads
  > `PollStatus.arrived` / `quarantined` / `last_finished_at` for its band and Status panel, and
  > renders **no per-bundle threshold state**: there is no `met` anywhere in stage 4. So a
  > `bundle watch <hash>` user who wanted "tell me when THIS bundle reaches its threshold" is
  > served by the bundle list screen's existing per-bundle view, not by a live notification.
  > That is a narrowing, and the "What is lost" paragraph below should say so rather than lean
  > on a stage-4 feature nobody has planned. Either stage 4 grows a `met` line — it is one
  > derived boolean over `PollStatus.arrivals`, and it needs an owner's decision, not a
  > guess — or this bullet drops the `met` claim. Flagged in `04-live-status.md` §11 too.

What is lost, stated plainly: an operator running *only* CLI subcommands, with neither
`hot_cheese` nor `hot_cheese serve` up, has no poller. `hot_cheese bundle sync`
(`bundle.rs:80-84,152-157`) remains as the scriptable one-shot exchange, and
`bundle list` / `bundle status` keep their own `SyncMode::On` pull (§6), so that
operator is exactly where they are today, minus the waiting loop.

### The console watch screen — **delete**

`hc-console/src/bundles.rs:616-685` (`WatchView`, `draw_watch`), `:687-761` (`watch` and
its doc), plus the two menu entries that reach it (`:72-74`, `:115`, `:125`, `:140-143`,
`:307`, `:335`, `:363`) and the constants they use (`:48` `TICK`, `:51` `MAX_ARRIVALS`).

Nothing in `menu.rs` is touched: the watch screen is reached from inside
`bundles::screen`, never from the menu state machine, so `MenuState`, `MenuChoice`,
`next()` and their tests (`menu.rs:1041-1091`) hold no `Watch` arm and are unaffected.
Verified by grep — the only `Watch` identifiers outside `hc-bundle` are in
`hc-cli/src/bundle.rs` and `hc-console/src/bundles.rs`.

Rationale:

- Its whole content — bundles watched, the peer line, an arrivals ring, "syncing…" — is
  a strictly poorer view of `PollStatus` (§8), which stage 4 renders on every screen.
- Its second job, draining queued approvals while the operator waits, is **not** lost.
  `menu::run` already calls `service_pending` on every pass of the outer loop
  (`hc-console/src/menu.rs:375`), and the Serve-and-approve screen exists as a place to
  sit (`MenuState::ServeAndApprove`, `menu.rs:85,116,159`). The watch screen's drain
  (`bundles.rs:719-733`) is a duplicate of that.
- It is a raw-mode screen that repeatedly toggles `disable_raw_mode` / `enable_raw_mode`
  around the drain (`bundles.rs:719-722`). Deleting it removes that whole hazard.

**What stage 3 must leave behind so nothing is lost before stage 4 lands:** the bundles
landing screen (`bundles.rs:285-338`) renders one line from `PollStatus` in its header —
last tick age, peers reached, arrivals since the session started, quarantined count — in
place of the `sync_note(&sync::pull(...))` line it prints today. That is a static read of
the shared struct, no polling, and stage 4 turns it live.

### `hc_bundle::Watch` — **delete**

`lib.rs:587-642`. `Watch`, `Watch::start`, `Watch::watching`, `Watch::poll`,
`Watch::take_stock`. `Arrival` (`lib.rs:573-585`) **stays**: it is the poller's output
type and the status's ring element. `HashSet` stays imported (`lib.rs:28`) — `Poller`
uses it — but check whether `loaded()` (`lib.rs:306-321`) still has a caller once
`Watch::poll` and `Watch::start` are gone; `Poller` should take it over rather than let it
go unused.

---

## 6. Sync triggers — every one, and its fate

The rule: a pull inside a library verb stays, because `hc-bundle` is also used by
processes that have no Runtime (`hot_cheese_mcp`, plain CLI subcommands). What changes is
what the *console* asks for, because in the console every pull is now redundant. That is
exactly what `SyncMode` is for and it already exists, so no shim and no new switch.

### Library level — `crates/hc-bundle/src/lib.rs`

| Line | Trigger | Fate |
|---|---|---|
| `:390` | `new` → `sync.push(One)` | **stays** — a proposal a co-signer cannot see is half a proposal |
| `:399` | `intent_to_sign` → `sync.pull(One)` | **stays** — a CLI-only machine may never have seen the bundle |
| `:423` | `collect` → `sync.push(One)` | **stays** — immediate, `Scope::One`, cheap |
| `:430` | `status` → `sync.pull(One)` | **stays** |
| `:473` | `list` → `sync.pull(All)` | **stays** |
| `:507` | `merge` → `sync.push(One)` | **stays** |
| `:516` | `export` → `sync.pull(One)` | **stays** — this is the last moment before gas is spent |
| `:615` | `Watch::poll` → `sync.pull(scope)` | **deleted** with `Watch` |
| `:544-548` | `rm` deliberately never syncs | **unchanged**, and the comment stays true |

### Console — `crates/hc-console/src/bundles.rs`

| Line | Today | After |
|---|---|---|
| `:286` | unconditional `sync::pull(Scope::All)` on **every render** of the landing screen | **deleted.** Replaced by a header line read from `PollStatus`. This is the single worst trigger in the tree: it runs one rsync per peer every time the operator so much as returns to the list. |
| `:360` | `export(SyncMode::On, ..)` | `poke(Poke::AwaitTick)` then `export(SyncMode::Off, ..)` |
| `:376` | `intent_to_sign(SyncMode::On, ..)` | `SyncMode::Off` — the bundle was picked from a list the poller populated |
| `:386` | `collect(SyncMode::On, ..)` | `SyncMode::Off` + `poke(Poke::Push { hash })` |
| `:402` | `status(SyncMode::On, ..)` | `SyncMode::Off` |
| `:497` | `collect(SyncMode::On, ..)` | `SyncMode::Off` + `poke(Poke::Push { hash })` |
| `:508` | `merge(SyncMode::On, ..)` | `SyncMode::Off` + `poke(Poke::Push { hash })` |
| `:531` | `new(SyncMode::On, ..)` | `SyncMode::Off` + `poke(Poke::Push { hash })` |
| `:710` | `sync::pull(scope)` inside the watch screen | **deleted** with the screen |
| `:903` | Peers → Sync: `sync::sync_now(Scope::All)` | `poke(Poke::AwaitTick)`, rendering the tick's `PollStatus` |

**The write verbs must poke with the digest, not with a bare "tick now".** Flipping `new`,
`collect` and `merge` to `SyncMode::Off` deletes their `sync.push(Scope::One(hash))`
(`lib.rs:390,423,507`). Under decision 9 the tick pushes only what is in
`Poller::contributed`, so a detached poke that carried no digest would leave a freshly
signed bundle on this disk with nothing ever sending it — the peers would get it only if
they happened to pull. `Poke::Push { hash }` is what puts the digest into `contributed`
*and* asks for the push, in one message, and it is also what marks the directory as ours
for §7(b)'s cap. This was a real hole in the first draft, not a stylistic point.

Moving the console's writes to `Off` + `Poke::Push { hash }` is not just deduplication: today
those calls run `rsync` synchronously on the **main OS thread**, which is the thread that
owns the terminal and every approval (`hc-console/src/lib.rs:1-12`). A sleeping peer can
hold it for `CONNECT_TIMEOUT_SECS` per peer immediately after a Touch ID. After this
change the write returns as soon as the file is on disk.

`Poke::AwaitTick` is kept for exactly two operator-initiated verbs — Export and
Peers→Sync — where waiting is the point and where the operator already expects a pause.
It replaces a synchronous rsync that already blocked that thread, so it is not a
regression, and it cannot run concurrently with a background tick.

### CLI — `crates/hc-cli/src/bundle.rs`

| Line | Trigger | Fate |
|---|---|---|
| `:112-115` | `--no-sync` → `SyncMode` | **stays.** Its clap wiring (`hc-cli/src/lib.rs:178-185`) and its test (`lib.rs:1271`) are unaffected — the flag still reaches every bundle verb, and `Watch` simply stops being one of them. |
| `:153` | `bundle sync` → `sync::sync_now(scope)` | **stays** — the scriptable one-shot |
| `:301` | `watch.poll(mode)` | **deleted** with the subcommand |

### MCP — `crates/hc-mcp`

| Line | Trigger | Fate |
|---|---|---|
| `proposal.rs:27` | `list(SyncMode::Off)` | **stays.** `hot_cheese_mcp` is a separate binary with no Runtime, and the reason at `proposal.rs:22-24` — an agent may poll, and a sync costs 5s per peer — is still exactly right. |
| `proposal.rs:93` | `new(SyncMode::On, ..)` | **stays.** The MCP process may be the only thing running; it cannot assume a poller exists. |
| `tools.rs:430` | `list(SyncMode::Off)` | **stays** |
| `tools.rs:455` | `status(SyncMode::Off)` | **stays** |

---

## 7. Untrusted writers under continuous polling

"Every reachable peer is an untrusted writer" (`sync.rs:16-17`); being on the tailnet
grants no authority (`tailnet.rs:8-10`). What changes at stage 3 is not the trust model
but the *duty cycle*: injection stops being something that happens while a human is
looking and becomes something that happens 2,880 times a day, unattended.

### What is bounded today, and what is not

| Bound | Where | Enforced? |
|---|---|---|
| 64 KiB per file | `--max-size` (`sync.rs:191`) and `Reject::Size` (`ingest.rs:134`) | yes, on the wire and on disk |
| 64 files per bundle directory | `MAX_FILES_PER_BUNDLE` (`ingest.rs:31`) | **no** — `Verdict::crowded` is a count (`ingest.rs:188-190`) |
| 4096 files per validation pass | `MAX_INGEST_FILES` (`ingest.rs:34`) | stops the pass, sets `capped` (`ingest.rs:192-195`) |
| number of bundle directories | — | **nothing at all** |
| size of the quarantine tree | — | **nothing at all** |
| **ecrecovers per file** | — | **nothing at all** |

So today a peer can create bundle directories at will, forever. Nothing gates directory
creation: rsync writes them, `dirs()` (`ingest.rs:85-110`) accepts any name that parses
as a `B256`, and no code path ever deletes one.

Two of these become *worse than unbounded* under a 30s poller:

- `capped: true` today is a transient thing a human sees on one screen. Under continuous
  polling it becomes a permanent state, and the files past the cap are **never judged**,
  so a peer can hold arbitrarily many bundle directories permanently unloadable by
  `load_dir` — the exact DoS `ingest.rs:1-16` was written to close.
- Re-pull churn. There is no `--delete` (`sync.rs:166-168`) and quarantine *moves the
  file out of the tree*, so rsync sees it missing and re-sends it next tick, forever.

I looked for a way to tell rsync "never fetch this path again" and there is not one that
holds up: `--exclude-from` would need a file whose length the attacker controls, and they
can cycle filenames anyway. **Re-pull churn is inherent to the transport.** The plan
bounds the harm rather than pretending to remove it.

### What the plan does

**(a) Bound the ecrecovers one file can cost. New, and the biggest hole in the tree.**

Every cap that exists today counts *files*. Nothing counts *signatures*, and `judge` runs
one ecrecover per signature in a file (`ingest.rs:143-156`). `SafeTxBundle::add` recovers
**first** (`hc-sign/src/bundle.rs:98`) and only then looks for a signature it already
holds — and a byte-identical repeat of a signature it already holds returns `Ok(())` and
lets the loop continue (`bundle.rs:109-113`). So a file that passes the `Misfiled` check
and then repeats one valid signature N times costs N ecrecovers and is **accepted**.

The arithmetic is bad: one `CollectedSignature` is roughly 215 bytes of JSON, so a 64 KiB
file holds about 300 of them, and 4096 such files is ~1.2M secp256k1 recoveries — minutes
of CPU per tick, against a 30s interval, on one thread. The incremental map stops the
*repeat* cost, but a peer who rewrites the files each tick pays only bandwidth for it, and
none of it trips §7(f)'s backoff, because none of it is a refusal.

The fix is exact and costs nothing, because the tree's own layout already forbids it:

```rust
/// A per-signer file carrying more than the one signature its name binds it to.
Stuffed,
```

`judge` refuses `Stuffed` on `bundle.signatures.len() > 1` for any `0x<addr>.json`, before
the recovery loop. **No legitimate writer produces such a file:** `write_one` only ever
writes what `take` built, which holds exactly one signature (`lib.rs:327-336`), `new`
writes a seed holding zero (`lib.rs:375-381`), and `merge` gives every incoming signature
its own file (`lib.rs:497-505`). The seed's zero-signature case is already covered by the
existing `Misfiled` rule. The worst case per file therefore drops from ~300 ecrecovers to
**one**, and `MAX_INGEST_FILES` becomes a real bound on validation cost rather than a bound
on file count alone.

**(b) Cap the number of bundle directories. New, enforced.**

```rust
/// Bundle directories this machine will hold. Beyond it, a directory that ARRIVED is
/// refused; one that was already here is never touched.
pub const MAX_BUNDLE_DIRS: usize = 64;
```

A directory is "arrived" iff its digest is absent from **both** `Ingest::dirs` and
`Poller::contributed`. On the priming pass (`primed == false`) nothing has arrived, so an
operator whose tree is already larger than the cap keeps every bundle they have — the cap
only ever refuses growth caused by a peer. A refused directory is `remove_dir_all`'d, not
quarantined: quarantining unbounded growth just relocates it. Its digest is recorded in
`Verdict::refused_dirs`.

**The `contributed` half of that test is not optional.** "Absent from `Ingest::dirs`" on
its own cannot tell a peer's new directory from one `hc_bundle::new` created three
milliseconds ago on this machine (`lib.rs:387`), so a tree sitting at the cap would have
the operator's brand-new bundle deleted by the next tick. `Poke::Push { hash }` (§6) puts
the digest into `contributed` before the poller can run, and a digest in `contributed` is
never refused and never removed.

Arithmetic: 64 dirs × 64 files × 64 KiB = **256 MiB ceiling** on a `bundles/` tree that has
been under the cap from the start, and 64 × 64 = 4096 = `MAX_INGEST_FILES` exactly, so such
a tree is fully covered by one pass. That equality does **not** hold for a grandfathered
tree: the cap deliberately never removes what was already there, so an operator arriving
with 200 directories keeps them, and their 12 800 files take several passes to cover — which
is exactly what (d) is for. Say it rather than let the "always one tick" line stand.

A const, not config, for consistency with its three siblings in the same module;
`mcp.max_pending` defaults to 16 (`config.rs:59`), so 64 is already four times the queue a
human is expected to read.

**(c) `MAX_FILES_PER_BUNDLE` starts enforcing — with a cost that must be stated.** Files
beyond the cap in one directory are moved to quarantine, **not deleted**, and counted in
`Verdict::refused_files`; quarantine is itself bounded by (e), so this cannot become
unbounded growth in a second location. Which 64 survive is decided deterministically:
`SEED_FILE` first, then everything already in `Ingest::seen` for that digest, then new
names in name order.

*AUDIT: this is the one place the stage weakens `ingest.rs:11-13`'s invariant, and the
first draft claimed the opposite. "Our own file is in `seen` from the moment `collect`
wrote it" is **false** — `seen` is populated only by a validation pass, and `collect`
(`lib.rs:405-425`) never touches the poller's `Ingest`. So a local signature written
between two passes is not yet protected by name, and file names are attacker-chosen hex, so
a peer can flood a directory with names sorting below ours. `Poke::Push { hash }` narrows
the window for console writes but cannot close it for a `hot_cheese bundle sign` run in
another process. Either the cap is per-directory-arrival rather than per-directory-total,
or it accepts that a valid local signature can be quarantined in a flood and relies on
quarantine being reversible. The plan takes the second and quarantines rather than deletes
precisely so the operator can get the file back. Owner's call.*

**(d) `MAX_INGEST_FILES` becomes a resumable work budget.** When a pass hits it, it still
stops and still sets `capped`, but the incremental map means the next tick *continues*:
everything judged so far is recorded, everything else still mismatches. A flooded tree
therefore drains at 4096 files per tick instead of leaving a permanent hole.

**The budget counts files it JUDGED, not files it looked at.** This is the whole of the
claim and the first draft did not say it. `validate` today increments `inspected` for every
name it reaches (`ingest.rs:196`). Keep that and the resumption is a lie: a tree of 10 000
files walks in a fixed order (`dirs()` sorts by digest, names sort within a directory), so
every pass would spend its entire 4096 budget re-`stat`ing the same prefix and the suffix
past file 4096 would **never** be judged — a permanent hole, and a starvation an attacker
can aim by choosing a low digest. Counting only the files that actually cost a parse and an
ecrecover makes a skip free, so each pass gets 4096 units of *new* work and the walk
reaches further every tick until it covers the tree. The `open`+`fstat` of a skipped file is
not free in absolute terms, but it is bounded by the tree size, not by the budget.

**(e) Bound the quarantine tree.**

```rust
/// Files the quarantine tree holds before a rejected file is deleted instead of moved.
pub const MAX_QUARANTINE_FILES: usize = 1024;
```

`Ingest::quarantined` counts it, seeded by one walk of the tree at `start()`. Beyond the
cap a rejected file is deleted. 1024 × 64 KiB = 64 MiB ceiling.

The counter tracks **files in the tree, not quarantine events**. `quarantine`
(`ingest.rs:161-171`) renames to `<quarantine>/<hash>/<name>`, a path fixed by the digest
and the file name, so re-quarantining the same `(hash, name)` — which the re-pull churn
below makes routine — overwrites the previous file and adds nothing. Incrementing per
event would drive a counter that never falls to the cap while the tree stayed small, and
`MAX_QUARANTINE_FILES` would start deleting files it did not need to. The counter is
incremented only when the destination did not already exist.

Deleting past the cap is safe for the `Reject` cases every check in `judge` refuses by
construction. It is **not** safe for the `Stuffed` and `refused_files` cases added by this
stage, which can in principle land on a valid local file (see (c)); those are exempt from
the delete-past-cap rule and are dropped rather than deleted if the quarantine tree is full.

**(f) Attribute everything to a peer, and rate-limit the peer.** Because each peer's pull
is validated on its own (§4), `PeerTick.verdict` names *who* sent what was quarantined or
refused — which is impossible today, since `pull` runs every peer and then validates once
(`sync.rs:283-291`). A peer whose pull produced any refusal-beyond-cap is skipped for
`min(2^n, 32)` ticks, where `n` is its run of offending ticks, reset to zero by a clean
tick. This is a **rate limiter, not a trust decision**: the peer stays enrolled, the
backoff self-clears, and `PeerPoll.skip_ticks` puts it on the status so the operator sees
why a machine went quiet. Un-enrolling is still `bundle peer rm` (`sync.rs:432-459`).

**The backoff must also trigger on work, not only on refusals.** A peer that rewrites
valid files every tick produces zero quarantines, zero refusals and zero `crowded`
entries, and would never be backed off — while costing a parse and an ecrecover per file
per tick forever. So a peer's tick counts as offending if it produced any refusal-beyond-cap
**or** if the pull it triggered judged more than `MAX_FILES_PER_BUNDLE` files. That number
is a peer rewriting more files in 30 seconds than one Safe can hold owners, which no honest
co-signer does.

**(g) Stop the log flood.** `validate` currently emits one `tracing::warn!` per
quarantined file (`ingest.rs:200-205`). At 30s intervals against a hostile peer that
alone would evict the console's whole `LogRing` (200 lines, `status.rs:19`) every tick.
That per-file line drops to `debug`, and the poller emits **one** `warn` per peer per
tick carrying the counts.

### What is deliberately *not* claimed

- Bandwidth is not bounded. A peer that re-sends what we delete costs us up to 256 MiB of
  transfer per tick before the backoff engages, and after it engages, once every 32 ticks.
  That is a nuisance from a machine the operator explicitly enrolled and can un-enrol; it
  is surfaced, not silently absorbed.
- None of this is authentication. It is a bound on how much disk and noise an enrolled
  writer can cost. The security property that actually matters is unchanged: no peer can
  forge a signature, because every signature is checked against a digest we rebuild from
  the fields ourselves (`ingest.rs:129-158`), and `owners_ok` still refuses a
  valid-but-unwanted signer at `export` (`lib.rs:515-522`).

---

## 8. Status for stage 4

**This section is the single definition of the bundle-poll status shape.** Locked decision 14:
stage 4 owns no status of its own; it reads what this stage and stage 2 publish and owns only
its own pending-approvals gauge. `04-live-status.md` §1 references this section rather than
restating it, and the `BundleState`/`PeerState` mirrors it once invented are deleted.

Lives in `crates/hc-daemon/src/bundle_poll.rs`. Follows the `LogRing` pattern the hazard
list points at — a `parking_lot` lock inside an `Arc`, shared with whoever renders.

**The clock is `u64` Unix seconds**, locked decision 12:

> Stage 2 and stage 3 independently chose seconds and milliseconds; nothing type-checks the
> difference. Seconds wins.

An earlier revision of this section stamped milliseconds from `hc_sign::grant::now_ms()`
(`crates/hc-sign/src/grant.rs:174-178`) because that is the repo's existing spelling
(`created_at_ms`, `Arrival`). It is replaced here by `hc_sign::grant::now_secs()`, the sibling
`02-git-store.md` §6 specifies, so both stages read one clock in one unit. `PollErr` keeps its
`Grant(hc_sign::grant::GrantErr)` variant, because `now_secs` has the same `Result` shape.

Every **timestamp** field is therefore seconds and named `_at`, matching stage 2's
`last_push_ok_at` / `last_fetch_ok_at`. The one field that stays in milliseconds is
`last_took_ms`, and it is not a timestamp: it is a measured elapsed duration, and a tick that
takes 300 ms would render as `0` in seconds, which destroys the only thing it exists to show
(§3's drift note). Decision 12 governs epoch stamps. The `_ms`/`_at` split in the names is what
keeps the two from being confused, which is the foot-gun decision 12 names.

Nothing else in this stage does arithmetic on a timestamp: the interval is
`Duration::from_secs(interval_secs)` from config and the loop waits on `recv_timeout`, never on
a stamp difference; the peer backoff counts **ticks**, not time. So the unit change touches the
field types and `now_secs()`, and nothing else.

```rust
/// The background poller: its thread's handle, its request channel, and what it last did.
pub struct BundlePoll {
    status: Mutex<PollStatus>,
    requests: SyncSender<PollRequest>,
}

impl BundlePoll {
    /// Read the last tick. Never hold this across a prompt; `inquire` owns the terminal.
    pub fn status(&self) -> MutexGuard<'_, PollStatus>;
    /// Ask for a tick now, optionally waiting for it to finish.
    pub fn poke(&self, poke: Poke) -> Result<(), PollErr>;
}

/// What a caller is asking the poller to do, and whether it waits.
pub enum Poke {
    /// Record a bundle this device wrote into, push it, and return without waiting.
    Push { hash: B256 },
    /// Block until the requested tick has finished.
    AwaitTick,
}

/// What the poller has done, as of the last tick that finished.
pub struct PollStatus {
    /// Unix seconds the last tick finished; None before the first one.
    pub last_finished_at: Option<u64>,
    /// How long that tick took, in milliseconds. An elapsed duration, not an epoch stamp.
    pub last_took_ms: u64,
    /// Ticks finished since this runtime started.
    pub ticks: u64,
    /// Seconds between ticks, as the last tick read it from config.toml.
    pub interval_secs: u64,
    /// One row per enrolled peer, in config.toml order. Empty before the first tick.
    pub peers: Vec<PeerPoll>,
    /// Bundle directories the tree holds.
    pub bundles: usize,
    /// Newest last, capped at ARRIVAL_RING.
    pub arrivals: VecDeque<Arrival>,
    /// Signatures that have arrived since this runtime started.
    pub arrived: u64,
    /// Files moved to bundle-quarantine since this runtime started.
    pub quarantined: u64,
    /// Files and directories deleted for breaking a cap since this runtime started.
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
    /// Ticks it stays skipped for after flooding; 0 when it is not backed off.
    pub skip_ticks: u32,
}
```

Notes on the shape, since stage 4 has to render it:

- `pull` and `push` hold the **typed** `Result<(), SyncErr>`, not a rendered string and
  not a remapped enum. `SyncErr` nests `std::io::Error` and so cannot be `Clone`, which is
  why `status()` hands back a guard rather than a snapshot: the renderer formats under the
  lock, exactly as `LogRing::recent` copies under the lock (`status.rs:46-50`).
- The three `Option`s are all cases where `None` is a genuine value — "no tick has
  finished", "no pull has ever succeeded", "the last tick finished". None of them signals
  failure.
- `peers` is empty until the first tick, so no `PeerPoll` ever exists without a real
  result. **A renderer must therefore not derive "are any peers enrolled?" from
  `peers.len()`** — that answer is 0 for the first tick of a machine with three peers, and a
  chip that appeared a tick later would make the band jump sideways. The configured count comes
  from `config.bundle_peers` (`crates/hc-core/src/config.rs:37`), which is where "enrolled"
  actually lives; `peers` answers "what happened to each of them", not "how many are there".
  Stage 4 §1.4 reads it that way.
- Timestamps use `hc_sign::grant::now_secs()`, the seconds sibling of the repo's existing wall
  clock (`crates/hc-sign/src/grant.rs:174-178`, used at `lib.rs:380,461`), specified once in
  `02-git-store.md` §6. The hazard note "No timestamps exist anywhere in the status code today"
  is answered here rather than in stage 4.
- `Arrival` is the existing type (`lib.rs:573-585`), unchanged. It keeps its own `created_at_ms`
  — that is a wire field of an existing on-disk format, not a status field, and decision 12 does
  not reach it.

### RECONCILED with stage 4

`04-live-status.md` was written before this file and invented its own `BundleState` and
`PeerState` for the same facts. **Locked decision 14 settles it: stage 4 publishes none of
them.** Its revision reads `PollStatus`/`PeerPoll` directly, so there is no derivation step, no
`Update` enum and no second writer. What remains of the old table, with each row's disposition:

| Was | Now |
|---|---|
| `crates/hc-daemon/src/live.rs` holding one `LiveStatus` for backup, store, bundles and peers | Stage 4's `Live` is a handle holding `Arc<GitStatus>`, `Arc<BundlePoll>` and its own `Pending` gauge. It stores no bundle facts. |
| `BundleState` enum derived from `PollStatus` at publish time | Deleted. The band reads `PollStatus` fields directly at render time; there is no publish step. |
| `PeerState { enrolled, reachable, silent, at }` | Deleted. `silent` is `peers` filtered to rows whose `pull` is `Err`, computed in stage 4's `band_source`; `enrolled` is `config.bundle_peers.len()`. |
| Clock: `SystemTime` vs `u64` ms — **unresolved** | Settled by decision 12: `u64` Unix **seconds**, both stages, `now_secs()`. This section is written to it. |
| Step 6 adds a status band to `bundles.rs:691-761` (`watch`) | That screen is deleted by §5/§10 of this stage. Stage 4's step 6 has been corrected to the one surviving panel (`approval.rs`'s `serve_and_approve`) plus its own Status panel. |
| `bundles.rs:286` is "stage 3 deletes it" | Agreed, §10 deletes it. No action. |
| Poller lands in `hc-daemon`, so stage 4's module may live there | Agreed. §1 puts the thread and status in `hc-daemon` and adds `hc-daemon → hc-bundle`; no cycle. |

One thing stage 4 asks for that this stage deliberately does **not** provide: a non-blocking
"poll bundles now" trigger. `Poke::AwaitTick` blocks the caller for up to one tick and
`Poke::Push { hash }` needs a digest, so neither is a key a panel can bind without freezing. See
§13 open question 1; stage 4's revision does not add such a key, so nothing is owed here.

---

## 9. Typed errors

New enum, in `crates/hc-bundle/src/poll.rs`, via `err_mac::create_err_with_impls!` with
`#[from]` nesting so `?` unwraps library errors with no `map_err`:

```rust
create_err_with_impls!(
    #[derive(Debug)]
    pub PollErr,
    Config(hc_core::config::ConfigErr),
    Ingest(crate::ingest::IngestErr),
    Bundle(crate::BundleErr),
    Grant(hc_sign::grant::GrantErr),
    StdIo(std::io::Error)
    ;
    PokeTimedOut { secs: u64 },
    PollerGone
);
```

- `Grant` is needed because `now_secs()` returns `Result<u64, GrantErr>` (§8).
- Nesting both `StdIo` and `Bundle` is fine: `create_err_with_impls!` generates one
  `From` per listed source type and those are distinct types.
- `PokeTimedOut { secs }` carries the deadline that expired; `PollerGone` is the poller
  thread having exited, which the renderer must be able to state rather than hang on.
- **A per-peer transport failure is not a `PollErr`.** It stays `SyncErr` in a
  `PeerPoll` row, preserving the existing rule at `sync.rs:75-77`: "an unreachable laptop
  must not break signing on the desktop". A tick returning `Err` is logged and the loop
  continues; a background loop must never die on one bad tick.
- The new caps produce `Verdict` entries, not errors. A peer flooding us is data about
  that peer, not a failure of ours.

`Verdict` (`ingest.rs:72-80`) gains two fields:

```rust
/// Bundle directories refused whole for arriving past MAX_BUNDLE_DIRS.
pub refused_dirs: Vec<B256>,
/// Files quarantined for pushing a directory past MAX_FILES_PER_BUNDLE.
pub refused_files: usize,
```

`Reject` (`ingest.rs:44-58`) gains `Stuffed` (§7a).

`crowded` stays as the "this directory is at the cap" signal. Exactly one renderer of
`Verdict` survives this stage and must show the new fields: `report`
(`hc-cli/src/bundle.rs:171-193`), which `bundle sync` still calls. **`sync_note`
(`hc-console/src/bundles.rs:217-252`) is not extended — it is deleted.** All four of its
call sites (`:286`, `:710`, `:904`, `:905`) are removed by §6 and §10, so extending it in
step 2 and deleting it in step 6 would be churn on a corpse. `Report` drops out of the
console's imports with it (`bundles.rs:21` narrows to `use hc_bundle::sync::{self,
SyncMode};` — `sync::` is still needed for `peer_list`, `peer_add`, `peer_rm` and
`SyncErr`).

---

## 10. Deletion list

Every line below is dead after this stage and is removed, not left alongside.

| File | Lines | What |
|---|---|---|
| `crates/hc-bundle/src/lib.rs` | `587-642` | `Watch` and its doc, `start`, `watching`, `poll`, `take_stock`. `Arrival` (`573-585`) stays. |
| `crates/hc-bundle/src/ingest.rs` | `175-211` | free `pub fn validate`, replaced by `Ingest::validate` |
| `crates/hc-bundle/src/ingest.rs` | `129-158` | `judge`'s io — it takes bytes now and stops returning `Result` |
| `crates/hc-bundle/src/ingest.rs` | `200-205` | the per-file `warn!`, demoted to `debug!` |
| `crates/hc-cli/src/bundle.rs` | `85-89` | `BundleCmd::Watch` |
| `crates/hc-cli/src/bundle.rs` | `158` | its dispatch arm |
| `crates/hc-cli/src/bundle.rs` | `289-317` | `fn watch` and its doc |
| `crates/hc-cli/src/bundle.rs` | `12` | narrows to `use hc_bundle::Scope;` — `Scope` is still used by `fn scope` (`:163`) |
| `crates/hc-cli/src/bundle.rs` | `13`, `16` | `Config` and `Duration` imports, used only by the deleted `watch` (`:293`) |
| `crates/hc-console/src/bundles.rs` | `286` | the unconditional `sync::pull(Scope::All)` per render |
| `crates/hc-console/src/bundles.rs` | `217-252` | `fn sync_note` — every call site goes (§9) |
| `crates/hc-console/src/bundles.rs` | `616-685` | `WatchView`, `WatchView::push`, `draw_watch` |
| `crates/hc-console/src/bundles.rs` | `687-761` | `fn watch` and its doc |
| `crates/hc-console/src/bundles.rs` | `48`, `51` | `TICK`, `MAX_ARRIVALS` |
| `crates/hc-console/src/bundles.rs` | `72-74` | `BundleAction::Watch` menu entry |
| `crates/hc-console/src/bundles.rs` | `115`, `125`, `140-143`, `307`, `335` | `Landing::Watch` and its arms — `140-143` only; `144-147` is the `Peers` arm and stays |
| `crates/hc-console/src/bundles.rs` | `363` | `BundleAction::Watch => watch(..)` |
| `crates/hc-console/src/bundles.rs` | `710` | `sync::pull(scope)` in the watch loop |
| `crates/hc-console/src/bundles.rs` | `903` | `sync::sync_now(Scope::All)`, becomes `poke(Poke::AwaitTick)` |
| `crates/hc-console/src/bundles.rs` | `21` | narrows to `use hc_bundle::sync::{self, SyncMode};` — `Report` dies with `sync_note` |
| `crates/hc-console/src/bundles.rs` | `23` | narrows to `use hc_bundle::{Loaded, Scope, Slot};` — `Arrival` returns via `hc_daemon::bundle_poll`'s status |

Check after deleting: `crossterm::event`, `Hide`, `Print`, `enable_raw_mode`,
`disable_raw_mode`, `RawScreen`, `Instant` and `Duration` in `bundles.rs` may become
unused imports; `RawScreen` (`hc-console/src/approval.rs`) is used by other screens and
stays.

### Documentation the deletion also makes wrong

Grepped, not guessed. `scripts/*.sh` are clean — none of `demo.sh`, `dryrun.sh` or
`verify.sh` mentions `bundle watch`. These do:

| File | Lines | What |
|---|---|---|
| `README.md` | `406` | the `bundle watch [<hash>]` row in the subcommand table — delete |
| `README.md` | `447`, `486` | `bundle_watch_secs = 15` and "Seconds between polls in `bundle watch` (optional; defaults to `15`)" — the key survives, the default becomes 30, the floor is 5, and the description becomes the background poller |
| `README.md` | `886`, `891` | the "Pull first" table and "a bare `watch`" both name `watch` as a sync trigger |
| `README.md` | `985`, `988-992` | the worked example and the paragraph describing the foreground loop |
| `MIGRATION.md` | `618` | "`bundle watch <hash>` polls until the threshold is met" |
| `crates/hc-core/src/config.rs` | `24` | the field doc "Seconds `bundle watch` waits between polls" — the subcommand it names will not exist |

The README's peer section also has to gain the mutual-enrolment sentence decision 9 makes
load-bearing (§4).

---

## 11. Steps

Each step builds in release and is verified before the next.

**1. Make `judge` pure and give `Ingest` its identity map.**
Rework `crates/hc-bundle/src/ingest.rs`: `FileId`, `Ingest`, `Ingest::new`,
`Ingest::validate`; `judge(bytes, name, hash) -> Option<Reject>` plus the new
`Reject::Stuffed` (§7a); open, fstat, skip-or-size-check, read only when the identity
moved. Delete the free `validate`.

**No public signature moves in this step.** `sync::pull` (`sync.rs:277-292`) keeps
`pull(scope) -> Report` and builds a throwaway `Ingest::new()` internally, which is a
full pass — today's exact behaviour, which is the right behaviour for a one-shot CLI
process. `SyncMode::pull` (`sync.rs:309-314`), `sync_now`, and every verb in `lib.rs` are
untouched, so nothing ripples into `hc-cli`, `hc-console` or `hc-mcp`. The long-lived
`Ingest` is owned by the `Poller` (step 3) and never passed through `pull`.
*Verify:* `cargo test --release -p hc-bundle`, including the new agreement test (§12).

**2. Add the caps.**
`MAX_BUNDLE_DIRS`, `MAX_QUARANTINE_FILES`, enforce `MAX_FILES_PER_BUNDLE`, make
`MAX_INGEST_FILES` a budget over judged files only, extend `Verdict`, demote the per-file
warn. Update `report` (`hc-cli/src/bundle.rs:171-193`) to render the new fields.
`sync_note` is left alone here; step 6 deletes it.
*Verify:* `cargo build --release`, `cargo test --release -p hc-bundle` with the cap test.

**3. Add `Poller` and per-peer sync.**
New `crates/hc-bundle/src/poll.rs`: `Poller`, `PeerTick`, `PollErr`. Add
`sync::pull_from(peer, scope)` / `sync::push_to(peer, scope)` alongside the existing
aggregate `pull`/`push`/`sync_now`, which keep working for `bundle sync`. `pull_from` does
the `create_dir_all` that `pull` does today (`sync.rs:279-282`) and does **not** validate —
the `Poller` owns the `Ingest`. `enrolled()` stays private (§3). The argv builders
(`sync.rs:180-195`) and their test (`sync.rs:482-523`) are **untouched**.
*Verify:* `cargo test --release -p hc-bundle`; the argv test still passes byte-for-byte.

**4. Add the thread and the status.**
`hc-daemon/Cargo.toml` gains `hc-bundle`. New `crates/hc-daemon/src/bundle_poll.rs`:
`BundlePoll`, `PollStatus`, `PeerPoll`, `Poke`, the `std::thread` loop over
`recv_timeout`, the between-peers shutdown check, the backoff. Wire it into stage 1's
`Runtime` (own it, hand `&Arc<BundlePoll>` to both renderers, drop-sender-then-join-with-
deadline at shutdown).
Change `Config::bundle_watch_secs()` (`config.rs:283-285`) to the 30s default with the
5s floor, and its field doc (`config.rs:24`), which names a subcommand step 5 deletes.
*Verify:* `cargo build --release`; run `hot_cheese serve` in the **foreground** with a
throwaway `HOT_CHEESE_HOME`, `HOT_CHEESE_INSECURE_SOFTWARE_ENCLAVE=1` and **no**
`[[bundle_peers]]`; confirm the log shows a tick every 30s doing nothing and `/health`
answers. Do not touch `/read`, `/evm_address` or `/solana_address`.

**5. Delete the foreground pollers.**
Everything in §10 for `hc-cli/src/bundle.rs` and the watch parts of
`hc-console/src/bundles.rs`.
*Verify:* `cargo build --release`; `hot_cheese bundle --help` no longer lists `watch`;
`cargo test --release -p hc-cli` (the `--no-sync` test at `lib.rs:1271` still
passes).

**6. Rewire the console.**
The §6 table for `bundles.rs`: delete `:286` and `sync_note` (`:217-252`), flip the read
verbs to `SyncMode::Off`, add `Poke::Push { hash }` on the three write verbs, render the
`PollStatus` header line, turn Peers→Sync into a poke.
*Verify:* `cargo build --release`; `cargo clippy --release --all-targets -- -D warnings`
with **no** new `#[allow]`; open the console with a throwaway home and walk
Bundles → Peers → back, confirming no rsync is spawned per render.

**7. Fix the documentation the deletion invalidated.**
The `README.md` and `MIGRATION.md` rows in §10, plus the mutual-enrolment sentence decision
9 requires. Prose only; no code.
*Verify:* `grep -rn "bundle watch" README.md MIGRATION.md scripts/ crates/` returns
nothing.

---

## 12. Tests

Per `CLAUDE.md` and `00-design-decisions.md:130-136`. Four tests, all in `hc-bundle`,
all blocking, none touching a network or a thread.

**1. Incremental and full validation agree on the same tree.** *(Named explicitly in
`00-design-decisions.md:88` as a required test.)*
Build a bundle tree under a temp dir. Keep two copies. On copy A, run one `Ingest` across
several passes with a mutation between each: add a valid signer file, overwrite a valid
file with corrupt bytes, add a misfiled signature, rewrite a file with *different bytes of
the same length*, remove a directory. On copy B, run a fresh `Ingest::new()` for a single
full pass over the same final tree. Assert the two trees end byte-identical, the same
files are in quarantine with the same `Reject`, and the union of A's verdicts equals B's.
This is the whole correctness claim of the stage; the same-length rewrite is the case that
fails if identity is keyed on path or on size alone.

Copy A's run must include **one pass that hits `MAX_INGEST_FILES`**, because the agreement
claim is only true if a capped pass resumes: if the budget were spent on skips (§7d) the
suffix would never be judged and A and B would differ exactly there. Without that case the
test passes on a tree small enough to hide the bug it exists to catch.

**2. A directory that arrived past the cap is refused; one already here is never touched.**
Prime an `Ingest` on a tree already holding more than `MAX_BUNDLE_DIRS` directories and
assert the priming pass removes none of them. Then add one more directory and assert it is
removed and named in `refused_dirs`. This is the non-trivial part of the cap — the
priming asymmetry — and getting it backwards deletes the operator's own bundles.

**3. Enforcing `MAX_FILES_PER_BUNDLE` never moves a file this machine already had judged.**
Fill one directory past the cap with peer files, having first written our own signer file
through the normal path **and run one pass**, so it is in `seen`. Assert the seed and our
file survive and the overflow is what goes. This pins as much of `ingest.rs:11-13` as (c)
still guarantees; the unprotected window (a local write not yet judged) is the `AUDIT` note
in §7(c) and this test must not be read as covering it.

**4. A file repeating one valid signature is refused before it is recovered.**
Build a file holding the same valid `CollectedSignature` many times and assert
`Reject::Stuffed`. The point is not the refusal — that is one `if` — it is that the refusal
happens **before** the loop that calls `SafeTxBundle::add`, which is the only thing bounding
this stage's per-tick CPU (§7a). Written as an assertion on the verdict of a file whose
signature count exceeds what any writer in `lib.rs` can produce.

**Not written**, per the rules: nothing that asserts `recv_timeout` sleeps, that the
backoff arithmetic multiplies, that `Verdict` serialises, or that "a peer that is not in
the map returns an error".

---

## 13. Risks and open questions

**Verified, but worth flagging.** rsync skips a file whose size *and* mtime match the
receiver's copy even when the content differs — I confirmed this by forcing the mtime and
watching rsync say nothing. This does not affect our invariant (we only claim that
everything in *our* tree has been judged), but it does mean a peer can silently diverge
from us on a file we both hold. That is already true today and this stage does not change
it.

**Unverified, and I will not pretend otherwise.** Every rsync claim in this file was
reproduced against **rsync 3.4.1 on Linux**, which is not what the target runs: stock macOS
has shipped rsync 2.6.9 for years and recent releases ship openrsync, and neither was
available to test here. This matters for §2's escape and itemize observations, which are
3.4.1's behaviour and may differ. It does **not** matter for the design: the argv is
unchanged from what the repo already ships and already tests (`sync.rs:482-523`), and
Option A is rejected on three grounds of which version compatibility is only one. What
does need checking on the Mac before this stage is trusted:

- that `rsync -a` on the target still replaces the destination inode rather than writing
  in place (the `FileId` design rests on ctime, which advances either way, but `ino` is one
  of the four fields);
- that openrsync, if that is what `/usr/bin/rsync` resolves to, honours `--max-size` — it
  is the only thing bounding a peer's bytes on the wire (`sync.rs:191`).

If someone later wants Option A, the version check comes first.

**Open questions.**

1. **Does `Poke::AwaitTick` belong on the main thread at all?** It blocks the terminal
   thread for up to one tick. It is strictly better than the synchronous rsync it
   replaces, but stage 4 may make it unnecessary for Export by rendering "waiting for a
   signature" live instead. Revisit at stage 4.
2. **`MAX_BUNDLE_DIRS = 64` may be wrong for a real operator.** I derived it from
   `mcp.max_pending`'s default of 16 and from making the tree fit one `MAX_INGEST_FILES`
   pass. If anyone genuinely runs more than 64 concurrent Safe transactions the cap
   should become config, matching `mcp.max_pending`. I chose the const for consistency
   with its three siblings; say so out loud rather than discovering it in an incident.
3. **Decision 9 removed the relay, and with it a convergence path.** An earlier draft of
   this file proposed a periodic `push(Scope::All)` and asked the owner to sign off on
   relaying. That is settled the other way (`00-design-decisions.md:96-98`) and §4 has been
   rewritten to push only `Poller::contributed`. The residual question is operational:
   **enrolment is now required to be mutual**, and nothing in the code enforces or checks
   it. `bundle peer list`'s `orphans` (`sync.rs:340-351`) reports a name no tailnet machine
   answers to, not a peer that has not enrolled us back — this machine cannot learn that
   without asking the peer, and asking is a wire protocol, which is a non-goal. So the
   answer is documentation plus `peer add` on both machines. If one-sided enrolment turns
   out to be common, the fix is a `bundle peer check` that ssh's to the peer and reads its
   `config.toml`, not a relay.
4. **`Poller::contributed` does not survive a restart.** A daemon restarted between "we
   signed" and "the peer woke up" pushes nothing for that bundle. Convergence still holds —
   the peer pulls from us — but the push-side retry silently narrows. Persisting the set
   would mean a new on-disk file for a property the pull already provides, which is why the
   plan does not. A choice, not an oversight.
5. **The backoff hides a real peer's problem.** A peer that is genuinely misconfigured —
   not hostile — will be skipped for up to 32 ticks with only a status row saying so. The
   alternative (no backoff) lets one bad peer burn bandwidth indefinitely. I picked the
   backoff and made it visible; if that trade is wrong the fix is to surface it harder,
   not to remove the bound.
6. **`bundle watch` deletion narrows the CLI-only workflow.** Stated plainly in §5. If the
   repo owner wants a waiting loop for the no-daemon case, the honest shape is a thin
   `bundle sync --until-met` built on `sync_now`, not a resurrected second poller — but I
   am not adding it speculatively.
7. **§7(c) weakens `ingest.rs:11-13`.** Enforcing `MAX_FILES_PER_BUNDLE` can move a valid
   local signature that no pass has judged yet. The plan quarantines rather than deletes so
   the file is recoverable, and narrows the window with `Poke::Push { hash }`, but it cannot
   close it for a write made by a separate CLI process. The alternative — leaving the
   per-bundle cap as a count, as today — leaves one directory's file count unbounded.
   Owner's call, marked `AUDIT` inline in §7(c).
8. **~~Stage 4 and this file disagree~~ — closed by decisions 12 and 14.** The clock is `u64`
   Unix seconds for both stages, and stage 4 publishes no bundle or peer state at all; it reads
   §8's types. §8's table records each old conflict and its disposition. The one live
   dependency that remains is the reverse direction: §8's shape is now load-bearing for stage 4,
   so a field renamed here breaks stage 4's `band_source` — which is the one place it should
   break, and stage 4 says so.
