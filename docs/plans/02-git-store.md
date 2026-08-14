# Stage 2 — Git-backed store, automatic push/fetch

Implements locked decision 3 of `00-design-decisions.md`: the store becomes a git repository,
mutations auto-commit, backup push is a git push, the freshness probe is a fetch, a merge is
applied only when it is a fast-forward, divergence is a surfaced state, and the rsync backup
transport is **deleted**, not kept alongside.

Depends on stage 1. Stage 3–5 do not depend on this stage; stage 4 consumes the status type in
§6.

---

## 0. Verified ground truth

Everything below was read in this repo or executed against `git version 2.53.0`. Two statements
in `00-design-decisions.md` are **wrong** and are corrected here.

Audited: every `file:line` re-opened and every git experiment independently re-run against the
same `git version 2.53.0`. Line citations were sound apart from those corrected inline
(`hc-cli/src/lib.rs:76`→`:78`, `:112`→`:108`, `:264-265`→`:262-263`; "three"
`write_private_file` call sites → four; "four" rsync-argv tests → five). Six git claims did not
reproduce as stated and are marked **CORRECTED** in §0.4, and four hazards the first pass did
not test are added there as **NEW**. `00-design-decisions.md:158-165` repeats the
"exactly three places" `write_private_file` count and should be corrected there too.

### 0.1 The transport today

| Fact | Evidence |
|---|---|
| `BackupRemote { host, folder }`, TOML `[[backup_remotes]]`, N allowed | `crates/hc-core/src/config.rs:46-52`, `:31` |
| Push is `rsync -az <store>/ <host>:~/<folder>/<vault>/` | `crates/hc-daemon/src/backup.rs:119-129`, `:105-117`, `:144-153` |
| Remote dir creation is `ssh <host> mkdir -p -- <folder>/<vault>` | `crates/hc-daemon/src/backup.rs:210-217`, `:157-170` |
| Backup rsync sets **no** `--delete`, **no** `--exclude`, **no** `-e ssh …` | `crates/hc-daemon/src/backup.rs:123-141` |
| Bundle sync **does** set `BatchMode=yes`, `ConnectTimeout=5`, `--exclude=*.hctmp` | `crates/hc-bundle/src/sync.rs:140-144`, `:169-177`, `:29-36` |
| Legacy (no `vault_id`) keyrings push un-namespaced to `<folder>/` | `crates/hc-daemon/src/backup.rs:112-117` (`None` arm) |
| `vault_id` is cleartext in `keyring.json`; a push unlocks nothing | `crates/hc-core/src/keyring.rs:124-126`, `crates/hc-daemon/src/backup.rs:76-86` |
| Push fans out to **every** remote | `crates/hc-daemon/src/backup.rs:258-267` |
| Pull / list / adopt use only `.first()` | `crates/hc-cli/src/lib.rs:931`, `:950-953`, `:959-962`; `crates/hc-console/src/menu.rs:821` |
| `push_all` warns per remote and returns `Ok(())` even when **all** failed | `crates/hc-daemon/src/backup.rs:249-269` |
| Pull merges (no `--delete`, no `--update`): the remote `keyring.json` overwrites the local one regardless of age | `crates/hc-daemon/src/backup.rs:135-141`, `:229-240` |
| Guards that exist: pre-rsync `require_vault`, post-rsync vault re-check, `AmbiguousRemoteTryPullVault` | `crates/hc-daemon/src/backup.rs:90-103`, `:229-240`, `:188-207` |
| `Keyring` has `v`, `vault_id`, `enrollments` — no generation counter, no `updated_at` | `crates/hc-core/src/keyring.rs:120-128` |
| Auto-pull fires only when the store dir is missing/empty, in `cmd_serve` | `crates/hc-cli/src/lib.rs:927-936`, `crates/hc-daemon/src/backup.rs:68-74` |
| No dirty flag, no store hash, no generation counter anywhere | grep over `crates/` |
| The store is **not flat**: `policies/<name>.toml` is a tracked subdirectory | `crates/hc-sign/src/policy.rs:127-128` |
| `bundles/`, `adapters/`, certs live under the **home** dir, never the store | `crates/hc-core/src/config.rs:236-263` |
| The repo already shells out to `rsync`, `ssh`, `tailscale`, `/bin/ps`, `/bin/sleep`, `swiftc` | `crates/hc-bundle/src/sync.rs:201,215`; `crates/hc-bundle/src/tailnet.rs`; `crates/hc-cli/src/bootstrap.rs`; `crates/hc-console/src/exposure.rs`; `crates/hc-core/build.rs` |

### 0.2 Correction 1 — keystores are **not** 0600 today

`00-design-decisions.md:108-110` says "Keystores are written 0600 by `write_private_file`".
That is false.

- `encrypt_file` → `atomic_write` (`crates/hc-core/src/crypto/envelope.rs:265-276`, `:312-318`).
- `atomic_write` is `fs::write` + `fs::rename` — **umask**, i.e. 0644 on a default macOS umask 022.
- `write_private_file` (0600, `envelope.rs:293-310`) is called from exactly four sites covering
  three kinds, none of them a keystore: the SE blob
  (`crates/hc-core/src/mac/secure_enclave.rs:204`), the demo software key (`:428`, inside
  `ensure_software_key_at`) and the TLS private key (`crates/hc-cli/src/lib.rs:550`, `:557`).
- The store dir itself is `create_dir_all` at umask (`crates/hc-core/src/mac/mod.rs:28-36`).
- The only mode enforcement in the whole workspace is the adapter socket dir/socket
  (`crates/hc-daemon/src/socket.rs:20-23`, `:118`, `:125`).

This is not a vulnerability — the store is an envelope and the DEK never appears in it, which is
the stated reason the whole dir is safe to replicate to untrusted remotes
(`crates/hc-daemon/src/backup.rs:1-14`). It does mean there is no 0600 property to *preserve*.
This stage **establishes** one rather than preserving one, and §7 says how.

### 0.3 Correction 2 — `read_dir(store)` already ignores `.git` at every keystore-counting site

`00-design-decisions.md:112` requires that a keystore count not include `.git`. Every counting
site already filters on `is_file()`, and most additionally on `is_valid_string_name`, which
accepts only `[A-Za-z0-9_]` (`crates/hc-core/src/lib.rs:24-26`) and therefore rejects `.git`,
`.gitignore` and `*.hctmp`:

| Site | Filter | Sees `.git`? |
|---|---|---|
| `crates/hc-console/src/status.rs:115-123` | `is_file()` + `is_valid_string_name` | no |
| `crates/hc-cli/src/lib.rs:507-515` (init guard) | `is_file()` + `is_valid_string_name` | no |
| `crates/hc-cli/src/lib.rs:822-828` (`keystore_names`) | `is_file()` + `is_valid_string_name` | no |
| `crates/hc-console/src/menu.rs:984-989` (`keystore_names`) | `is_file()` + `is_valid_string_name` | no |
| `crates/hc-cli/src/migrate.rs:101-110`, `:120-135` | `is_file()` + `is_valid_string_name` | no |
| `crates/hc-cli/src/bootstrap.rs:339-347` (`shippable_files`) | `is_file()` + skips `keyring.json` / `*.hctmp` | no (dir) |
| **`crates/hc-daemon/src/backup.rs:69-74` (`store_absent`)** | **counts any entry** | **yes** |

So exactly one site breaks, and this stage deletes it (§7). No sweep is needed; do not invent
one. `shippable_files` would ship a tracked `.gitignore`, which is one of the reasons §2 uses
`.git/info/exclude` instead.

### 0.4 Git behaviours this plan relies on — executed, not assumed

All run against `git version 2.53.0`. **Re-run independently during audit; six rows below are
corrections to the first pass and are marked.**

| Behaviour | Result |
|---|---|
| `git init --bare -- a/b/c.git` creates leading dirs | rc 0, dirs created; identical for a relative path, which is the `ssh` case |
| re-running it on an existing bare repo | rc 0 (idempotent) |
| `git ls-remote --exit-code <url> refs/heads/main` | **0** = branch exists, **2** = repo exists but empty, **128** = repo absent / transport failure |
| `git init` + `git symbolic-ref HEAD refs/heads/main` | rc 0. **CORRECTED:** on the resulting *unborn* branch `rev-parse --abbrev-ref HEAD` is `fatal: ambiguous argument 'HEAD'` and prints `HEAD`, **not** `main`. What does work unborn: `symbolic-ref -q HEAD` → `refs/heads/main` (rc 0) and `branch --show-current` → `main`. §8.2 step 4 already uses `symbolic-ref`; §4.1 must not call `rev-parse HEAD` before the first commit — it exits **128** |
| **`git init --bare` sets the bare repo's HEAD to `refs/heads/master`** | **NEW:** the default branch name, not `main`. A plain `git clone <url>` of that repo warns `remote HEAD refers to nonexistent ref` and checks out **nothing**. §2 must set the bare HEAD too |
| `*.hctmp` in `.git/info/exclude`, then `git add -A` | hctmp **not** staged, at the root and under `policies/` |
| `core.fileMode=false`, then `chmod 0600` every tracked file and `0700` the dirs | `git status --porcelain` stays **empty** |
| `git diff --cached --quiet` | **0** = nothing staged, **1** = something staged |
| `git push <path> refs/heads/main:refs/heads/main` with no named remote | rc 0 |
| `git clone` into an **existing empty** dir | rc 0. **`git clone` into an existing dir holding any file is `fatal: … not an empty directory`, rc 128** |
| **clone of 0600 files** (`clone --branch main`) | **recreated 0644**, dirs 0755 — the file-mode hazard, reproduced |
| **`merge --ff-only` of a fast-forward** | rc 0. **CORRECTED and worse than first recorded:** a newly-arrived file lands 0644 *and* an existing tracked file whose content changed remotely is rewritten **0644**, losing a mode this machine had set. Only files the merge did not touch stayed 0600 |
| `merge-base --is-ancestor` | **0** = is ancestor, **1** = is not |
| divergence: both `--is-ancestor` directions | both rc **1** |
| `merge --ff-only` on divergence | rc **128**, worktree **byte-identical** |
| `push` on divergence | rc **1**, remote unchanged |
| `git show FETCH_HEAD:keyring.json` | rc 0 and prints the **remote** blob without touching the worktree; rc 128 if the path is absent |
| `reset --hard FETCH_HEAD` + `clean -fd` | rc 0. **CORRECTED:** `*.hctmp` survives **only when `.git/info/exclude` already carries the rule** — with a fresh clone's default exclude it is deleted. Also deleted, in both cases: every untracked non-excluded file, and every keystore that was committed **locally only** |
| `receive.denyNonFastForwards` on a fresh bare | **unset**; once set, a genuine non-fast-forward `push --force` is rejected rc 1, remote unmoved |
| **`receive.denyDeletes` on a fresh bare** | **NEW:** also **unset**, and `denyNonFastForwards` does **not** cover it — `git push <url> :refs/heads/main` deletes the remote branch rc **0**. With `denyDeletes true` the delete is rejected rc 1 |
| **global `commit.gpgsign = true` in the operator's `~/.gitconfig`** | **NEW:** `git commit` tries to sign and fails (`gpg failed to sign the data`); with a real gpg it can block on a pinentry prompt, which `GIT_TERMINAL_PROMPT=0` does **not** cover. `-c commit.gpgsign=false` fixes it |
| **global `core.hooksPath` / `init.templateDir`** | **NEW:** a `pre-commit` hook from the operator's config **ran** inside our commit — arbitrary code in the process holding the store lock. `git init --template=` yields zero hooks; `-c core.hooksPath=/dev/null` suppresses an inherited path |
| **`GIT_DIR` exported in the environment** | **NEW:** it **overrides `-C <store>`** — `git -C <other> rev-parse --git-dir` returned the `GIT_DIR` repo. Every `add`/`commit`/`reset --hard`/`clean` would run against the wrong tree |

---

## 1. Subprocess `git`, not a Rust library

**Decision: subprocess `git`. Zero new Cargo dependencies.**

Argued against the two candidates:

- **`gix`** is ~50 crates. `deny.toml` sets `[bans] multiple-versions = "deny"` and
  `wildcards = "deny"`, and the existing `skip`/`skip-tree` list shows how much work a single
  duplicate already costs here (hashbrown, password-hash, the whole dalek and ring trees). Every
  workspace dep is `=`-pinned in `Cargo.toml`; pinning a 50-crate subtree exactly is a standing
  tax on every future `cargo update`.
- **`git2`** drags `libgit2-sys` (a C build) and, for the SSH transport, `libssh2-sys` plus an
  `openssl-sys`/`libssl` linkage. `libssh2` is **not** OpenSSH: it does not read the operator's
  `~/.ssh/config`, its agent and key-format support differs, and `ProxyCommand`/`Match` blocks are
  invisible to it. Every other remote path in this repo — bundle sync, `bootstrap-from`, the
  reverse tunnels — already runs through the operator's real `ssh`. Introducing a second, weaker
  ssh for the *backup* path would let backups fail on hosts that `bundle sync` reaches.
- **Licensing**: `deny.toml [licenses] allow` does not include libgit2's GPL-2.0-with-linking-
  exception, so `git2` needs a new `exceptions` entry as well.

Against that, subprocess `git` costs: argv construction, exit-code parsing, and one new host
prerequisite. The prerequisite is nearly free — `README.md:183-185` already requires the Xcode
Command Line Tools for `swiftc`, and the CLT ships `git`. `README.md:186` gains `git` beside
`rsync`/`ssh`. The remote side's prerequisite **changes** from `rsync` to `git`; say so in the
README.

Every invocation is captured, never inherited, for the reason already written at
`crates/hc-bundle/src/sync.rs:197-199`: a console owns the terminal and library code may not draw
into it. Today's backup path violates this — `backup.rs:145` uses `.status()` (inherits both
streams) and `backup.rs:161` inherits stderr, so rsync writes into the console's screen. That is
fixed here as a side effect.

---

## 2. Repo layout

### Local

The **store dir is the working tree**; `<store>/.git` is the repository. Branch: `main`, a
module constant. Created portably (avoids any `--initial-branch` version floor):

```
git init -q --template=
git symbolic-ref HEAD refs/heads/main
```

`--template=` is not decoration: an operator whose `~/.gitconfig` sets `init.templateDir` gets
that directory's hooks installed into `<store>/.git/hooks`, and a `pre-commit` hook from it
**ran inside our commit** in testing — arbitrary code executed by the process holding the store
lock, on every mutation. With `--template=` the hooks dir is empty. The runner additionally
passes `-c core.hooksPath=/dev/null` (§8.2) so an inherited `core.hooksPath` cannot reach us
either.

**Tracked**: every regular file in the store — keystores under their bare names,
`keyring.json`, and `policies/*.toml`. That is exactly what `rsync -az` replicates today.

**Ignored** via `<store>/.git/info/exclude`, **not** a `.gitignore`:

```
*.hctmp
```

`.git/info/exclude` is per-repository, never committed, and never travels. A tracked
`.gitignore` would be a new file in the store, would be shipped by
`crates/hc-cli/src/bootstrap.rs:339-347` (which filters `is_file()` and skips only
`keyring.json` and `*.hctmp` — a `.gitignore` passes all three), and would need a
second rule everywhere the store is enumerated. A clone's default exclude does **not** cover
`*.hctmp` (verified), so the ensure step in §8.2 writes it unconditionally on every open,
including right after a clone.

**Local config**, set at ensure time and after every clone:

```
git config core.fileMode false
git config user.name  hot_cheese
git config user.email hot_cheese@localhost
```

`core.fileMode false` is what lets the §7 chmod pass run without dirtying the tree (verified).
The pinned identity means a machine with no global `user.email` can still commit, and means no
hostname or operator email is recorded in any commit.

**Not used**: named remotes. `git push`/`git fetch` take an explicit URL. A `.git/config`
remote list would be a second copy of `config.backup_remotes` that could drift from the TOML —
precisely the "don't mirror a config struct into a second runtime struct" rule. `config.toml`
stays the single source of truth. The consequence is that there are no remote-tracking refs, so
ancestry is computed against `FETCH_HEAD` immediately after each fetch (§4).

### Remote

One **bare** repo per vault:

```
<host>:<folder>/<vault_id>.git
```

`folder` keeps its existing meaning — home-relative unless absolute — using the same rule
`crates/hc-bundle/src/sync.rs:131-138` already applies. In git's scp-like syntax a relative path
is already home-relative, so no `~/` is emitted. Carried-over limitation, identical to today's
rsync path: a bare IPv6 literal in `host` breaks scp-syntax. `BackupRemote.host` is documented as
`user@1.2.3.4` (`config.rs:48-49`); no regression, but note it in the README.

The `.git` suffix is load-bearing: it is a **different path** from the old rsync layout
`<folder>/<vault_id>/`, so both can sit in one folder without colliding (§9 migration).

Idempotent creation, replacing `ssh mkdir -p`:

```
ssh -o BatchMode=yes -o ConnectTimeout=5 <host> git init -q --bare --template= -- <folder>/<vault>.git
ssh -o BatchMode=yes -o ConnectTimeout=5 <host> git --git-dir=<folder>/<vault>.git symbolic-ref HEAD refs/heads/main
ssh -o BatchMode=yes -o ConnectTimeout=5 <host> git --git-dir=<folder>/<vault>.git config receive.denyNonFastForwards true
ssh -o BatchMode=yes -o ConnectTimeout=5 <host> git --git-dir=<folder>/<vault>.git config receive.denyDeletes true
```

All four verified idempotent. Three of them exist for a measured reason:

- **`symbolic-ref HEAD`** because `git init --bare` leaves HEAD on `refs/heads/master`
  (verified). Our own clone passes `--branch main` so it does not care, but an operator doing
  manual recovery with a plain `git clone <url>` gets `remote HEAD refers to nonexistent ref`
  and an **empty checkout** — a backup that looks lost. One extra ssh round trip removes that
  trap for good.
- **`receive.denyNonFastForwards`** is unset on a fresh bare repo and makes the backup refuse
  any history rewrite, including one from a future bug in this code.
- **`receive.denyDeletes`** because `denyNonFastForwards` does **not** cover a ref deletion:
  with it set and `denyDeletes` unset, `git push <url> :refs/heads/main` still removed the
  remote branch, rc 0 (verified). Rejecting a rewrite while allowing a delete would leave the
  most destructive single command unguarded.

`vault_id` → repo name is the whole mapping. **A keyring with no `vault_id` gets one minted
automatically** at ensure time (§8.2), which is the `backup adopt` logic run without asking. There
is no un-namespaced git layout; keeping one would mean a second remote path shape for no benefit.

---

## 3. Commit policy

### Trigger

Stage 1's single backup-after-mutation chokepoint. **What stage 1 actually delivers, read from
`01-runtime-unification.md`, and where stage 2 must adapt:**

1. **The cross-process lock exists and is adequate.** `01-runtime-unification.md` §4 specifies
   `hc-daemon/src/flock.rs`, `flock::Claim::take(&home_dir().join(".store.lock"))`,
   `try_lock` never `lock`, `FlockErr::Held { path }` returned immediately. It is `flock(2)`, in
   the **home** dir, so it is never a store entry and never replicated. That is exactly what
   `git add -A` needs: `atomic_write`'s rename makes each file atomic but says nothing about a
   *set* of files, and `migrate`, `bootstrap-from` and a CLI `add` beside a running `serve` are
   all excluded — stage 1 §4 lists the mutating subcommands that take it. The file is
   `<home>/.store.lock`; that spelling is used everywhere in both plans.

2. **Its scope is the whole session, not one mutation, and stage 2 must not re-take it.**
   Locked decision 11: `Runtime::start` *receives* an already-held claim, taken at the head of
   the entry point in `hc-cli` and held until the process exits, and nothing in-process calls
   `Claim::take` again because `flock` locks are per open-file-description
   (`crates/hc-daemon/src/socket.rs:103` is the precedent) and a second `open` in the same
   process conflicts with itself.

   Stage 1 §4 therefore provides the in-process half directly, on the claim itself:

   ```rust
   impl Claim {
       /// Serialise one store mutation against every other in this process.
       pub fn mutate(&self) -> parking_lot::MutexGuard<'_, ()>;
   }
   ```

   So every "under the store lock" in §4.1 and §4.3 below means **`Claim::mutate()`** —
   serialising the commit chokepoint against the background task's worktree writes — not a
   second `Claim::take`. Stage 2 does **not** define its own mutex: there is one store and one
   claim, so the guard belongs on the claim, which is where stage 1 puts it. Two writers inside
   one process is a real case (the chokepoint on a blocking thread, the fetch task on another)
   and `git` itself only protects `.git/index` with `index.lock`, which fails the loser rather
   than queueing it. The flock excludes other *processes*; the mutex excludes other *threads*.
   Both are required; neither substitutes.

3. **The chokepoint commits fallibly and pushes best-effort.** This is locked decision 13:

   > A failed commit is a real error the caller must see; a failed push is a warning the status
   > band reports. These are two halves with two different failure dispositions, not one call.

   Stage 1 §7a already ships the signature this needs, with the `Result` present from the start
   precisely so stage 2 does not re-touch seven call sites:

   ```rust
   pub fn after_mutation(cfg: &Config) -> Result<(), GitErr>
   ```

   In stage 1 the body is the best-effort push alone and the `Ok(())` is unconditional; the
   error type is `BackupErr`. Stage 2 replaces the body with §3's commit-then-signal and the
   error type with `GitErr`, and the name and arity do not change. `Err` is returned when the
   **commit** failed; a failed **push** is swallowed into `GitStatus` (§6) and never reaches the
   caller. The one caller that cannot propagate — `crates/hc-daemon/src/lib.rs:854-856`, a
   detached `spawn_blocking` after the HTTP response is already written — logs the `Err` instead.

4. The `Claim::mutate()` guard must be acquirable from a `spawn_blocking` closure. A
   `parking_lot` guard must never straddle an `.await`; the entire locked section lives inside
   one blocking closure.

### The commit

Under `Claim::mutate()`, in order:

1. `enforce_store_modes(store)` (§7).
2. `git -C <store> add -A`
3. `git -C <store> diff --cached --quiet` → **0** = nothing staged, return `Ok(())` without
   committing or signalling a push; **1** = staged; anything else = `GitErr::GitFailed`.
4. `git -C <store> commit -q -m "<message>"`
5. Signal the background task that a push is wanted (§4).

Step 3 is what stops an empty commit per no-op mutation. Exit codes verified.

### Message content

```
hot_cheese <vault_id> <unix_secs>
```

Nothing else. **No key name, no operation, no hostname, no user.**

- The *diff* already reveals which files changed. That is unavoidable — it is what a backup is —
  and it is what rsync already revealed by mtime.
- The *operation* does not. "read `TREASURY`", "signed with `TREASURY`" would put a signing
  history on an untrusted remote that has never held one. That is a new leak; refuse it.
- `vault_id` is already cleartext in `keyring.json` on the same remote
  (`crates/hc-core/src/keyring.rs:32-38`).
- The timestamp is already in git's author/committer date, which cannot be omitted; repeating it
  costs nothing and makes `git log --oneline` legible.
- Committer identity is pinned to `hot_cheese <hot_cheese@localhost>`, so the machine's hostname
  and the operator's email never enter an object.

### Debounce

**No timer.** A mutation is gated behind a biometric, so it cannot arrive faster than a human
presses a finger. The commit is synchronous and cheap (a handful of small JSON files).

Coalescing happens on the *push*, not the commit: the chokepoint sets a
`tokio::sync::watch::Sender<u64>` to the new commit's counter, and the background task pushes
whatever HEAD is when it wakes. `watch` always delivers the latest value, so N commits collapse
into at most one push and a push can never be lost. No `Instant`-based debounce logic, no timer
to test.

In a pure-CLI session (no runtime, e.g. `hot_cheese add`) there is no background task, so the
chokepoint pushes **synchronously** after committing, and the CLI reports the result. That is why
`backup push` survives as a manual retry (§7).

---

## 4. Background task

**Where**: the stage-1 unified `Runtime`'s background task set, alongside its other tasks. One
task. All git work runs inside `tokio::task::spawn_blocking` — it is subprocess + filesystem work
and must not sit on an async worker thread.

**Cadence**: config-driven, not hardcoded.

```rust
/// Seconds the runtime waits between backup fetches; 0 disables the periodic fetch.
#[serde(default)]
pub backup_fetch_secs: Option<u64>,
```

with an accessor mirroring `bundle_watch_secs` (`crates/hc-core/src/config.rs:283-285`):

```rust
pub fn backup_fetch_secs(&self) -> u64 { self.backup_fetch_secs.unwrap_or(300) }
```

`Config::load()` is re-read at the top of each cycle, matching the property bundle sync already
maintains, so an edited `config.toml` takes effect without a restart.

**Loop**: `tokio::select!` over **three** arms — the push-wanted `watch` receiver, the
fetch-wanted `watch` receiver, and a `tokio::time::interval`. Push-wanted → §4.2 for every
remote. Fetch-wanted and tick → §4.1 for every remote, the same path from the same code.

### 4.0 What the renderer can ask for, and what it can see

`04-live-status.md` §5.3 needs an operator-driven fetch (`[p]` on the Status panel) and an
honest in-flight indicator. An earlier draft of this section had a push-wanted channel and an
interval and nothing else, which stage 4 cannot build on: there was no fetch trigger, and every
field in `GitState` was written only on *completion*, so "fetching…" could not be rendered
without inventing state. Four concrete additions, which are stage 4's contract on this stage:

1. **A fetch-wanted `tokio::sync::watch::Sender<u64>`**, mirroring the push-wanted one, held on
   the `Runtime` so a renderer can signal it. `watch` rather than `Notify` because coalescing is
   then free — several presses of `[p]` before the task wakes are one wake — and because a
   signal can never be lost, which is the same property that made `watch` right for the push
   side.
2. **A third `select!` arm** on that receiver, running the same §4.1 fetch-and-fast-forward path
   the interval arm runs. Not a second implementation; the arm calls the same function.
3. **An in-flight marker written before the work and cleared after**, on **both** the timed and
   the forced path:

   ```rust
   /// A fetch is running right now. Written before the `spawn_blocking` and cleared after it,
   /// on every exit including an error, so the UI can say "fetching" without inferring it.
   pub fetching: bool,
   ```

   on `GitState` (§6). Every other field there is written only on completion, which is correct
   for a *result* and useless for a *progress* indicator. The clear must be unconditional — a
   fetch that returns `Err` clears it as it records the failure — or a single unreachable host
   pins the marker on forever.
4. **`Relation::RemoteAhead`'s semantics are settled here, not in stage 4.** `Relation` records
   the relation **as the fetch found it, before the merge**, and the fast-forward that follows
   moves it to `InSync` on the same pass. So `RemoteAhead` is genuinely near-unobservable in the
   steady state and is observable exactly when it matters: while `fetching` is true, and after a
   fast-forward that failed. Stage 4's `store BEHIND` chip is therefore kept, and it means "a
   fast-forward is due or in progress", which is a state an operator can act on. Recording the
   post-merge relation instead would make the field a duplicate of `InSync` and lose the failed
   -merge case entirely.

`watch::Sender::send` fails only when every receiver is gone, i.e. the task is dead. That is not
an operator-caused failure and the renderer ignores it (stage 4 §5.3); the task being gone is
already visible as the store chip's age freezing.

### 4.1 Fetch and the fast-forward decision, per remote

```
git ls-remote --exit-code <url> refs/heads/main
```

- **128** → `Relation::Absent` if the ensure step has not run, else a transport failure
  (`GitErr::GitFailed`) recorded on that remote. Cheap, one round trip, and it distinguishes
  "unreachable" from "empty" before anything writes to `.git`.
- **2** → repo exists, branch absent → `Relation::Absent`; nothing to fetch, a push will create it.
- **0** → proceed:

```
git -C <store> fetch --quiet <url> refs/heads/main
git -C <store> rev-parse HEAD          -> L
git -C <store> rev-parse FETCH_HEAD    -> R
```

`rev-parse HEAD` exits **128** on an unborn branch (verified), which is the state of a store
that has no committable file yet — see §8.2 step 5. The cycle must treat "local HEAD is unborn"
as `Relation::Absent` for the local side and skip to the fast-forward, not surface a
`GitErr::GitFailed`: a store with no commit yet has nothing that could conflict, so an incoming
`main` is by definition a fast-forward from nothing and `merge --ff-only FETCH_HEAD` takes it.

Then, exactly (exit codes verified; `2` and above are errors, not answers):

| Test | Result |
|---|---|
| `L == R` | `Relation::InSync` |
| `git -C <store> merge-base --is-ancestor L R` → 0 | `Relation::RemoteAhead` → fast-forward |
| `git -C <store> merge-base --is-ancestor R L` → 0 | `Relation::LocalAhead` → push |
| both → 1 | `Relation::Diverged` |
| either → ≥2 | `GitErr::AncestryUndecidable { argv, code }` |

**Fast-forward** holds `Claim::mutate()` (it rewrites the worktree), never a second
`Claim::take` — §3 item 2:

```
git -C <store> merge --ff-only FETCH_HEAD
```

then `enforce_store_modes(store)` — mandatory, and for a wider reason than first recorded. The
merge writes every file it *touches* at umask: a newly-arrived file landed 0644, **and so did an
existing keystore whose content the merge updated**, even though this machine had chmodded it
0600 (verified). Only files the merge left alone kept 0600. So the fixup is not a
new-files-only tidy — without it, every remote edit to an existing keystore silently widens that
keystore's mode.

`fetch` itself writes only into `.git` and runs **without** the lock. `push` reads only `.git`
and runs **without** the lock; HEAD advancing between the ancestry check and the push is
harmless, the push simply carries more.

**Divergence**: nothing is merged, nothing is pushed, nothing is deleted. `Relation::Diverged` is
written into the status, logged once at `warn` per transition (not per tick), and the daemon
keeps serving. This is decision 3's "surfaced state, never a silent overwrite". Verified: on
divergence `merge --ff-only` exits 128 leaving the worktree byte-identical, and `push` exits 1
leaving the remote untouched — so even a bug that skipped the check could not lose data.

### 4.2 Push, per remote

```
git -C <store> push --quiet <url> refs/heads/main:refs/heads/main
```

`push_all` attempts **every** remote — the existing rationale at
`crates/hc-daemon/src/backup.rs:242-248` (one dead host must not block the others) is correct and
survives. What changes is the return:

- at least one remote succeeded → `Ok(())`
- **every** remote failed → `Err(GitErr::AllRemotesFailed { failures })`

That is the precise fix for the swallow at `backup.rs:258-268`. Per-remote outcomes are recorded
in `GitStatus` (§6) regardless, so a partial failure is visible even when the call returns `Ok`.

### 4.3 Manual forced pull — what it does differently

The background task **can never** move past divergence. The manual forced pull is the only path
that can, and it does so by **discarding local history**, not by merging:

```
git -C <store> fetch --quiet <url> refs/heads/main
git -C <store> show FETCH_HEAD:keyring.json        <- vault pre-check, BEFORE any write
git -C <store> reset --hard --quiet FETCH_HEAD
git -C <store> clean -fdq
enforce_store_modes(store)
```

Under `Claim::mutate()`, and only from an explicit operator action (`hot_cheese backup pull --force`
or the console's Backup screen with its existing `Confirm` at
`crates/hc-console/src/menu.rs:825-835`).

The `git show FETCH_HEAD:keyring.json` step is **strictly better** than today's guard. Today
`require_vault` runs before rsync against the *local* keyring and again *after* rsync has already
overwritten it (`backup.rs:229-240`) — the wrong-vault keyring is on disk by the time it is
caught. Here the remote blob is parsed from the object database and `require_vault` runs before
`reset --hard` touches anything. `VaultSite` and `require_vault` survive unchanged; the
`VaultSite::Pulled` arm now means "the vault the remote's committed keyring declares".

`clean -fd` (no `-x`) honours the exclude, so an in-flight `*.hctmp` from another writer is not
deleted — **but only because `ensure_repo` writes `.git/info/exclude` on every open**. Re-run
during audit against a fresh clone, whose default exclude has no `*.hctmp` rule, `clean -fd`
deleted the temp file. The ensure step is therefore a precondition of this operation, not a
convenience; §8.2 step 3 must run before any forced pull, including immediately after a clone.

**This is the one operation in the stage that can destroy key material, and the plan must say so
where the operator can read it.** Verified: `reset --hard FETCH_HEAD` deletes every keystore that
was committed **locally only** — a key generated on this machine and never pushed is gone from
the worktree — and `clean -fd` then deletes every untracked non-excluded file. The old rsync
`pull` could not do this: it had no `--delete`, so it merged and left local-only files alone
(`backup.rs:135-141`). That is a **real reduction in safety at this one call site**, traded for
the fast-forward property, and it must be handled rather than noted:

- Before `reset --hard`, diff the two trees for names present locally and absent remotely:
  `git -C <store> diff --name-only --diff-filter=D HEAD FETCH_HEAD`, plus
  `git -C <store> ls-files --others --exclude-standard`.
- The confirmation must **name those files and their count**, not say "discards local history".
  An operator who is told "this deletes TREASURY, OPS and 1 untracked file" can stop; one told
  "discards local history" cannot tell whether that means commits or keys.
- The local commits are not recoverable from the remote, but they are still in the local
  reflog and object store until `gc` runs, so the escape hatch exists — say it in the notice.

---

## 5. Errors

New module `crates/hc-daemon/src/git_store.rs` replaces `crates/hc-daemon/src/backup.rs`.

`err_mac` is a **git dependency pinned at rev `08f6335`** (`Cargo.toml:25`, allowed by
`deny.toml:66`); it is not vendored in this repo, so read it from that checkout, not from a
`bedrock/` path. At that rev `create_err_with_impls!` has exactly two sections: before the `;`,
unit variants and single-type tuple variants — and **every tuple variant gets an automatic
`From`**, which is what makes `?` unwrap library errors with no `map_err`; after the `;`, struct
variants with named fields and no `From`. There is no `#[from]` and no `#[error(...)]` attribute
in this repo's idiom — `Display` is derived from `Debug` by the macro
(`write!(f, "{:?}", self)`), so `#[derive(Debug)]` is load-bearing, not decorative. Primitives
(`i32`, `String`) must **never** be tuple variants: that would generate `From<i32> for GitErr`.
Today's `RsyncFailed(i32)` (`backup.rs:25`) does exactly that and is deleted with the rest;
`SyncErr::RsyncFailed { code }` (`crates/hc-bundle/src/sync.rs:207`) is the idiom to copy.

The macro at this rev emits **no `impl std::error::Error`** — that is why `keyring.rs:30` adds
one by hand for `VaultIdErr`. `BackupErr` has none today and `GitErr` needs none, unless
something nests it as a `source`; if it ever does, add the one-line impl rather than switching
error crates.

```rust
create_err_with_impls!(
    #[derive(Debug)]
    pub GitErr,
    NoBackupRemote,
    HeadNotOnBranch,
    StdIo(std::io::Error),
    Keyring(KeyringErr),
    VaultId(VaultIdErr),
    Grant(hc_sign::grant::GrantErr),
    Utf8(std::string::FromUtf8Error),
    Json(serde_json::Error)
    ;
    GitFailed { argv: Vec<String>, code: i32 },
    GitSignal { argv: Vec<String> },
    SshFailed { host: String, code: i32 },
    SshSignal { host: String },
    AncestryUndecidable { argv: Vec<String>, code: i32 },
    Diverged { host: String, local: CommitId, remote: CommitId },
    VaultMismatch { site: VaultSite, requested: Option<VaultId>, found: Option<VaultId> },
    LocalKeyringMissing { store: PathBuf },
    AmbiguousRemoteTryPullVault { vaults: Vec<VaultId> },
    BadCommitId { value: String },
    AllRemotesFailed { failures: Vec<RemoteFailure> }
);

/// One remote's reason for refusing a push, kept so a total failure names every cause.
#[derive(Debug)]
pub struct RemoteFailure {
    /// The ssh target from `config.backup_remotes`.
    pub host: String,
    /// Shared because a status render must be able to read it without consuming it.
    pub cause: Arc<GitErr>,
}
```

`Arc<GitErr>` supplies the indirection that makes the recursive variant sized, and lets §6 hold
the same typed cause the caller returned. No error is ever formatted to a string.

Child-process stderr is **not** put in a variant. It is logged at the call site with
`tracing::warn!(stderr = %…)`, exactly as `crates/hc-bundle/src/sync.rs:200-210` already does, and
the human-readable copy for the UI lives in the status record (§6), which is a display type, not
an error.

`CommitId` mirrors `VaultId`'s shape (`crates/hc-core/src/keyring.rs:36-72`) rather than being a
`String`:

```rust
/// A git object id, 40 lowercase hex on the wire.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CommitId([u8; 20]);
```

with `FromStr` (rejecting anything that is not 40 hex, via `GitErr::BadCommitId`), `Display` as
hex, and `Debug` delegating to `Display` — the same three impls `VaultId` has. Fixed at 20 bytes
because this code creates every repository it reads and never opts into `extensions.objectFormat
= sha256`; a future git that flipped the default would produce a 64-hex line and fail loudly at
`BadCommitId` rather than silently truncating.

### Error plumbing

- `crates/hc-cli/src/lib.rs:88` `Backup(hc_daemon::backup::BackupErr)` → `Git(hc_daemon::git_store::GitErr)`.
- `crates/hc-console/src/menu.rs:59` `Backup(hc_daemon::backup::BackupErr)` → `Git(hc_daemon::git_store::GitErr)`.
- `CliErr::NoBackupRemote` (`crates/hc-cli/src/lib.rs:78`) and `MenuErr::NoBackupRemote`
  (`menu.rs:43`) are **deleted**; `GitErr::NoBackupRemote` is the one variant, reached through the
  nested `From`. `scripts/dryrun.sh:1183-1184` asserts on the variant *name*, which is unchanged.
- `CliErr::VaultAlreadyAdopted` (`crates/hc-cli/src/lib.rs:108`, described in the error-ordering
  comment at `:68`) is **deleted** with `backup adopt` (§7); delete the comment line too.

---

## 6. Status the UI consumes (stage 4)

**This section is the single definition of the git-store status shape.** Locked decision 14:
stage 4 owns no status of its own; it reads what this stage and stage 3 publish and owns only
its own pending-approvals gauge. `04-live-status.md` §1 references this section rather than
restating it, and its earlier invented `StoreState`/`BackupState` mirrors are deleted. If a
field here changes, stage 4's `band_source` is the one place the compiler catches it.

Follows the `LogRing` pattern the design doc points at
(`crates/hc-console/src/status.rs:38-59`): an `Arc<_>` owned by the runtime, a `parking_lot`
`Mutex` inside, a `Clone` snapshot taken per render. `parking_lot` per CLAUDE.md; no `std` locks.

**The clock, once, for both stages.** Locked decision 12: every timestamp in this repo's status
types is `u64` Unix **seconds**. The repo's existing wall clock is `hc_sign::grant::now_ms()`
(`crates/hc-sign/src/grant.rs:174-178`), which returns milliseconds and
`Result<u64, GrantErr>`. A sibling is added beside it rather than dividing at each call site,
because "nothing type-checks the difference" is exactly what decision 12 exists to stop:

```rust
/// Seconds since the Unix epoch.
pub fn now_secs() -> Result<u64, GrantErr>
```

`hc-daemon` already depends on `hc-sign` (`crates/hc-daemon/Cargo.toml`), so both
`git_store.rs` and stage 3's `bundle_poll.rs` reach it with no new dependency. `GitErr` gains
`Grant(hc_sign::grant::GrantErr)` as a nested variant so `?` unwraps it with no `map_err`;
stage 3's `PollErr` already carries the same variant for the same reason.

```rust
/// Everything the git-store subsystem knows, shared with whichever renderer is drawing.
pub struct GitStatus {
    inner: Mutex<GitState>,
}

impl GitStatus {
    /// One consistent snapshot; the lock is never held across a render.
    pub fn snapshot(&self) -> GitState { self.inner.lock().clone() }
}

/// One snapshot of the git store, cloned out for a render.
#[derive(Clone, Debug)]
pub struct GitState {
    /// This install's vault, which names its bare repo on every remote.
    pub vault: VaultId,
    /// Local `HEAD` after the last commit this process observed; `None` before the first commit.
    pub head: Option<CommitId>,
    /// Unix seconds of the last commit this process made.
    pub last_commit_at: Option<u64>,
    /// A fetch is running right now; the one field written before the work, not after (§4.0).
    pub fetching: bool,
    /// One entry per configured remote, in `config.backup_remotes` order.
    pub remotes: Vec<RemoteState>,
}

/// What this install last learned about one backup remote.
#[derive(Clone, Debug)]
pub struct RemoteState {
    /// The ssh target from `config.backup_remotes`.
    pub host: String,
    /// The remote folder holding `<vault>.git`.
    pub folder: String,
    /// What the last completed fetch found, as it found it, before any merge (§4.0 item 4).
    pub relation: Relation,
    /// The commit the last completed fetch found on the remote's `main`.
    pub remote_head: Option<CommitId>,
    /// Unix seconds of the last successful push.
    pub last_push_ok_at: Option<u64>,
    /// Unix seconds of the last successful fetch.
    pub last_fetch_ok_at: Option<u64>,
    /// The most recent failure, cleared by the next success against this remote.
    pub last_failure: Option<Failure>,
}

/// How local history stands against one remote's `main`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    /// No fetch has completed against this remote yet.
    Unknown,
    /// The remote has no repository, or no `main`, for this vault.
    Absent,
    /// Local and remote are the same commit.
    InSync,
    /// Local has commits the remote does not; a push is due.
    LocalAhead,
    /// The remote has commits local does not; a fast-forward is due.
    RemoteAhead,
    /// Both sides moved; only a forced pull resolves it.
    Diverged,
}

/// One recorded failure against a remote.
#[derive(Clone, Debug)]
pub struct Failure {
    /// Unix seconds the failure was recorded.
    pub at: u64,
    /// What was being attempted.
    pub op: GitOp,
    /// The typed cause, shared so a render reads without consuming.
    pub cause: Arc<GitErr>,
    /// The child's stderr, for the operator to read; empty when there was none.
    pub stderr: String,
}

/// Which git operation a failure came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitOp { EnsureRemote, Commit, Fetch, Merge, Push, ForcedPull }
```

`Relation::Unknown`, `head: None`, `remote_head: None` and `last_*_at: None` are genuine values
("no fetch has happened", "nothing has been committed yet"), not failure signals, so `Option`
here is correct per CLAUDE.md.

`remote_head` is `R` — the `rev-parse FETCH_HEAD` §4.1 already runs on every fetch — kept rather
than discarded because stage 4's Status panel names both commit ids on the divergence line, and
there is no other source for the remote one. `GitErr::Diverged { host, local, remote }` (§5)
carries them, but the background task's divergence is a *state* written into `Relation`, not an
error returned to anyone, so nothing in `GitStatus` would hold that variant. Recording `R` costs
a 20-byte copy on a path that already parsed it.

Stage 4 renders one line per remote: `host`, `relation`, age of `last_push_ok_at`, and the
`last_failure` when present. That is the "last push failed" the design doc demands, and it is the
exact opposite of today's swallow.

### RECONCILED with stage 4

An earlier revision of this section carried a long AUDIT box listing seven axes on which this
stage and `04-live-status.md` disagreed — aggregate vs per-remote, `Copy` vs `Vec`, whether a
failure reason may live in a status record, `SystemTime` vs epoch integers, and who writes the
backup state. **Locked decision 14 settles all of them in this stage's favour by construction:**

> Stage 4 owns no status of its own. It reads what stages 2 and 3 already publish and owns only
> the pending-approvals gauge. Three parallel status structs with three writers was the third
> copy of the same idea.

So the shape above is the shape, and stage 4's revision has deleted its `StoreState`,
`BackupState` and `PeerState` mirrors. The two axes that were genuinely open are settled as:

- **Per-remote, not aggregate.** One diverged remote out of three is the fact the operator has
  to act on; a count cannot express it.
- **The typed cause lives in the record.** `Arc<GitErr>` supplies the `Clone` stage 4 said was
  impossible. `stderr: String` stays too, and stage 4's objection to it was not wrong in
  principle — it is a human-readable blob in a status struct. It is kept because it is the only
  place a child's diagnosis survives, and the cost is bounded: stage 4's render clones
  `GitState` per tick, so the string is copied ~8×/s while a list is on screen. If that cost
  ever matters, the fix is a cheap projection on this side, not a second status struct on
  stage 4's.

The console's own `menu.rs:566` / `:622` push sites are deleted by §7, and `menu.rs:814` becomes
the git push — so **this stage's chokepoint and background task are the only writers of
`GitStatus`**, and stage 4 writes none of it.

---

## 7. Deletion list

No shims, no reexports. Every path below is fixed at the call site.

### Deleted outright

| Location | What |
|---|---|
| `crates/hc-daemon/src/backup.rs:1-14` | module doc describing the rsync design |
| `crates/hc-daemon/src/backup.rs:21-37` | `BackupErr` including `RsyncFailed(i32)`, `RsyncSignal`, `SshSignal`, `SshFailed` |
| `crates/hc-daemon/src/backup.rs:68-74` | `store_absent` — the only `read_dir` that would count `.git` (§0.3) |
| `crates/hc-daemon/src/backup.rs:105-109` | `dir_with_trailing_slash` |
| `crates/hc-daemon/src/backup.rs:111-117` | `remote_dir` |
| `crates/hc-daemon/src/backup.rs:119-129` | `rsync_push_args` |
| `crates/hc-daemon/src/backup.rs:131-141` | `rsync_pull_args` |
| `crates/hc-daemon/src/backup.rs:143-153` | `run_rsync` |
| `crates/hc-daemon/src/backup.rs:155-170` | `ssh` (a git-specific runner replaces it; one `ssh` survives for §8.2 enumeration and remote init) |
| `crates/hc-daemon/src/backup.rs:209-221` | `push` |
| `crates/hc-daemon/src/backup.rs:223-240` | `pull` |
| `crates/hc-daemon/src/backup.rs:242-269` | `push_all` |
| `crates/hc-daemon/src/backup.rs:288-343` | the **five** rsync-argv tests — they assert a `format!`, which is the pattern CLAUDE.md bans; §9 replaces them with one real invariant |
| `crates/hc-daemon/src/backup.rs:377-392` | `store_absent` tests |
| `crates/hc-daemon/src/lib.rs:7` | `pub mod backup;` → `pub mod git_store;` |
| `crates/hc-daemon/src/lib.rs:790-802` | `backup_after_mutation` |
| `crates/hc-cli/src/lib.rs:1033-1041` | `best_effort_backup_push` |
| `crates/hc-cli/src/lib.rs:659`, `:679`, `:896`, `:1020` | its four call sites |
| `crates/hc-cli/src/lib.rs:927-936` | the `store_absent` auto-pull block in `cmd_serve` — replaced by the runtime's clone-if-absent (§8.3) |
| `crates/hc-cli/src/lib.rs:262-263` | `BackupCmd::Adopt` and its doc line |
| `crates/hc-cli/src/lib.rs:970-980` | `cmd_backup`'s `Adopt` arm |
| `crates/hc-cli/src/lib.rs:108`, `:68` | `CliErr::VaultAlreadyAdopted` and its line in the error-ordering comment |
| `crates/hc-cli/src/lib.rs:78` | `CliErr::NoBackupRemote` |
| `crates/hc-console/src/menu.rs:43` | `MenuErr::NoBackupRemote` |
| `crates/hc-console/src/menu.rs:566` | `backup::push_all` after `generate` |
| `crates/hc-console/src/menu.rs:622` | `backup::push_all` after `add` |

### Not deleted — corrections found in audit

| Location | Why it survives |
|---|---|
| `crates/hc-daemon/src/lib.rs:854-856` | This **is** stage 1's chokepoint call site, not a competing one: `01-runtime-unification.md` §7a keeps it, wrapped in `spawn_blocking` because it is the one caller on an async worker, and logs the chokepoint's `Err` rather than propagating it because the HTTP response is already written. Stage 2 replaces the callee's body, not this site. |
| `crates/hc-console/src/menu.rs:814` | `backup::push_all` in `backup_screen` **becomes the git push**; it is not deleted. `01-runtime-unification.md` §7a is explicit that the Backup → Push action is **not** a chokepoint caller and "must keep failing loudly, because the operator asked for a push". Deleting it removes the console's only push action, and contradicts §7's own reason for keeping the `backup push` subcommand. |

Both entries were checked against stage 1 during reconciliation and stage 1 now names them in
§7a explicitly, so the two plans cannot drift apart on either.

The two remaining console `push_all` calls go because the chokepoint covers them **and more**:
today `init` (`crates/hc-cli/src/lib.rs:575`), `enroll` (`:620`, and console `menu.rs:890`),
`backup adopt` (`:978`) and `bootstrap-from` (`crates/hc-cli/src/bootstrap.rs:646-649`) mutate the
store and push **nothing**. Six of the seventeen mutation sites are hooked today; the chokepoint
hooks all of them.

### Moved into `git_store.rs` (moved, not reexported; callers updated)

`VaultSite` (`backup.rs:39-46`), `LocalVault` (`backup.rs:48-66`), `local_vault`
(`backup.rs:76-86`), `require_vault` (`backup.rs:88-103`), the vault-selection logic of
`pull_vault` (`backup.rs:186-207`) and its `AmbiguousRemoteTryPullVault`, and the test
`a_pull_refuses_every_vault_but_the_requested_one` (`backup.rs:345-375`) — it pins a real
invariant that the forced pull still depends on, unchanged.

`list_vaults` (`backup.rs:172-183`) survives with one change: it parses `v_<32 hex>.git` and
strips the suffix. It remains the one `ssh` call left in this subsystem, because git can probe a
named repo but cannot enumerate a directory.

### CLI surface

`backup push` **stays** and becomes `git push`. Justification against the "delete redundant
surface" rule: in a runtime session the background task retries, but a pure-CLI session
(`hot_cheese add` with no daemon) has no task, so a push that failed because the host was asleep
has no other retry. It now returns `Err` when every remote failed.

Final surface:

| Command | Behaviour |
|---|---|
| `backup status` | print `GitState`; no network |
| `backup push` | push every remote; `Err(AllRemotesFailed)` only when all failed |
| `backup fetch` | fetch + fast-forward-only merge; `Err(Diverged)` on divergence |
| `backup pull --force [--vault <id>]` | §4.3; refuses without `--force` |
| `backup list` | enumerate `v_<hex>.git` on the first remote |
| ~~`backup adopt`~~ | **deleted** — adoption is automatic at ensure time |

`01-runtime-unification.md` §4 enumerates which subcommands take the store claim, from the
surface as it stands today. Two entries change: `backup adopt` leaves the list (deleted), and
the two new verbs join it — **`backup fetch` takes the claim** (it can `merge --ff-only` into
the worktree) while **`backup status` does not** (no network, no write, and an operator must be
able to ask "is my backup healthy?" while the console is open, which is the same reason
`backup list` is already exempt). Stage 1 §4 now records both changes, so the lists agree.

### Docs and scripts

| Location | Change |
|---|---|
| `README.md:75-79` | feature bullet: rsync → git |
| `README.md:186` | prerequisites: add `git`, note the **remote** now needs `git` instead of `rsync` |
| `README.md:375-376`, `:411` | `serve` auto-pull → auto-clone |
| `README.md:412-415` | command table: rewrite, drop `adopt`, add `status`/`fetch`, `pull --force` |
| `README.md:483` | `backup_remotes` description: rsync target → git remote; document `backup_fetch_secs` |
| `README.md:508`, `:510` | `/evm_generate` / `/solana_generate` → "commit and push" |
| `README.md:1226-1244` | the Backups section: rewrite around commit/push/fetch/ff-only/divergence |
| `README.md:1246-1270` | Vaults section: `<folder>/<vault_id>/` → `<folder>/<vault_id>.git`, the two rsync argv lines → the git ones, and the per-vault command table below the prose (which still lists `backup adopt`) |
| `scripts/dryrun.sh:1162-1196` | phase 8: `backup adopt` no longer fails with `VaultAlreadyAdopted` (deleted) — `:1177-1178` go with it; `backup list`/`backup pull` still fail with `NoBackupRemote` but from `GitErr`; the push-target assertion at `:1186-1195` becomes `<folder>/<vault>.git`; add an assertion that `<store>/.git` exists and `git -C <store> status --porcelain` is empty after every earlier phase — a zero-network, zero-biometric check that the store self-commits |
| `scripts/dryrun.sh:348` | the phase-summary line still says "no ssh and no rsync" |
| `scripts/dryrun.sh:277`, `:597-602` | unchanged (`backup_remotes = []` still means no network) |
| `MIGRATION.md:336`, `:468`, `:477` | **missed in the first pass.** "travels with the rsync backup" / "the rsync backup replicates only the store dir" → git |
| `MIGRATION.md:500` | the literal `rsync -az <store>/ <host>:~/<folder>/<vault_id>/` → the git push |
| `MIGRATION.md:516`, `:653` | `[[backup_remotes]]` + `backup push` walkthrough: the remote now needs `git`, and the first push creates a bare repo |
| `MIGRATION.md:527` | the vault-mismatch guard is described in terms of `rsync -az` having no `--delete`; under §4.3 the guard is `git show FETCH_HEAD:keyring.json` **before** any write, and the reasoning changes with it |
| `MIGRATION.md:536` | documents `hot_cheese backup adopt`, which is **deleted** — adoption is automatic at ensure time |
| `MIGRATION.md:613`, `:622`, `:624` | unchanged — those are **bundle** sync's rsync, which decision 4 keeps |

---

## 8. Ordered steps

Each step leaves the workspace building in release with tests passing.

### 8.1 `enforce_store_modes` + the config field

Add to `crates/hc-core/src/crypto/envelope.rs`, beside `write_private_file`:

```rust
pub fn enforce_store_modes(store: &Path) -> std::io::Result<()>
```

Sets the store dir and `policies/` to `0o700`, every regular file in both to `0o600`, and
**skips `.git` entirely** (never descends into it). Justified as a function under CLAUDE.md
because it is called from four places (commit chokepoint, ff-merge, forced pull, post-clone) and
because it is the subject of the mandated test.

`std::io::Result` is chosen to match its neighbour `write_private_file` (`envelope.rs:296`)
rather than `atomic_write`'s `Result<(), EnvErr>`; either works at the call sites, since
`GitErr::StdIo` and `EnvErr`'s own `StdIo` both give `?` an automatic `From`. **AUDIT: pick one
and be consistent within `envelope.rs` — the file currently uses both conventions.**

Add `backup_fetch_secs: Option<u64>` to `Config` (`crates/hc-core/src/config.rs:44`) and its
accessor beside `bundle_watch_secs` (`:283-285`). Update the struct literal in `cmd_init`
(`crates/hc-cli/src/lib.rs:526-539`) — it names every field, so it will not compile until it does.

**Verify**: `cargo build --release`; `cargo test --release -p hc-core`.

### 8.2 `git_store.rs`: the runner, `ensure_repo`, `ensure_remote`

New `crates/hc-daemon/src/git_store.rs`, added **beside** `backup.rs`:
`crates/hc-daemon/src/lib.rs:7` gains `pub mod git_store;` and keeps `pub mod backup;` until
§8.6.

**Ordering correction.** The first draft deleted `backup.rs` here, which does not leave a
compiling tree and so breaks this section's own opening promise: `backup::` still has sixteen
live callers at this point — `hc-daemon/src/lib.rs:798`, `hc-cli/src/lib.rs:88`, `:930`, `:932`,
`:934`, `:946`, `:954`, `:955`, `:963`, `:964`, `:1038`, and `hc-console/src/menu.rs:59`,
`:566`, `:622`, `:814`, `:824`, `:836` — and the last of them is not rewritten until §8.6.
`backup.rs` is deleted in §8.6, in the same commit that removes its final caller. This is not a
shim and does not violate the no-shims rule: nothing is re-exported, no call is forwarded, and
the old module is gone by the end of the stage. Two modules coexisting for two steps of one
stage is the only ordering that keeps every intermediate tree green.

The runner — every git invocation goes through it:

```rust
fn git(store: &Path, argv: &[&str]) -> Result<Vec<u8>, GitErr>
```

- `Command::new("git")` with `-C <store>` prepended, then
  `-c commit.gpgsign=false -c core.hooksPath=/dev/null` before the subcommand. Both are
  defences against the operator's own `~/.gitconfig`, both reproduced: a global
  `commit.gpgsign = true` made `git commit` fail trying to sign (and with a real gpg can block
  on a pinentry prompt, which `GIT_TERMINAL_PROMPT=0` does **not** cover), and a global
  `core.hooksPath` made a foreign `pre-commit` hook **run inside our commit**.
- `.env_remove(…)` for every git-plumbing variable that could redirect us:
  `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY`,
  `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_NAMESPACE`, `GIT_CEILING_DIRECTORIES`.
  This is not hygiene, it is the worst single hazard found in audit: **`GIT_DIR` overrides
  `-C <store>`** (verified — `git -C <other> rev-parse --git-dir` returned the `GIT_DIR` repo).
  An operator with `GIT_DIR` exported would have `add -A`/`commit` write the store's keystores
  into an unrelated repository — and then `push` them to *that* repository's remote — while
  `reset --hard`/`clean -fd` ran against the wrong worktree. Nothing else in this stage detects
  it; the only fix is to refuse the inheritance.
- `.stdin(Stdio::null())`, `.output()` — both streams **captured**, never inherited.
- `.env("GIT_TERMINAL_PROMPT", "0")` — git will not prompt for credentials on any transport.
  Verified against an unresolvable ssh host and a dead https port: rc 128 immediately, no
  prompt, no hang. `GIT_ASKPASS`/`SSH_ASKPASS` are not a hole on the paths used here — the ssh
  transport is driven by `GIT_SSH_COMMAND` with `BatchMode=yes`, which makes ssh fail rather
  than ask, and `core.askPass`/`GIT_ASKPASS` are consulted only for credential prompts that
  `GIT_TERMINAL_PROMPT=0` has already refused. `SSH_ASKPASS` needs `DISPLAY` **and**
  `SSH_ASKPASS_REQUIRE`/no tty to fire, and `BatchMode=yes` short-circuits it first.
- `.env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=3")`.
  `BatchMode=yes` and `ConnectTimeout` mirror `crates/hc-bundle/src/sync.rs:140-144` and are the
  load-bearing pair (`hc-daemon` does not depend on `hc-bundle`, so the `CONNECT_TIMEOUT_SECS = 5`
  constant is duplicated deliberately; note it in the module doc). `ServerAlive*` is the addition
  the rsync path never had: `ConnectTimeout` bounds only the TCP connect, so a host that accepts
  and then stalls would hang a background task forever; `ServerAliveInterval=5` with
  `ServerAliveCountMax=3` drops it in ~15s.
- Non-zero → `GitErr::GitFailed { argv, code }` after `tracing::warn!(stderr = %…)`; signal →
  `GitErr::GitSignal { argv }`.
- A sibling `git_status_only` returns the raw exit code for the three commands whose non-zero
  exits are *answers*, not failures: `diff --cached --quiet`, `merge-base --is-ancestor`,
  `ls-remote --exit-code`.

`ensure_repo(store) -> Result<Option<CommitId>, GitErr>`, idempotent, run at every runtime start
and at the top of every CLI `backup` subcommand:

1. If `keyring.json` has no `vault_id`, mint one and `Keyring::save` (the deleted `backup adopt`).
   If there is no `keyring.json` **at all**, mint nothing: that is the pre-`init` store, and
   `init` will write one.
2. If `<store>/.git` is absent: `git init -q --template=`, `git symbolic-ref HEAD refs/heads/main`.
3. Always: write `.git/info/exclude` = `*.hctmp\n`; `git config core.fileMode false`;
   `git config user.name hot_cheese`; `git config user.email hot_cheese@localhost`.
4. `git symbolic-ref -q HEAD` must be `refs/heads/main`, else `GitErr::HeadNotOnBranch` — an
   operator who detached HEAD by hand gets a refusal, not a mystery. `symbolic-ref` is used
   rather than `rev-parse --abbrev-ref HEAD` because only `symbolic-ref` answers on an unborn
   branch (verified: `rev-parse --abbrev-ref HEAD` is `fatal: ambiguous argument`).
5. `enforce_store_modes`, then the §3 add/diff/commit. On a pre-existing rsync store this is
   commit #1 and it contains everything already there.

The return is `Option<CommitId>` and **not** `CommitId`, which is the correct use of `Option`
under CLAUDE.md rather than a failure signal: `ensure_repo` runs before `init` has written
anything, `git add -A` then stages nothing, §3 step 3 returns without committing, and
`rev-parse HEAD` on the unborn branch exits 128 (verified). "No commit yet" is a genuine and
correct value for a store that has no file to commit. `GitState.head` (§6) takes the same
treatment.

`ensure_remote(remote, vault)` runs the two `ssh` commands in §2 and is invoked lazily: at runtime
start, and again whenever a push fails with `Relation::Absent`.

**Verify**: `cargo build --release`; `cargo test --release -p hc-daemon`; on a throwaway
`HOT_CHEESE_HOME`, `hot_cheese init` then `git -C <store> log --oneline` shows one
`hot_cheese v_… <secs>` commit and `git -C <store> status --porcelain` is empty.

### 8.3 Clone-if-absent, replacing the `serve` auto-pull

`clone(remote, vault, store)`:

```
git -c core.fileMode=false clone --quiet --branch main -- <url> <store>
git -C <store> config user.name  hot_cheese
git -C <store> config user.email hot_cheese@localhost
git -C <store> config core.fileMode false
write .git/info/exclude
enforce_store_modes(store)
```

`git clone` into an existing **empty** directory succeeds (verified), which matters because
`Backend::store_path` silently `create_dir_all`s the store
(`crates/hc-core/src/mac/mod.rs:28-36`) before anything else runs. The trigger is
`<store>/keyring.json` being absent — not "the dir is empty", which `store_absent` used and which
`.git` would have broken (§0.3). The vault is chosen by exactly today's rule
(`backup.rs:186-207`): explicit → this install's id → the remote's single vault, refusing to guess
between several with `AmbiguousRemoteTryPullVault`.

`--branch main` is mandatory, not tidiness: the bare repo's HEAD is `refs/heads/master` unless
§2's `symbolic-ref` ran, and a plain `git clone` of it checks out **nothing** while still
exiting 0 (verified).

**Two ordering constraints the trigger creates, both verified:**

- `git clone` into a dir holding **any** file is `fatal: … not an empty directory`, rc 128
  (verified). "keyring.json absent" does **not** imply "dir empty": a store can hold a stray
  `*.hctmp`, a `policies/` dir, or keystores from a half-finished `bootstrap-from`. The clone
  path must therefore check the dir is empty as well, and when it is not, refuse with a typed
  variant naming the entries rather than letting git's 128 surface as `GitFailed`. Silently
  proceeding to `ensure_repo` instead would `git init` a **second, unrelated history** in a
  store that has keystores but no keyring — precisely risk 2 below, manufactured locally.
- **Clone must run before `ensure_repo`, never after.** `ensure_repo` creates `<store>/.git`,
  which makes the dir non-empty, which makes every later clone fail 128. State the order in
  `Runtime::start`: clone-if-keyring-absent, then `ensure_repo`, then `ensure_remote`.

Delete `crates/hc-cli/src/lib.rs:927-936`.

**Verify**: two throwaway homes on one machine, remote a local bare path; `init` in A, push,
delete B's store, start B, B clones and `git -C <storeB> status --porcelain` is empty.

### 8.4 Wire the chokepoint

Replace the body of stage 1's `after_mutation` with §3 and its error type with `GitErr`; the
signature is already `Result<_, _>` (§3 item 3, decision 13), so no call site changes arity.
Delete `crates/hc-daemon/src/lib.rs:790-802`,
`crates/hc-cli/src/lib.rs:1033-1041` and its four call sites, and
`crates/hc-console/src/menu.rs:566`, `:622`. `crates/hc-daemon/src/lib.rs:854-856` and
`crates/hc-console/src/menu.rs:814` are **kept** and rewritten — see §7's "Not deleted" table.

**Verify**: `cargo build --release`; `hot_cheese generate`, `add`, `enroll` and `seal` each add
exactly one commit; two consecutive `enroll`s that change nothing add zero.

### 8.5 The background task

Add **both** `watch` channels (push-wanted and fetch-wanted, §4.0), the three-arm `select!` loop,
§4.1 and §4.2, and populate `GitStatus` including the `fetching` marker set before the
`spawn_blocking` and cleared on every exit. The fetch-wanted `Sender` is reachable from the
`Runtime`, which is what stage 4's `[p]` signals; nothing in stage 2 presses it, so this step
must not wait on stage 4 to be verifiable.

**Verify**: with `backup_fetch_secs = 5` and a local bare path as the remote, `serve` fetches on
schedule; a commit pushed into the bare repo from a second clone is fast-forwarded in, and the
newly arrived file is 0600 after the merge (the §9.1 test pins this, but check it by hand once);
sending on the fetch-wanted channel from a test harness triggers exactly one extra fetch and
several sends before the task wakes trigger one, not several.

### 8.6 CLI and console surfaces

Rewrite `BackupCmd` and `cmd_backup` (`crates/hc-cli/src/lib.rs:251-264`, `:942-983`) to §7's
table. Rewrite `BackupAction` (`crates/hc-console/src/menu.rs:270-279`) and `backup_screen`
(`:801-847`); keep the existing `Confirm` and reword it to name the files a forced pull will
delete (§4.3), not merely "discards local history". Add a `Status` action rendering §6.

This is the step that removes `backup.rs`'s last caller, so it also deletes
`crates/hc-daemon/src/backup.rs` and drops `pub mod backup;` from
`crates/hc-daemon/src/lib.rs:7`, moving `VaultSite` / `LocalVault` / `local_vault` /
`require_vault` / the `pull_vault` selection logic / `list_vaults` and the surviving test into
`git_store.rs` per §7.

**Verify**: `cargo clippy --release --all-targets -- -D warnings` clean with **no** `#[allow]`;
`hot_cheese backup status` with `backup_remotes = []` prints the local state and touches no
network.

### 8.7 Docs and dryrun

Apply §7's docs/scripts table.

**Verify**: `bash scripts/dryrun.sh` to completion on macOS; `cargo test --release --workspace`.

---

## 9. Tests

Per CLAUDE.md: only new non-trivial logic or a crucial invariant. All four drive git against
**local bare paths**, so they need no network and no ssh — `git push /path/to/x.git` uses no
transport (verified). This is why the plumbing takes a `&str` URL and the `BackupRemote → URL`
mapping is a separate one-liner: the layering is real, not test scaffolding. Shelling out from a
test is established here (`crates/hc-core/tests/boundary.rs` shells out to `cargo`).

### 9.1 `store_modes_survive_a_checkout` — mandated

*Modes and cleanliness after a checkout.* Build a store with `keyring.json`, a keystore and
`policies/x.toml`; `enforce_store_modes`; `ensure_repo`; push to a local bare repo; clone
(`--branch main`) into a second dir; assert the clone's keystore is 0644 **before** the fixup
(this is the hazard, and the probe confirms it is 0644, not a coin flip on a default umask); call
`enforce_store_modes` on the clone; assert every file is exactly 0600, the store dir and
`policies/` are 0700, and — the real invariant — `git -C <clone> status --porcelain` is **empty**,
i.e. the chmod did not dirty the tree. That last assertion is what pins `core.fileMode false` and
the skip-`.git` rule together; without either, it fails.

The test must then extend past the clone to the **merge**, because that is the wider half of the
hazard: commit a change to the *existing* keystore in the first store, push, fetch and
`merge --ff-only` into the clone, and assert that keystore is 0644 **before** the post-merge
`enforce_store_modes` and 0600 after. Verified in audit: a merge rewrites a modified tracked
file at umask, undoing a 0600 this machine had already set — so a fix that only ran after a
clone would leave every subsequent remote edit widening the mode. Without the post-merge call
this assertion fails, which is what makes it worth writing.

No `umask()` call anywhere: umask is process-global and tests share a process.

### 9.2 `divergence_is_refused_not_merged` — mandated

*Fast-forward-only refusal.* One bare repo, two clones, a commit on each, push from one. On the
other: fetch, compute the relation, assert `Relation::Diverged`; assert both
`merge-base --is-ancestor` directions returned 1; assert the worktree file set and contents are
**byte-identical** to before the fetch; assert a push returns `Err(GitErr::GitFailed { code: 1, .. })`
and the bare repo's `main` is unmoved. Pins the three-way ancestry decision, which is the one
genuinely non-trivial piece of logic in this stage.

### 9.3 `commit_skips_when_nothing_changed`

*The empty-commit guard.* `ensure_repo`, count commits, run the chokepoint twice with no store
change, assert the count is unchanged; touch a keystore, run it once, assert exactly one new
commit. Pins the `git diff --cached --quiet` 0/1/error three-way, without which every no-op
mutation would push an empty commit to every remote forever.

### 9.4 `a_pull_refuses_every_vault_but_the_requested_one` — kept verbatim

Moved from `crates/hc-daemon/src/backup.rs:345-375`, unchanged. It pins `require_vault`, which the
forced pull still depends on.

### Not written

- The five rsync-argv tests (`backup.rs:288-343`). They assert the output of a `format!`, which is
  the pattern CLAUDE.md bans. Their one real content — that two vaults never share a remote
  location — is covered by 9.2's use of two distinct bare repos plus a single assertion in 9.1
  that the URL for a vault ends in `<vault>.git`.
- Anything asserting that `git init` initializes, that `Relation` serializes, or that the status
  struct clones.

---

## 10. Risks and open questions

**Stated honestly. Where I did not verify, I say so.**

1. **History is forever, and now replicated.** Every version of every keystore stays in the
   history on every backup remote. A key removed from the store is still recoverable from any
   clone. Under rsync-without-`--delete` a deleted keystore also survived on the remote, so this
   is not a regression — but it becomes *permanent and distributed*, and no future `rm` can undo
   it without rewriting history on every remote, which `receive.denyNonFastForwards` deliberately
   forbids. **Open question for the repo owner: is that acceptable?** If not, git is the wrong
   answer for the store and the alternative is a versioned-snapshot rsync layout, which loses the
   fast-forward property that motivated this stage.

2. **Two machines sharing one vault will diverge on first git contact.** Under rsync,
   `bootstrap-from` gives B the same DEK and the same `vault_id`, and both machines rsync into one
   subtree, merging by last-writer-wins per file. Under git they will `git init` independently,
   producing two unrelated histories, and the second push is rejected as non-fast-forward
   (verified). Resolution is a one-time manual forced pull on whichever machine's store is stale.
   This is a **real migration cost, not a bug**, and it must be in the README. I deliberately did
   **not** add an auto-heal for "my history is a single genesis commit, so just take theirs": it
   would silently discard a store holding keys the remote lacks, which is exactly the silent
   overwrite decision 3 forbids.

3. **The old rsync backup is orphaned, not migrated.** On first run against a folder that already
   holds `<folder>/<vault_id>/` (plain files), the new bare repo appears beside it at
   `<folder>/<vault_id>.git`. The old directory is untouched, becomes stale from that moment, and
   is never deleted by this code. That is deliberate — it stays as a last-known-good copy — but
   the operator must be told, and told to delete it once satisfied. Nothing detects or reports its
   staleness.

   Traced step by step, first run of the new code against both an existing plain store and an
   existing plain remote folder: `ensure_repo` finds `keyring.json` with a `vault_id`, finds no
   `.git`, inits one, writes the exclude and the config, stages every existing keystore plus
   `policies/`, and makes commit #1. Nothing is deleted, nothing is rewritten, and the store's
   bytes are untouched apart from `enforce_store_modes` tightening 0644 → 0600. `ensure_remote`
   then creates `<folder>/<vault_id>.git` **beside** the existing `<folder>/<vault_id>/`, and
   the first push is to an empty repo, so it is trivially a fast-forward. **This path is safe.**

3a. **A mixed-version fleet silently stops converging, and nothing detects it.** Two machines
   that share a vault (the `bootstrap-from` case) replicate through one folder. After one
   upgrades, the old machine keeps rsyncing to `<folder>/<vault_id>/` and the new one pushes to
   `<folder>/<vault_id>.git`. The disjoint paths mean neither corrupts the other — which is the
   point of the `.git` suffix — but it also means **neither sees the other's new keys**, and
   both report success. Under rsync they converged; now they split-brain quietly until both are
   upgraded. `backup list` enumerating both `v_<hex>` and `v_<hex>.git` for the same id is a
   cheap detector: if `list_vaults` sees a plain `<vault_id>` directory next to our
   `<vault_id>.git`, say so once at `warn`, naming both paths. Cheap, and it converts a silent
   split into a visible one. **AUDIT: is that warning worth the one extra `ssh` on the ensure
   path, or is the README note enough?**

3b. **A downgrade is the one direction that does damage, and it is not guarded.** The old
   binary's push is `rsync -az <store>/ …` with no `--exclude` (`backup.rs:123-129`), so rolling
   a machine back after this stage has run would upload the whole `.git` — every historical
   version of every keystore — into the plain rsync folder. Worse in the other direction: the
   old `backup pull` merges remote plain files over the worktree without touching the index, so
   the next `add -A` commits whatever rsync happened to land. Neither is silent key *loss*, but
   both leave an inconsistent store, and nothing in either binary detects the mismatch. Say
   plainly in the README that this stage is one-way per machine.

4. **The remote's prerequisite changes from `rsync` to `git`.** A backup host chosen because it
   had rsync may not have git. There is no fallback: this stage deletes the rsync path entirely,
   per decision 3. `ensure_remote` will fail with `SshFailed { code: 127 }` and the status will
   show it, which is at least a clear diagnosis.

5. **I did not verify git's presence on a macOS box from here** — this machine is NixOS. The claim
   rests on the Xcode Command Line Tools already being a stated prerequisite
   (`README.md:183-185`) and the CLT shipping git. Confirm on the target Mac before 8.7.

6. **The cross-process store lock — stage 1 delivers it, and both adjustments are now closed.**
   `git add -A` stages a set of files. `atomic_write`'s rename makes each file atomic and says
   nothing about two. `crates/hc-cli/src/migrate.rs:184-186` (a `fs::rename` loop into the store)
   and `crates/hc-cli/src/bootstrap.rs:628-633` (a delete loop) both bypass `atomic_write`
   entirely and are exactly the writers that would tear. `01-runtime-unification.md` §4 delivers
   a real `flock(2)` on `<home>/.store.lock` and puts `migrate` and `bootstrap-from` under it.
   The two things this plan raised against stage 1 are now settled by locked decisions rather
   than left owed: the chokepoint is fallible for the commit half (decision 13, §3 item 3), and
   the in-process guard is `Claim::mutate()` on stage 1's own `Claim` rather than a second mutex
   invented here (decision 11, §3 item 2).

   Three limitations ride along, all stage 1's and none fixable here: two installs with
   different `HOT_CHEESE_HOME` pointed at the **same** store path are not excluded from each
   other; `bootstrap-serve` takes no claim, so a store being served for a bootstrap is not
   excluded from a concurrent commit; and plain `init` takes no claim either, which is safe only
   because it refuses when any prior install is visible.

12. **`GIT_DIR` and friends are the sharpest edge in the stage.** Handled in §8.2 by
    `.env_remove`, recorded here because it is the only verified path by which this design could
    write the store's keystores into a repository the operator did not choose and then push them
    there. Anything added to the runner later must go through the same scrubbed environment;
    a second `Command::new("git")` built somewhere else would reintroduce it.

13. **Commit objects leak nothing beyond the diff, with one nit.** Verified against a real
    commit: the object records only `hot_cheese <hot_cheese@localhost>` as both author and
    committer — no hostname, no operator email, no `git init` provenance. Reflogs record the same
    pinned identity and are never pushed. The nit: the author/committer line carries the
    machine's **UTC offset**, which is a coarse geographic hint and cannot be removed without
    lying about the timestamp. Accepted, and named.

7. **`ServerAliveInterval` bounds a stalled session at ~15s; nothing bounds a *slow* one.** A host
   that is reachable but transferring at 1 byte/s holds a `spawn_blocking` thread indefinitely. A
   hard wall-clock kill needs a supervising thread per child, which is more machinery than this
   stage should carry. Accepted, and named.

8. **`ls-remote` exit 128 conflates "repo absent" with "host unreachable".** The plan resolves it
   by ordering — `ensure_remote` runs first, so a 128 after a successful `ensure_remote` in the
   same cycle means unreachable — but a host that dies between the two calls is reported as
   `Absent`. Minor, and self-correcting on the next tick.

9. **IPv6 literals in `BackupRemote.host` break scp-syntax.** Carried over verbatim from the rsync
   path, which has the identical limitation. Not fixed here; note it in the README.

10. **Repo growth is unbounded and nothing rate-limits it.** `/evm_generate` over the loopback
    HTTPS listener could be scripted into thousands of commits. Nothing bounds it today either
    (each such call already triggers an rsync), and each commit is a few hundred bytes, so this is
    a monitoring concern rather than a blocker. Worth a bound if stage 4's status shows it
    growing.

11. **Where git is the wrong answer, and I agree with the design doc:** bundles. Decision 4 keeps
    them on rsync, and the reasoning at `crates/hc-bundle/src/sync.rs:1-17` is correct — one file
    per signer makes rsync-without-`--delete` an already-commutative union merge, and git would
    manufacture conflicts on a path that has none. Nothing in this stage touches `hc-bundle`.
