# hot_cheese upgrade — locked design decisions

Input to every plan file in this directory. Decisions here are settled by the repo owner.
A plan that contradicts this file is wrong.

## Scope

Five workstreams, staged. Each stage must build in release and pass its tests on its own,
before the next begins.

| Stage | File | Workstream |
|---|---|---|
| 1 | `01-runtime-unification.md` | One runtime, two renderers + cross-cutting dedupe |
| 2 | `02-git-store.md` | Git-backed store, automatic push/fetch |
| 3 | `03-bundle-autopoll.md` | Background bundle polling from tailnet peers |
| 4 | `04-live-status.md` | Self-updating status in the console |
| 5 | `05-sign-path-collapse.md` | Delete the human raw-JSON sign path |
| 6 | `06-typed-admission.md` | Typed-only admission: declared signatures + EIP-712 |

`06-typed-admission.md` supersedes the "half B" section of `05-sign-path-collapse.md`,
which was written against an earlier, stricter reading of decision 7.

## Locked decisions

1. **One runtime, two renderers.** A single `Runtime` owns the TLS listener on
   `config.port()`, the adapter unix sockets, one main-thread approver fed over mpsc, the
   background tasks, and a store lock. `hot_cheese` selects the terminal renderer;
   `hot_cheese serve` selects the headless renderer. There is no second listener setup, no
   second approver, no second signal handler, no second set of background tasks.

2. **One approval policy: every privileged operation prompts.** The console's stricter
   behaviour wins. `Read`, `Generate`, `Address` and `Sign` all reach the approver. The
   headless renderer keeps the typed refusal when there is no terminal; it must not
   degrade into a generic denial.

3. **The store is a git repository.** Versioning replaces the hand-rolled freshness
   guessing. Mutations auto-commit; backup push is a git push; the freshness probe is a
   fetch; a merge is applied only when it is a fast-forward. Divergence is a surfaced
   state, never a silent overwrite. The rsync backup transport is deleted, not kept
   alongside.

4. **Bundles stay on rsync.** Union merge over per-signer, digest-named files is already
   correct, idempotent and commutative (proven by tests in `crates/hc-sign/src/bundle.rs`).
   Git there manufactures conflicts for no gain.

5. **Signing is MCP → bundle → viewer → sign.** The human raw-JSON-intent path is deleted:
   the `hot_cheese sign [--file]` subcommand and the console's type-a-file-path Sign screen
   both go. The HTTPS `/sign/<KEY>` route and the adapter sockets stay — that is how
   services request signatures.

6. **No new calldata builders.** Transactions are proposed over MCP. The CLI does not grow
   intent-construction helpers.

7. **Typed-only. There is no untyped option.** The daemon signs only what it can fully
   deconstruct into typed data and evaluate against the policy. Anything else is refused
   before any prompt — never rendered as raw hex for a human to eyeball. Every path that
   currently degrades to "unknown selector", "could not decode", `Alarm::Undecoded`,
   `Alarm::BatchMalformed`, `Body::Undecoded` or `Body::Unexpanded` and still permits a
   signature is deleted, not downgraded to a warning.

   **The governing rule: the daemon decodes against a shape the POLICY declared, never
   against a shape the REQUEST described about itself.** This applies to both halves.

   7a. **Calls.** Policy rules declare full canonical signatures — `transfer(address,uint256)` —
   instead of bare 4-byte selectors. The selector is derived from the declared signature,
   so anything policy permits is decodable by construction, and the current hole where an
   operator allow-lists a selector nothing can decode (`crates/hc-sign/src/policy.rs:195-199`)
   closes structurally. The 4-byte selector allow-list is replaced, not kept alongside.

   7b. **EIP-712 typed data.** A first-class intent kind beside `safe_tx`. Policy declares
   the domain and the complete struct schema; a request must match a declared schema
   exactly. The request's self-declared `types` map is never trusted for rendering or
   admission — otherwise the requester chooses the field names the human reads. Field-level
   constraints (address allow-lists, integer ceilings, deadline windows) are part of the
   rule, since an unconstrained permit is an infinite approval to anyone.

   7c. **Shapes required:** arbitrary operator-declared schemas, with EIP-1271 Safe messages
   as one such declared schema rather than special-cased code.

   7d. **Bare ETH transfer** (empty calldata, non-zero value) stays refused. It is already
   refused today by the policy layer's `NoSelector`, not by the decoder; no new
   value-transfer rule kind is added.

   7e. **Unannotated contracts still sign.** Annotation is additive by construction
   (`crates/hc-sign/src/adapter/annotate.rs:1-7,56-74`); making a missing `[[token]]` or
   `[[label]]` a refusal would mean a fresh `init` could sign nothing.

8. **One configured port. REVISED by the owner.** Both renderers bind `config.port()`
   (default `5555`), and a console reverse tunnel publishes that same number as its remote
   port. There is no per-renderer or per-tunnel port choice. `scan_stranded` refuses startup
   when it sees an earlier process forwarding into that port. The scan remains best effort:
   it runs once, another uid's argv may be hidden, and a forward opened from the remote side
   is invisible; `-ww` and matching the `-R` shape rather than a program name keep locally
   visible forwards from being missed unnecessarily.

   **Both** renderers bind the adapter unix sockets. Those are 0600 filesystem paths
   guarded by the existing flock (`crates/hc-daemon/src/socket.rs:25`), so they carry no
   port-unpredictability concern, and binding them in the terminal renderer closes a real
   capability gap: the console cannot serve adapters today.

   Independently, `scan_stranded` is repaired as a bug in its own right — `-ww`, and
   matching beyond bare `ssh`. It stays belt-and-braces; nothing is built on top of it.

11. **The store claim is taken once, at the top, and shared.** `Runtime::start` receives an
    already-held claim rather than taking one, because `crates/hc-cli/src/lib.rs:930-936`
    runs a store-mutating pull *before* the runtime exists. `flock(2)` is per
    open-file-description, so a second `open` in the same process genuinely conflicts:
    nothing re-takes the claim in-process. Background tasks that need mutual exclusion
    among themselves layer a `parking_lot::Mutex` *under* the flock. The lock file is
    `<home>/.store.lock` — outside the store, because `backup::pull` rsyncs over the store
    and would swap the inode of a lock file kept inside it. `init --force` takes it too:
    it is the most destructive mutator and was exempt.

12. **Timestamps are `u64` Unix seconds everywhere.** Stage 2 and stage 3 independently
    chose seconds and milliseconds; nothing type-checks the difference. Seconds wins.

13. **The mutation chokepoint commits fallibly and pushes best-effort.** A failed commit is
    a real error the caller must see; a failed push is a warning the status band reports.
    These are two halves with two different failure dispositions, not one call.

14. **Stage 4 owns no status of its own.** It reads what stages 2 and 3 already publish and
    owns only the pending-approvals gauge. Three parallel status structs with three writers
    was the third copy of the same idea.

15. **The live band shows how many bundles have met their threshold.** Stage 3 justified
    deleting `bundle watch` partly on the grounds that stage 4 would surface arrivals and
    threshold state, but stage 4 as planned has no per-bundle threshold. Deleting the watch
    screen without it would be a real narrowing: "the threshold is met" is precisely what a
    human waits for while collecting signatures. Stage 3's poller already loads every
    bundle on its tick, so it publishes a ready count alongside the arrival count, and
    stage 4 renders it. This is the minimum that makes the deletion honest — not a
    per-bundle panel.

16. **`FieldRule::Batch` exists.** `multiSend`'s argument is a packed batch payload with no
    honest bound; forcing it to `Unbounded` would print `⚠ UNBOUNDED FIELD` on every batch
    approval — inverting the alarm on precisely the call this stage checks hardest.

17. **`FieldRule::BoolEq { eq: bool }` exists.** Stage 6 deletes `Alarm::UnlimitedApproval`
    on the grounds that field rules supersede it. For `setApprovalForAll(address,bool)` they
    do not: with only `Unbounded` available, `true` and `false` would render identically,
    turning an infinite approval into something indistinguishable from a revocation. That is
    a security regression and is not acceptable.

18. **Decision 7d's refusal stays in the policy layer.** An earlier draft raised
    `AdapterErr::NoCalldata` in the decoder before the policy match, which would make
    `CallDenied::NoSelector` / `PolicyDenied::NoSelector` unreachable and orphan the
    assertion at `crates/hc-sign/src/policy.rs:372-377`. 7d says the bare-transfer refusal
    comes from the policy layer; it stays inside `match_call`.

19. **`OwnerMgmt` gains `max_value`, defaulting to 0.** Stage 6 dereferenced a ceiling the
    type does not have. Owner-management self-calls have no need to move value, and today
    they are unbounded because `crates/hc-sign/src/policy.rs:289` returns early. Default 0
    closes that; an operator who needs otherwise sets it explicitly.

9. **Bundles are not relayed.** The background poll pulls from every peer but pushes only
   bundles this device contributed a signature to. Signatures still converge because every
   device pulls from every peer. This machine never redistributes, unattended, something a
   hostile peer injected.

10. **Approval prompt scope.** Decision 2 governs requests arriving over the network
    surface — loopback TLS and adapter sockets — which is where the console draws the line
    today. A human running a CLI subcommand at their own terminal is not prompted twice;
    the Secure Enclave gate already authenticated them.

## Non-negotiable engineering rules

From `CLAUDE.md`. Every plan is judged against these.

- No comments in main code. Struct field docs are one short sentence. Test purpose is one
  short sentence. No comments in `.sh`, TOML, or `Cargo.toml`.
- Every failure is a variant in a typed error enum via `err_mac::create_err_with_impls!`.
  Never format an error into a string. Nest inner errors as `#[from]` variants so `?`
  works without `map_err`.
- Never return `Option` to signal failure. `Option` only where `None` is a correct value.
- Fixed sets of choices are enums, not strings.
- `hashbrown` for `HashMap`/`HashSet`; `parking_lot` for `Mutex`/`RwLock`. No exceptions,
  including tests and examples.
- No reexport shims. When code moves, fix every path.
- Delete every path an upgrade makes dead. The legacy Web3 keystore reader kept for
  `migrate` is the one deliberate exception.
- `#[allow(clippy::...)]` is banned, including `too_many_arguments`.
- Do not create a function that is used once and proves nothing. Do not create a variable
  only to pass it to a function. If the args are the fields of a struct, take the struct.
- Never run rayon inside the tokio runtime.
- Key material is plaintext only transiently after a gated unlock, then zeroized. Never
  persisted, logged, or `Debug`-printed.
- Build and run in release.
- Do not commit, stage, push, or create branches or worktrees.

## Tests

Only tests that pin new non-trivial logic or a crucial invariant. Do not test that `if`
works, that arithmetic works, or that serde round-trips. Do test: fast-forward-only merge
refusal, file-mode preservation across a git checkout, the approval policy covering every
privileged operation, incremental-validation correctness for bundle ingest, and the pure
parts of the status/menu state machines.

## Hazards every plan must address

Found by reading the current code. A plan that ignores one of these is incomplete.

### Runtime
- **The store lock must be cross-process** — an `flock` on a file outside the store, not a
  `parking_lot::Mutex`. Stage 2 is unsound without it: `crates/hc-cli/src/migrate.rs:184-186`
  and `crates/hc-cli/src/bootstrap.rs:628-633` bypass `atomic_write` entirely, and those are
  exactly the writers that would let a `git add -A` stage a torn set of files.
- `LaContext` is `!Send` and must be created on the main thread. The console already
  routes approvals to the main thread over `mpsc`; the daemon instead builds it inside
  `spawn_blocking`. The unified runtime uses the main-thread model.
- Both renderers bind `config.port()` plus one unix socket per manifest, and console-plus-serve
  cannot coexist. The store lock must produce a clean typed refusal, not a corrupt store.
- A passphrase session currently refuses to serve (`Serving::Refused`). That behaviour is
  load-bearing and must survive.
- Under `UnlockGate::Passphrase` the console must still not expose or read-test.

### Git store
- **File modes.** Corrected by the stage-2 planner against the real code: keystores are
  **not** 0600 today. `encrypt_file` -> `atomic_write` -> `fs::write` lands at the process
  umask, i.e. 0644. `write_private_file` (0600) is called only for the Secure Enclave blob
  (`crates/hc-core/src/mac/secure_enclave.rs:204,428`) and the TLS private key
  (`crates/hc-cli/src/lib.rs:550,557`). So there is no 0600 property to preserve; stage 2
  establishes one, and must also account for git recording only the exec bit so a checkout
  does not undo it. A test must pin it.
- `*.hctmp` from `atomic_write` must never be committed.
- `read_dir(store)` counting keystores: corrected — all six keystore-counting sites already
  filter `is_file()` + `is_valid_string_name`, which rejects a leading `.`, so `.git` is
  already excluded. Only `store_absent` (`crates/hc-daemon/src/backup.rs:69-74`) is
  affected, and stage 2 deletes it.
- The remote side needs a bare repo where `mkdir -p` used to suffice, created idempotently.
- An existing rsync-backed store must become a repo without a manual step and without
  losing its `vault_id` identity.
- `push_all` currently logs and returns `Ok(())` even when every remote failed. The new
  path must report failure so the UI can show it.
- Backup rsync today lacks `BatchMode=yes`, `ConnectTimeout`, and `--exclude=*.hctmp`,
  which bundle sync already sets. Whatever replaces it must not block a background task on
  a password prompt or an unreachable host.
- There is no lock around store mutation versus push/pull.

### Bundle polling
- `ingest::validate(Scope::All)` ecrecovers every signature of every bundle on every poll,
  bounded only by `MAX_INGEST_FILES = 4096`. At a 30s interval this must become
  incremental — validate what the transfer actually changed.
- The work is blocking: subprocess, filesystem, secp256k1. It cannot sit on an async
  worker thread.
- `hc-daemon` does not depend on `hc-bundle` today. Adding the dependency must not create
  a cycle.
- The console re-pulls `Scope::All` on every render of the bundles landing screen. Once a
  background poller exists that is redundant and must go.
- A reachable peer is an untrusted writer. Nothing currently gates creation of a new
  bundle directory by a peer. Background polling makes that continuous; say what the plan
  does about it.
- `Config::load()` is re-read on every sync run so enrollment changes take effect without
  a restart. Preserve that or replace it deliberately.

### Live status
- `pick` draws from an anchor computed at entry and must never write above it, nor
  overdraw the rows below its budget. The invariant is tested; do not break it.
- `inquire` prompts own the terminal with no repaint hook. Status is live on list screens
  and frozen inside a text or password prompt. Say so rather than pretending otherwise.
- The outer menu loop has no tick at all today; it blocks in `screen()`.
- `LogRing` is the one already-shared, already-thread-safe thing the status screen reads.
  Shared status should follow that pattern.
- No timestamps exist anywhere in the status code today.

### Sign path
- Deleting `hot_cheese sign` breaks `scripts/demo.sh`, which drives it directly. The
  script must be rewritten onto the bundle flow, not left broken.
- `hc-cli` serializes a `SafeTxIntent` it already holds into bytes so the daemon can parse
  it back. Collapsing that must not weaken the property that the approval summary is
  rendered from the bytes that were actually submitted and the digest is rebuilt
  independently.
- The grant is minted for every signature under the same `LaContext` the approval already
  evaluated, with a 5s TTL. Do not introduce a second prompt or widen that window.
- Adapter-socket requests carry a manifest digest; loopback and CLI use `B256::ZERO`.
  Preserve that distinction.

### Typed-only enforcement
- The summary renderer in `crates/hc-sign/src/adapter/` is today a *display* layer. Under
  decision 7 it becomes an *admission* layer: whatever it cannot decode, the daemon
  refuses. Establish by reading the code exactly what it does now with an unrecognised
  selector, a selector it knows but whose arguments fail to decode, an inner call of a
  batch it cannot expand, and a zero-length `data` on a non-zero `value`. Each of those is
  a distinct refusal variant, not one catch-all.
- The policy today gates on the 4-byte selector and a value ceiling. A selector allow-list
  is not the same as decodability: a permitted selector with undecodable arguments must
  still be refused.
- Ordering matters. The typed-decode refusal must happen before the approver is reached,
  so a refusal never costs a biometric — the same property the existing policy check has.
- Deleting the untyped path must not silently narrow what the operator can legitimately
  sign without saying so. Enumerate what stops being signable and state it plainly in the
  plan.
