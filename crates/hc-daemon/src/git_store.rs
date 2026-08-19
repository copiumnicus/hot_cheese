//! The store as a git repository: every mutation auto-commits, a backup is a push, the
//! freshness probe is a fetch, and applying remote state is always an explicit operator action.
//!
//! A fast-forward proves ancestry, not authorship, and not freshness either: a backup host that
//! serves an older commit of its own history rolls this store back with a proof that checks out,
//! and a child of this machine's own tip whose tree replays older blobs does the same while
//! staying an ancestor-clean fast-forward. Backup hosts are therefore confidentiality-only stores.
//! A background task never lets one rewrite the active worktree; only an explicit operator action
//! — which names the files it will replace, add and delete first — can apply remote history, and
//! one that moves backwards, forks, drops a store file, or replaces the content of any of them
//! needs that specific loss accepted on top ([`Doomed::accept_rewind`]). Only a purely additive
//! incoming tip stays on the single confirmation.
//!
//! The same asymmetry runs the other way: a deletion pushed as a clean fast-forward is a deletion
//! on every backup, so [`commit`] refuses to record one at all unless the operator confirmed the
//! [`Destruction`] behind it — a forced init's replacement, or a loss [`GitStore::missing`] named
//! and they accepted. Both grounds exist because the refusal is otherwise permanent and takes
//! every later `open` down with it.
//!
//! Every `git` runs through [`scrubbed`], which strips the plumbing variables that could aim it
//! at another repository. `GIT_DIR` overrides `-C`, so an exported one would commit this store's
//! keystores into a repository the operator did not choose and push them to that repository's
//! remote; nothing else here could detect it.
//!
//! [`CONNECT_TIMEOUT_SECS`] duplicates `hc_bundle::sync`'s constant of the same name on purpose:
//! `hc-daemon` does not depend on `hc-bundle`, and taking that dependency to share a `5` would
//! be a worse trade than writing it twice.
use crate::flock;
use err_mac::create_err_with_impls;
use hc_core::config::{BackupRemote, Config};
use hc_core::crypto::envelope::{enforce_store_modes, GIT_DIR, MAX_KEYSTORE_FILE_BYTES};
use hc_core::keyring::{Keyring, KeyringErr, VaultId, KEYRING_FILE, MAX_KEYRING_BYTES};
use hc_core::{is_valid_key_name, MAX_STORE_BYTES, MAX_STORE_FILES};
use hc_sign::grant::{now_secs, GrantErr};
use hc_sign::policy::MAX_POLICY_BYTES;
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// The one branch this design has. Both ends of every transfer name it explicitly, so no `HEAD`
/// on either side has to be guessed at.
#[cfg(test)]
const BRANCH: &str = "main";

/// What `symbolic-ref HEAD` must answer, and half of every refspec.
const HEAD_REF: &str = "refs/heads/main";

/// Pushed and fetched explicitly, because this repository has no named remotes: `config.toml`
/// is the single source of truth for where a backup goes, and a `.git/config` remote list would
/// be a second copy of it that could drift. Production pushes name the validated commit as the
/// source instead; only fixtures publish a whole branch.
#[cfg(test)]
const REFSPEC: &str = "refs/heads/main:refs/heads/main";

/// Suffix of a vault's bare repository on a backup host. Deliberately not [`GIT_DIR`]: that one
/// is a working tree's own directory, and the two only look alike.
const BARE_SUFFIX: &str = ".git";

/// Where [`GitStore::pull_preview`] pins the commit it described. `FETCH_HEAD` is not a gc root,
/// so a background fetch's [`reclaim_fetch_objects`] deletes a previewed tip while the operator is
/// still deciding, and the accepted restore then fails on an object that no longer exists.
const PREVIEW_REF: &str = "refs/hot_cheese/pull-preview";

/// The only ignore rule, written to `.git/info/exclude` rather than a tracked `.gitignore`: a
/// `.gitignore` would be a new file in the store, would be shipped by `bootstrap-from`, and
/// would need a second rule everywhere the store is enumerated.
const EXCLUDE: &str = "*.hctmp\n";

/// Committer identity, pinned so no hostname and no operator email ever enters an object or a
/// reflog, and so a machine with no global `user.email` can still commit.
const USER_NAME: &str = "hot_cheese";
const USER_EMAIL: &str = "hot_cheese@localhost";

/// Local settings every repository this code touches carries, set on open and after a clone.
/// `core.fileMode false` is what lets the mode sweep run without dirtying the tree.
const LOCAL_CONFIG: [(&str, &str); 3] = [
    ("core.fileMode", "false"),
    ("user.name", USER_NAME),
    ("user.email", USER_EMAIL),
];

/// Askpass hooks outside git's own namespace: a helper the operator never chose, named by an
/// inherited variable, run to answer a prompt. Removed from both the git and the [`ssh`] child.
const SCRUBBED_ASKPASS: [&str; 2] = ["SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"];

/// No inherited `GIT_*` variable reaches a child, because an enumerated deny-list can only grow:
/// `GIT_DIR` overrides `-C`, `GIT_CONFIG` redirects the writes [`LOCAL_CONFIG`] makes,
/// `GIT_ALLOW_PROTOCOL` and `GIT_PROTOCOL_FROM_USER` re-open transports, every `GIT_TRACE*` names
/// a file git appends to, and `GIT_AUTHOR_*` displaces the pinned identity. Everything git needs
/// here is set explicitly in [`scrubbed`], and the sweep stops at that one namespace so ssh keeps
/// the `SSH_AUTH_SOCK` an agent is reached through. Its config file and known-hosts path are
/// pinned as arguments by [`ssh_options`] instead of inherited.
fn is_scrubbed(name: &str) -> bool {
    name.starts_with("GIT_") || SCRUBBED_ASKPASS.contains(&name)
}

/// Seconds ssh waits for a backup host's TCP connect.
const CONNECT_TIMEOUT_SECS: u64 = 5;

/// A host that accepts and then stalls is bounded by these instead: `ConnectTimeout` covers only
/// the connect, and a background task must not hang on a half-dead session forever.
const ALIVE_INTERVAL_SECS: u64 = 5;
const ALIVE_COUNT_MAX: u64 = 3;
const MAX_COMMAND_STDOUT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_COMMAND_STDERR_BYTES: u64 = 1024 * 1024;
/// A fetched pack may contain history as well as the current bounded tree. Four current-store
/// ceilings leave room for ordinary history and thin-pack base repair while preventing a hostile
/// backup from consuming the rest of the volume before tree validation runs.
const MAX_FETCH_FILE_BYTES: u64 = MAX_STORE_BYTES * 4;
/// Total bytes already retained in `.git/objects/pack` before and after a fetch. `RLIMIT_FSIZE`
/// bounds one incoming pack, but without a cumulative ceiling a hostile backup can advertise a
/// fresh rejected history on every poll and leave one more bounded pack behind each time.
const MAX_FETCH_OBJECT_BYTES: u64 = MAX_FETCH_FILE_BYTES;
/// Pack-directory entries retained by this repository. A receive forced through `index-pack`
/// normally adds a `.pack`/`.idx` pair; this separately bounds a flood of tiny rejected packs.
const MAX_FETCH_OBJECT_FILES: usize = 8192;
/// Git's pack parser allocates from attacker-controlled object and delta metadata. macOS does not
/// enforce `RLIMIT_RSS`, so [`hc_core::output_bounded_timeout_memory`] watches the aggregate
/// physical memory of the process group and kills it before a compressed pack can grow without
/// bound in memory. It bounds every git child, not only `fetch`: a hostile host answers
/// `ls-remote` and `push` on the same poll and out of the same parsers.
const MAX_GIT_PROCESS_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
/// Git may transfer the whole bounded store, but it may not hold a mutator or background worker
/// forever when a remote or local helper stalls.
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SSH_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REMOTE_VAULTS: usize = 1024;

create_err_with_impls!(
    #[derive(Debug)]
    pub GitErr,
    NoBackupRemote,
    HeadNotOnBranch,
    FetchTaskGone,
    MalformedRemoteTree,
    PullPreviewStale,
    StdIo(std::io::Error),
    Envelope(hc_core::crypto::envelope::EnvErr),
    Keyring(KeyringErr),
    Grant(GrantErr),
    Hex(hex::FromHexError),
    Json(serde_json::Error),
    ParseInt(std::num::ParseIntError),
    Utf8(std::str::Utf8Error)
    ;
    GitFailed { argv: Vec<String>, code: i32 },
    GitSignal { argv: Vec<String> },
    SshFailed { host: String, code: i32 },
    SshSignal { host: String },
    AncestryUndecidable { argv: Vec<String>, code: i32 },
    Diverged { host: String, local: CommitId, remote: CommitId },
    VaultMismatch { site: VaultSite, requested: Option<VaultId>, found: Option<VaultId> },
    DestructionNotConfirmed { destruction: Destruction },
    LossPreviewStale { found: Missing },
    LocalKeyringMissing { store: PathBuf },
    AmbiguousRemoteTryPullVault { vaults: Vec<VaultId> },
    NoVaultOnRemote { host: String },
    PullRewindNotAccepted { rewind: Rewind, local_only: u64, remote_only: u64, removed: Vec<String>, changed: Vec<String> },
    PullWouldLoseEveryEnrollment { ids: Vec<String> },
    CommitWouldDeleteStoreFiles { paths: Vec<String> },
    CommitWouldDropEnrollments { ids: Vec<String> },
    MalformedDiffOutput { fields: usize },
    UnsupportedDiffStatus { status: String, path: String },
    MalformedCommitCounts { output: String },
    UnsafeGitDirectory { path: PathBuf },
    UnsafeLocalStoreEntry { path: PathBuf },
    LocalBlobTooLarge { path: PathBuf, size: u64, max: u64 },
    LocalTreeTooLarge { files: usize, bytes: u64 },
    TooManyLocalStoreEntries { found: usize, max: usize },
    BadCommitId { value: String },
    UnsafeRemotePath { path: String },
    UnsafeFetchObject { path: PathBuf },
    UnsupportedRemoteEntry { path: String, mode: String, kind: String },
    RemoteBlobTooLarge { path: String, size: u64, max: u64 },
    RemoteTreeTooLarge { files: usize, bytes: u64 },
    FetchObjectStoreTooLarge { files: usize, bytes: u64, max_files: usize, max_bytes: u64 },
    TooManyRemoteVaults { found: usize, max: usize },
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

/// A git object id, 40 lowercase hex on the wire. Fixed at 20 bytes because this code creates
/// every repository it reads and never opts into `extensions.objectFormat = sha256`; a future
/// git that flipped the default fails loudly here rather than silently truncating.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CommitId([u8; 20]);

impl FromStr for CommitId {
    type Err = GitErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let mut out = [0u8; 20];
        if s.len() != out.len() * 2 {
            return Err(GitErr::BadCommitId {
                value: hc_core::safe_diagnostic_text(s),
            });
        }
        hex::decode_to_slice(s, &mut out)?;
        Ok(Self(out))
    }
}

impl fmt::Display for CommitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for CommitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Which keyring disagreed about the vault a pull was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultSite {
    /// The keyring already in the local store dir.
    LocalStore,
    /// The keyring the remote's committed history declares.
    Pulled,
}

/// What the local store dir says about its vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalVault {
    /// No `keyring.json` in the store dir.
    Absent,
    /// A keyring written before vault ids existed.
    Legacy,
    /// This install's vault id.
    Id(VaultId),
}

impl LocalVault {
    pub fn id(&self) -> Option<&VaultId> {
        match self {
            LocalVault::Id(v) => Some(v),
            _ => None,
        }
    }
}

/// What one remote's folder holds for this install.
#[derive(Debug, Default)]
pub struct RemoteVaults {
    /// Vaults with a `<id>.git` bare repository: the layout this version writes.
    pub git: Vec<VaultId>,
    /// Vaults with a plain `<id>` directory: a machine that has not been upgraded is still
    /// rsyncing here, and the two have silently stopped converging.
    pub legacy: Vec<VaultId>,
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
    /// The remote has commits local does not; an explicit pull may apply them.
    RemoteAhead,
    /// Both sides moved; only a forced pull resolves it.
    Diverged,
}

impl fmt::Display for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Relation::Unknown => "unknown",
            Relation::Absent => "absent",
            Relation::InSync => "in sync",
            Relation::LocalAhead => "local ahead",
            Relation::RemoteAhead => "remote ahead",
            Relation::Diverged => "diverged",
        })
    }
}

/// Which git operation a failure came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitOp {
    EnsureRemote,
    Commit,
    Fetch,
    Push,
    ForcedPull,
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

/// What this install last learned about one backup remote.
#[derive(Clone, Debug)]
pub struct RemoteState {
    /// The ssh target from `config.backup_remotes`.
    pub host: String,
    /// The remote folder holding `<vault>.git`.
    pub folder: String,
    /// What the last completed inspection-only fetch found.
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

/// One snapshot of the git store, cloned out for a render.
#[derive(Clone, Debug)]
pub struct GitState {
    /// This install's vault, which names its bare repo on every remote; `None` until a keyring
    /// carrying a vault id exists.
    pub vault: Option<VaultId>,
    /// Local `HEAD`; `None` before the first commit.
    pub head: Option<CommitId>,
    /// Unix seconds this process last moved local `HEAD` — a commit or a forced pull.
    pub last_commit_at: Option<u64>,
    /// A fetch is running right now; the one field written before the work, not after.
    pub fetching: bool,
    /// One entry per configured remote, in `config.backup_remotes` order.
    pub remotes: Vec<RemoteState>,
}

impl GitState {
    /// What one process can know without a network round trip: this install's vault, its local
    /// `HEAD`, and the remotes it is configured to talk to.
    pub fn local(cfg: &Config) -> Result<Self, GitErr> {
        let store = cfg.store_path();
        let git_dir = store.join(GIT_DIR);
        let head = match std::fs::symlink_metadata(&git_dir) {
            Ok(metadata) if metadata.file_type().is_dir() => rev(&store, "HEAD")?,
            Ok(_) => return Err(GitErr::UnsafeGitDirectory { path: git_dir }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        Ok(GitState {
            vault: local_vault(&store)?.id().cloned(),
            head,
            last_commit_at: None,
            fetching: false,
            remotes: cfg.backup_remotes.iter().map(fresh_remote).collect(),
        })
    }
}

/// A remote nothing has been learned about yet.
fn fresh_remote(remote: &BackupRemote) -> RemoteState {
    RemoteState {
        host: remote.host.clone(),
        folder: remote.folder.clone(),
        relation: Relation::Unknown,
        remote_head: None,
        last_push_ok_at: None,
        last_fetch_ok_at: None,
        last_failure: None,
    }
}

/// Everything the git-store subsystem knows, shared with whichever renderer is drawing.
#[derive(Debug)]
pub struct GitStatus {
    inner: Mutex<GitState>,
}

impl GitStatus {
    /// One consistent snapshot; the lock is never held across a render.
    pub fn snapshot(&self) -> GitState {
        self.inner.lock().clone()
    }

    fn set_fetching(&self, fetching: bool) {
        self.inner.lock().fetching = fetching;
    }

    /// Local `HEAD` moved, however it moved.
    fn moved(&self, head: Option<CommitId>, at: u64) {
        let mut state = self.inner.lock();
        state.head = head;
        state.last_commit_at = Some(at);
    }

    fn opened(&self, vault: Option<VaultId>, head: Option<CommitId>) {
        let mut state = self.inner.lock();
        state.vault = vault;
        state.head = head;
    }

    /// Make the recorded remotes match `remotes`, in that order, keeping everything already
    /// learned about one that is still configured — so an edited `config.toml` neither loses
    /// history nor leaves a host nobody talks to on the status panel.
    fn align(&self, remotes: &[BackupRemote]) {
        let mut state = self.inner.lock();
        let mut aligned = Vec::with_capacity(remotes.len());
        for remote in remotes {
            let known = state
                .remotes
                .iter()
                .position(|r| r.host == remote.host && r.folder == remote.folder);
            aligned.push(match known {
                Some(i) => state.remotes.swap_remove(i),
                None => fresh_remote(remote),
            });
        }
        state.remotes = aligned;
    }

    /// Apply `f` to one remote's record. Every pass aligns first, so the entry is already there.
    fn remote<F: FnOnce(&mut RemoteState)>(&self, remote: &BackupRemote, f: F) {
        let mut state = self.inner.lock();
        let found = state
            .remotes
            .iter_mut()
            .find(|r| r.host == remote.host && r.folder == remote.folder);
        match found {
            Some(known) => f(known),
            None => {
                let mut fresh = fresh_remote(remote);
                f(&mut fresh);
                state.remotes.push(fresh);
            }
        }
    }
}

/// How this session's pushes and fetches are driven.
enum Background {
    /// No runtime: the chokepoint pushes before it returns, and nothing fetches on a timer.
    None,
    /// A runtime's task coalesces both, so N commits collapse into at most one push.
    Task {
        push: watch::Sender<u64>,
        fetch: watch::Sender<u64>,
    },
}

/// The receiving halves [`background`] waits on.
pub struct Wake {
    push: watch::Receiver<u64>,
    fetch: watch::Receiver<u64>,
}

/// Why applying a preview costs state that only this machine has, which a fast-forward's ancestry
/// proof says nothing about. A backup host chooses the history it serves, so each of these is a
/// rollback an operator must be shown and must accept as such.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rewind {
    /// The incoming tip is an ancestor of local: state this machine already moved past, replayed.
    Backwards,
    /// Both sides moved, so the incoming tip does not contain this machine's commits.
    Fork,
    /// The incoming tip drops store files the local commit has.
    Deletes,
    /// The incoming tip keeps every path and every commit, and replaces the content of store
    /// files. The store grammar admits only security-relevant paths, so that alone puts an older
    /// keystore, keyring or policy back.
    Contents,
}

/// Why a commit may record a loss the routine guards refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destruction {
    /// A forced init minted a new DEK, so the keystores and enrollments of the vault it replaces
    /// go with it.
    Replacement,
    /// Store state is already gone from a store [`GitStore::missing`] named, and the operator
    /// accepted recording that loss rather than leaving every later commit refused.
    Deletion,
}

impl Destruction {
    /// What an operator types to authorize this destruction, and the only thing that mints it.
    pub const fn phrase(self) -> &'static str {
        match self {
            Destruction::Replacement => "destroy the existing hot_cheese keys",
            Destruction::Deletion => "record the loss of these hot_cheese files",
        }
    }
}

/// Consent to record a commit that destroys store state, minted from the phrase the operator
/// typed and spent by the one commit that records it. Every other commit is a routine mutation,
/// which [`commit`] refuses to let delete a store file or drop an enrollment: a value that cannot
/// be constructed outside this module is what separates the two, where a flag, a variable or a
/// `bool` parameter would let any caller claim to be the confirmed one.
pub struct Consent(Destruction);

impl Consent {
    /// Mint the capability out of the bytes the operator actually typed, and nothing else.
    pub fn confirmed(destruction: Destruction, typed: &str) -> Result<Self, GitErr> {
        match typed.trim() == destruction.phrase() {
            true => Ok(Self(destruction)),
            false => Err(GitErr::DestructionNotConfirmed { destruction }),
        }
    }
}

/// What a commit would record as gone. A backup takes a deletion as a clean fast-forward like any
/// other change, so it cannot put back what this names.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Missing {
    /// Committed store files the staged index no longer has.
    pub paths: Vec<String>,
    /// This vault's enrollment ids the staged keyring no longer wraps.
    pub ids: Vec<String>,
}

impl Missing {
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.ids.is_empty()
    }
}

/// What a forced pull is about to destroy, so a confirmation can name it rather than say
/// "discards local history".
#[derive(Debug)]
pub struct Doomed {
    /// The commit the worktree will be reset to. Pinned here rather than re-read from
    /// `FETCH_HEAD` at apply time, so a background fetch between the question and the answer
    /// cannot change what the operator agreed to.
    pub remote_head: CommitId,
    /// How the incoming tip stands against local history.
    pub relation: Relation,
    /// The state this pull costs, which [`GitStore::pull_apply`] refuses until it is accepted;
    /// `None` only for a fast-forward that adds files and touches nothing already here.
    pub rewind: Option<Rewind>,
    /// Commits this machine has that the incoming tip does not.
    pub local_only: u64,
    /// Commits the incoming tip has that this machine does not.
    pub remote_only: u64,
    /// Committer time of local `HEAD`; `None` before the first commit.
    pub local_at: Option<u64>,
    /// Committer time the incoming tip claims, which whoever wrote it chose freely.
    pub remote_at: u64,
    /// Store files the incoming tip adds.
    pub added: Vec<String>,
    /// Store files it replaces.
    pub changed: Vec<String>,
    /// Store files it deletes.
    pub removed: Vec<String>,
    /// Enrollment ids that stop existing here, when the incoming keyring keeps none of this
    /// machine's; empty while any local unlock path survives the pull.
    pub lost_enrollments: Vec<String>,
    /// Tracked paths the reset will replace or delete, including staged/unstaged worktree edits.
    pub tracked: Vec<String>,
    /// Untracked, non-excluded files `clean -fd` deletes.
    pub untracked: Vec<String>,
    accepted_rewind: bool,
    local_head: Option<CommitId>,
    local_status: Vec<u8>,
    vault: VaultId,
    store: PathBuf,
}

impl Doomed {
    /// Record that the operator was shown [`Doomed::rewind`] and accepted that specific loss.
    pub fn accept_rewind(&mut self) {
        self.accepted_rewind = true;
    }
}

/// The anchor lives exactly as long as the decision does, whichever way it goes: applied,
/// declined, or dropped by an error on the way to the question.
impl Drop for Doomed {
    fn drop(&mut self) {
        if let Err(failed) = release_preview(&self.store) {
            tracing::warn!(error = ?failed.cause, "the previewed commit's anchor outlived its decision");
        }
    }
}

/// Unpin whatever a preview anchored. Deleting a ref that is not there is a success, so this is
/// also how a preview clears an anchor a crashed process left behind.
fn release_preview(store: &Path) -> Step<()> {
    git(
        Some(store),
        GitOp::ForcedPull,
        &["update-ref", "-d", PREVIEW_REF],
    )?;
    Ok(())
}

/// One session's git store: the claim it serialises on, the state it publishes, and how its
/// pushes get done.
pub struct GitStore {
    config: Arc<Config>,
    /// Held for the whole session. `flock(2)` excludes other processes; the mutex inside it
    /// excludes this process's own threads. Both are required and neither substitutes.
    claim: flock::Claim,
    /// `git fetch` writes one repository-global `FETCH_HEAD`. Background inspection and an
    /// explicit pull may run on different threads, so their fetch/read pairs must be atomic with
    /// respect to each other even though inspection never takes the worktree mutation lock.
    fetch_head_guard: Mutex<()>,
    status: GitStatus,
    background: Background,
}

pub struct Mutation<'a> {
    store: &'a GitStore,
    _guard: parking_lot::MutexGuard<'a, ()>,
}

impl Mutation<'_> {
    pub fn commit(self) -> Result<(), GitErr> {
        self.record(None)
    }

    /// Record the loss [`GitStore::missing`] named and the operator confirmed. The consent is
    /// spent here, and covers exactly `accepted`: a store that lost something else while the
    /// question was open is refused rather than recorded against an answer nobody gave.
    pub fn commit_loss(self, consent: Consent, accepted: &Missing) -> Result<(), GitErr> {
        let store = self.store.config.store_path();
        let found = stage(&store, &store_vault(&store)?)?;
        if &found != accepted {
            return Err(GitErr::LossPreviewStale { found });
        }
        self.record(Some(consent))
    }

    /// The guard is released before the push, because [`GitStore::push_every`] takes it again for
    /// the vault read and `parking_lot`'s mutex is not re-entrant: pushing under it wedged every
    /// mutation of an install that had a backup remote.
    fn record(self, consent: Option<Consent>) -> Result<(), GitErr> {
        let store = self.store;
        let publish = store.record_mutation(consent)?;
        drop(self);
        if publish {
            if let Err(e) = store.push_every(&store.config) {
                tracing::warn!(error = %e, "the backup push after a store mutation failed");
            }
        }
        Ok(())
    }
}

impl GitStore {
    /// The store one CLI subcommand mutates. With no background task the chokepoint pushes
    /// before it returns, because a `hot_cheese add` at a terminal has no later retry.
    pub fn cli(config: Arc<Config>, claim: flock::Claim) -> Result<Self, GitErr> {
        Ok(Self {
            status: GitStatus {
                inner: Mutex::new(GitState::local(&config)?),
            },
            config,
            claim,
            fetch_head_guard: Mutex::new(()),
            background: Background::None,
        })
    }

    /// The store a session serves from, plus the halves its background task waits on.
    pub fn session(config: Arc<Config>, claim: flock::Claim) -> Result<(Self, Wake), GitErr> {
        let (push, push_rx) = watch::channel(0u64);
        let (fetch, fetch_rx) = watch::channel(0u64);
        let store = Self {
            status: GitStatus {
                inner: Mutex::new(GitState::local(&config)?),
            },
            config,
            claim,
            fetch_head_guard: Mutex::new(()),
            background: Background::Task { push, fetch },
        };
        Ok((
            store,
            Wake {
                push: push_rx,
                fetch: fetch_rx,
            },
        ))
    }

    pub fn status(&self) -> &GitStatus {
        &self.status
    }

    pub fn mutation(&self) -> Mutation<'_> {
        Mutation {
            store: self,
            _guard: self.claim.mutate(),
        }
    }

    /// Bring the repository into the shape everything below assumes, and record what it found.
    /// Idempotent; the first run on a pre-existing rsync store makes commit #1 out of
    /// everything already there.
    pub fn open(&self) -> Result<(), GitErr> {
        let store = self.config.store_path();
        let _mutating = self.claim.mutate();
        let head = ensure_repo(&store, None)?;
        self.status.opened(local_vault(&store)?.id().cloned(), head);
        Ok(())
    }

    /// Record the mutation, then replicate it. The commit is the caller's problem when it
    /// fails; the push is not, because a store that really was written must not be reported as
    /// a failure because a remote was asleep.
    pub fn after_mutation(&self) -> Result<(), GitErr> {
        self.mutation().commit()
    }

    /// Name what a commit would record as gone, without recording it: it stages and moves no ref.
    /// Deliberately not behind [`GitStore::open`], because a store whose commits are already
    /// refused is the only store where the answer matters.
    pub fn missing(&self) -> Result<Missing, GitErr> {
        let store = self.config.store_path();
        let _mutating = self.claim.mutate();
        Ok(stage(&store, &store_vault(&store)?)?)
    }

    /// `true` when this session has no background task to replicate for it, so the caller must
    /// push once it has released the mutation guard.
    fn record_mutation(&self, consent: Option<Consent>) -> Result<bool, GitErr> {
        let store = self.config.store_path();
        let vault = store_vault(&store)?;
        let committed = commit(&store, &vault, consent)?;
        let Some(head) = committed else {
            return Ok(false);
        };
        self.status.moved(Some(head), now_secs()?);
        match &self.background {
            Background::None => Ok(true),
            Background::Task { push, .. } => {
                push.send_modify(|n| *n += 1);
                Ok(false)
            }
        }
    }

    /// Ask the background task to fetch now. Nothing in this stage presses it; the console's
    /// Status panel does.
    pub fn request_fetch(&self) -> Result<(), GitErr> {
        match &self.background {
            Background::Task { fetch, .. } if fetch.receiver_count() > 0 => {
                fetch.send_modify(|n| *n += 1);
                Ok(())
            }
            _ => Err(GitErr::FetchTaskGone),
        }
    }

    /// Push every remote. One dead host must not block the others, so each is attempted and
    /// only a total failure is an error the caller sees.
    pub fn push_every(&self, cfg: &Config) -> Result<(), GitErr> {
        if cfg.backup_remotes.is_empty() {
            return Ok(());
        }
        let store = self.config.store_path();
        let vault = self.vault(&store)?;
        let Some(head) = publishable_head(&store, &vault)? else {
            return Ok(());
        };
        self.status.align(&cfg.backup_remotes);
        let mut failures = Vec::new();
        for remote in &cfg.backup_remotes {
            match self.push_one(&store, remote, &vault, head) {
                Ok(()) => {
                    let at = now_secs()?;
                    self.status.remote(remote, |r| {
                        r.last_push_ok_at = Some(at);
                        r.last_failure = None;
                    });
                }
                Err(failed) => failures.push(self.record(remote, failed)?),
            }
        }
        if failures.len() == cfg.backup_remotes.len() {
            return Err(GitErr::AllRemotesFailed { failures });
        }
        Ok(())
    }

    /// Fetch and inspect every remote without changing the active worktree. A fast-forward only
    /// proves ancestry, so even a `RemoteAhead` result waits for an explicit forced pull.
    pub fn fetch_every(&self, cfg: &Config) -> Result<(), GitErr> {
        if cfg.backup_remotes.is_empty() {
            return Ok(());
        }
        let store = self.config.store_path();
        let vault = self.vault(&store)?;
        {
            let _fetch_head = self.fetch_head_guard.lock();
            let _mutating = self.claim.mutate();
            reclaim_fetch_objects(&store, MAX_FETCH_OBJECT_FILES, MAX_FETCH_OBJECT_BYTES)?;
        }
        self.status.align(&cfg.backup_remotes);
        let mut failures = Vec::new();
        for remote in &cfg.backup_remotes {
            let fetched = {
                let _fetch_head = self.fetch_head_guard.lock();
                self.fetch_one(&store, remote, &vault)
            };
            match fetched {
                Ok(found) => {
                    let at = now_secs()?;
                    self.status.remote(remote, |r| {
                        if r.relation != found.relation && found.relation == Relation::Diverged {
                            tracing::warn!(
                                host = %remote.host,
                                local = ?found.local,
                                remote = ?found.remote,
                                "the backup has diverged; only a forced pull resolves it"
                            );
                        }
                        r.relation = found.relation;
                        r.remote_head = found.remote;
                        r.last_fetch_ok_at = Some(at);
                        r.last_failure = None;
                    });
                }
                Err(failed) => failures.push(self.record(remote, failed)?),
            }
        }
        if failures.len() == cfg.backup_remotes.len() {
            return Err(GitErr::AllRemotesFailed { failures });
        }
        Ok(())
    }

    /// Create every configured remote's bare repository. Runs once per session, off the main
    /// thread, so a sleeping host delays nothing an operator is looking at.
    fn ensure_remotes(&self, remotes: &[BackupRemote]) -> Result<(), GitErr> {
        let vault = self.vault(&self.config.store_path())?;
        for remote in remotes {
            if let Err(e) = ensure_remote(remote, &vault) {
                tracing::warn!(host = %remote.host, error = %e, "could not prepare the backup remote");
            }
        }
        Ok(())
    }

    /// Fetch, validate, and say what a forced pull would do: which way history moves, how many
    /// commits and how much time each side carries, and every store file it adds, changes and
    /// deletes. Nothing reaches the worktree — the tree and keyring are inspected out of the
    /// object database first.
    ///
    /// The store grammar admits only security-relevant paths — the keyring, a policy, a keystore —
    /// so an incoming tip that rewrites the content of any of them can revive a rotated key or
    /// reinstate a looser keyring or policy while its ancestry stays clean, and it is a
    /// [`Rewind::Contents`] on exactly that ground, distinct from the three losses that really are
    /// older history, a fork or a deletion. Only a purely additive tip escapes with one
    /// confirmation.
    ///
    /// The commit described is pinned under [`PREVIEW_REF`] for the life of the [`Doomed`], because
    /// `FETCH_HEAD` is not a gc root and a concurrent fetch would otherwise be able to delete the
    /// operator's answer out from under them.
    pub fn pull_preview(&self, remote: &BackupRemote, vault: &VaultId) -> Result<Doomed, GitErr> {
        let store = self.config.store_path();
        let url = url(remote, vault);
        // Take this before the worktree lock: if a background host is slow, waiting for its
        // FETCH_HEAD pair must not prevent an unrelated local mutation from finishing.
        let _fetch_head = self.fetch_head_guard.lock();
        let _mutating = self.claim.mutate();
        let mine = local_vault(&store)?;
        if mine != LocalVault::Absent {
            require_vault(VaultSite::LocalStore, Some(vault), mine.id())?;
        }
        release_preview(&store)?;
        reclaim_fetch_objects(&store, MAX_FETCH_OBJECT_FILES, MAX_FETCH_OBJECT_BYTES)?;
        git(
            Some(&store),
            GitOp::ForcedPull,
            &[
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                &url,
                HEAD_REF,
            ],
        )?;
        let remote_head = fetch_head(&store)?;
        git(
            Some(&store),
            GitOp::ForcedPull,
            &["update-ref", PREVIEW_REF, &remote_head.to_string()],
        )?;
        let found = inspect_fetched(&store, remote_head, vault, GitOp::ForcedPull)?;
        let local_head = found.local;
        let changed_files = doomed_paths(&store, local_head, remote_head)?;
        let (local_only, remote_only) = commit_counts(&store, local_head, remote_head)?;
        let local_at = match local_head {
            Some(local) => Some(commit_time(&store, local)?),
            None => None,
        };
        let rewind = if found.relation == Relation::Diverged {
            Some(Rewind::Fork)
        } else if found.relation == Relation::LocalAhead {
            Some(Rewind::Backwards)
        } else if !changed_files.removed.is_empty() {
            Some(Rewind::Deletes)
        } else if !changed_files.changed.is_empty() {
            Some(Rewind::Contents)
        } else {
            None
        };
        let local_status = git(
            Some(&store),
            GitOp::ForcedPull,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        )?;
        Ok(Doomed {
            remote_head,
            relation: found.relation,
            rewind,
            local_only,
            remote_only,
            local_at,
            remote_at: commit_time(&store, remote_head)?,
            added: changed_files.added,
            changed: changed_files.changed,
            removed: changed_files.removed,
            lost_enrollments: stranded_enrollments(&store, remote_head, GitOp::ForcedPull)?,
            tracked: changed_files.tracked,
            untracked: changed_files.untracked,
            accepted_rewind: false,
            local_head,
            local_status,
            vault: vault.clone(),
            store,
        })
    }

    /// Discard local history and take the remote's, then re-tighten every mode the checkout
    /// recreated at the umask. The one operation here that can destroy key material.
    ///
    /// Ancestry proves neither authorship nor freshness, so anything that costs state only this
    /// machine has fails closed until [`Doomed::accept_rewind`] records that the operator was
    /// shown that specific loss and took it. The unlock paths are re-read out of the object
    /// database here rather than trusted from the preview, because this is the one call that can
    /// leave the DEK with no way back into it.
    pub fn pull_apply(&self, doomed: &Doomed) -> Result<(), GitErr> {
        let store = self.config.store_path();
        let _mutating = self.claim.mutate();
        let current_status = git(
            Some(&store),
            GitOp::ForcedPull,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        )?;
        if rev(&store, "HEAD")? != doomed.local_head || current_status != doomed.local_status {
            return Err(GitErr::PullPreviewStale);
        }
        validate_remote_tree(&store, doomed.remote_head, GitOp::ForcedPull)?;
        validate_remote_keyring(&store, doomed.remote_head, &doomed.vault, GitOp::ForcedPull)?;
        if !doomed.accepted_rewind {
            let stranded = stranded_enrollments(&store, doomed.remote_head, GitOp::ForcedPull)?;
            if !stranded.is_empty() {
                return Err(GitErr::PullWouldLoseEveryEnrollment { ids: stranded });
            }
            if let Some(rewind) = doomed.rewind {
                return Err(GitErr::PullRewindNotAccepted {
                    rewind,
                    local_only: doomed.local_only,
                    remote_only: doomed.remote_only,
                    removed: doomed.removed.clone(),
                    changed: doomed.changed.clone(),
                });
            }
        }
        let target = doomed.remote_head.to_string();
        git(
            Some(&store),
            GitOp::ForcedPull,
            &["reset", "--hard", "--quiet", &target],
        )?;
        // A second `-f` is required for untracked nested repositories. The preview names such a
        // directory as one NUL-framed path; leaving it behind would make a reported-successful
        // restore differ from the tree that was validated above.
        git(Some(&store), GitOp::ForcedPull, &["clean", "-ffdq"])?;
        validate_local_store_tree(&store)?;
        enforce_store_modes(&store)?;
        self.status.moved(Some(doomed.remote_head), now_secs()?);
        Ok(())
    }

    /// This install's vault, minted under the in-process guard because minting writes the
    /// keyring back.
    fn vault(&self, store: &Path) -> Result<VaultId, GitErr> {
        let _mutating = self.claim.mutate();
        store_vault(store)
    }

    /// Push one remote, creating its bare repository if the push says there is none. The first
    /// attempt's cause is logged rather than dropped; the retry's is what a caller sees.
    ///
    /// The refspec names the commit [`publishable_head`] validated, not a ref that a concurrent
    /// mutation could have moved since, so what the backup receives is exactly what was checked.
    fn push_one(
        &self,
        store: &Path,
        remote: &BackupRemote,
        vault: &VaultId,
        head: CommitId,
    ) -> Step<()> {
        let url = url(remote, vault);
        let refspec = format!("{head}:{HEAD_REF}");
        let argv = ["push", "--quiet", &url, &refspec];
        let first = run(Some(store), GitOp::Push, &argv)?;
        if first.code == 0 {
            return Ok(());
        }
        tracing::warn!(
            host = %remote.host,
            code = first.code,
            stderr = %first.stderr,
            "backup push failed; creating the remote repository and retrying"
        );
        if let Err(e) = ensure_remote(remote, vault) {
            return Err(Failed {
                op: GitOp::EnsureRemote,
                cause: e,
                stderr: first.stderr,
            });
        }
        git(Some(store), GitOp::Push, &argv)?;
        Ok(())
    }

    /// One remote's validated ancestry as the fetch found it. Fetch writes only into `.git`;
    /// remote state never becomes active here, including when it is a fast-forward.
    fn fetch_one(&self, store: &Path, remote: &BackupRemote, vault: &VaultId) -> Step<Found> {
        let url = url(remote, vault);
        let probe = ["ls-remote", "--exit-code", &url, HEAD_REF];
        let probed = run(None, GitOp::Fetch, &probe)?;
        match probed.code {
            0 => {}
            2 => {
                return Ok(Found {
                    relation: Relation::Absent,
                    local: None,
                    remote: None,
                })
            }
            code => {
                tracing::warn!(host = %remote.host, code, stderr = %probed.stderr, "a backup remote did not answer");
                return Err(Failed {
                    op: GitOp::Fetch,
                    cause: GitErr::GitFailed {
                        argv: owned(&probe),
                        code,
                    },
                    stderr: probed.stderr,
                });
            }
        }
        git(
            Some(store),
            GitOp::Fetch,
            &[
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                &url,
                HEAD_REF,
            ],
        )?;
        let remote_head = fetch_head(store)?;
        inspect_fetched(store, remote_head, vault, GitOp::Fetch)
    }

    /// Put one remote's failure in the status and hand the shared cause back for the tally.
    fn record(&self, remote: &BackupRemote, failed: Failed) -> Result<RemoteFailure, GitErr> {
        let cause = Arc::new(failed.cause);
        let failure = Failure {
            at: now_secs()?,
            op: failed.op,
            cause: cause.clone(),
            stderr: failed.stderr,
        };
        self.status
            .remote(remote, |r| r.last_failure = Some(failure));
        Ok(RemoteFailure {
            host: remote.host.clone(),
            cause,
        })
    }
}

/// What one entry of `diff --name-status` says the incoming tree does to a store file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    Added,
    Changed,
    Removed,
}

/// Every pathname a forced pull touches, split by what happens to it and rendered as inert text
/// for its confirmation.
struct Doing {
    added: Vec<String>,
    changed: Vec<String>,
    removed: Vec<String>,
    tracked: Vec<String>,
    untracked: Vec<String>,
}

/// Pair `--name-status -z` output back up. The framing is `status NUL path NUL`, so a record is
/// only whole when both halves are present, and an unknown status letter is refused rather than
/// silently dropped from a confirmation that claims to name everything.
fn name_status(stdout: &[u8]) -> Result<Vec<(Change, String)>, GitErr> {
    if stdout.is_empty() {
        return Ok(Vec::new());
    }
    let Some(complete) = stdout.strip_suffix(&[0]) else {
        return Err(GitErr::MalformedDiffOutput {
            fields: stdout.split(|byte| *byte == 0).count(),
        });
    };
    let fields: Vec<&[u8]> = complete.split(|byte| *byte == 0).collect();
    let pairs = fields.chunks_exact(2);
    if !pairs.remainder().is_empty() {
        return Err(GitErr::MalformedDiffOutput {
            fields: fields.len(),
        });
    }
    let mut out = Vec::with_capacity(fields.len() / 2);
    for record in pairs {
        let status = hc_core::safe_diagnostic(record[0]);
        let path = hc_core::safe_diagnostic(record[1]);
        let change = match status.as_bytes().first() {
            Some(b'A') => Change::Added,
            Some(b'M' | b'T') => Change::Changed,
            Some(b'D') => Change::Removed,
            _ => return Err(GitErr::UnsupportedDiffStatus { status, path }),
        };
        out.push((change, path));
    }
    Ok(out)
}

/// What a forced pull does to each file. `git diff <local> <remote>` covers committed history,
/// `git diff HEAD` adds both staged and unstaged tracked edits, and `ls-files --others` names what
/// `clean -fd` removes. NUL framing is required: a local filename may contain a newline, and
/// treating it as two confirmation rows would let one path forge the name of another. Rename
/// detection is off so a moved keystore reads as the deletion it is.
fn doomed_paths(
    store: &Path,
    local_head: Option<CommitId>,
    remote_head: CommitId,
) -> Result<Doing, GitErr> {
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    let mut tracked = BTreeSet::new();
    if let Some(local) = local_head {
        let incoming = git(
            Some(store),
            GitOp::ForcedPull,
            &[
                "diff",
                "--no-ext-diff",
                "--no-renames",
                "--name-status",
                "-z",
                &local.to_string(),
                &remote_head.to_string(),
                "--",
            ],
        )?;
        for (change, path) in name_status(&incoming)? {
            match change {
                Change::Added => added.push(path.clone()),
                Change::Changed => changed.push(path.clone()),
                Change::Removed => removed.push(path.clone()),
            }
            tracked.insert(path);
        }
        for path in nul_paths(&git(
            Some(store),
            GitOp::ForcedPull,
            &["diff", "--no-ext-diff", "--name-only", "-z", "HEAD", "--"],
        )?) {
            tracked.insert(path);
        }
    }
    Ok(Doing {
        added,
        changed,
        removed,
        tracked: tracked.into_iter().collect(),
        untracked: nul_paths(&git(
            Some(store),
            GitOp::ForcedPull,
            &["ls-files", "--others", "--exclude-standard", "-z", "--"],
        )?),
    })
}

/// Commits each side has that the other does not, so a confirmation can say how far back a pull
/// reaches instead of only that it changes files.
fn commit_counts(
    store: &Path,
    local_head: Option<CommitId>,
    remote_head: CommitId,
) -> Result<(u64, u64), GitErr> {
    let remote = remote_head.to_string();
    let Some(local) = local_head else {
        let out = git(
            Some(store),
            GitOp::ForcedPull,
            &["rev-list", "--count", &remote],
        )?;
        return Ok((0, String::from_utf8_lossy(&out).trim().parse()?));
    };
    let range = format!("{local}...{remote}");
    let out = git(
        Some(store),
        GitOp::ForcedPull,
        &["rev-list", "--left-right", "--count", &range],
    )?;
    let counted = String::from_utf8_lossy(&out);
    let mut sides = counted.split_ascii_whitespace();
    let (Some(left), Some(right), None) = (sides.next(), sides.next(), sides.next()) else {
        return Err(GitErr::MalformedCommitCounts {
            output: hc_core::safe_diagnostic_text(&counted),
        });
    };
    Ok((left.parse()?, right.parse()?))
}

/// The committer time a commit carries. Whoever wrote the commit chose it, so this dates a
/// confirmation, never a trust decision.
fn commit_time(store: &Path, commit: CommitId) -> Result<u64, GitErr> {
    let out = git(
        Some(store),
        GitOp::ForcedPull,
        &["show", "--no-patch", "--format=%ct", &commit.to_string()],
    )?;
    Ok(String::from_utf8_lossy(&out).trim().parse()?)
}

/// What one completed inspection-only fetch learned.
struct Found {
    relation: Relation,
    local: Option<CommitId>,
    remote: Option<CommitId>,
}

/// The background task: one push arm, one operator-driven fetch arm, and one timer. Every git
/// call runs on a blocking thread, because it is subprocess and filesystem work.
pub async fn background(store: Arc<GitStore>, mut wake: Wake) {
    let first = reloaded(&store);
    let preparing = store.clone();
    let remotes = first.backup_remotes.clone();
    report(
        tokio::task::spawn_blocking(move || preparing.ensure_remotes(&remotes)).await,
        "preparing the backup remotes",
    );
    fetch_pass(&store, first).await;
    loop {
        let cfg = reloaded(&store);
        let period = std::time::Duration::from_secs(cfg.backup_fetch_secs());
        let fetching = tokio::select! {
            changed = wake.push.changed() => {
                if changed.is_err() {
                    return;
                }
                false
            }
            changed = wake.fetch.changed() => {
                if changed.is_err() {
                    return;
                }
                true
            }
            _ = tokio::time::sleep(period), if !period.is_zero() => true,
        };
        if fetching {
            fetch_pass(&store, cfg).await;
            continue;
        }
        let pushing = store.clone();
        report(
            tokio::task::spawn_blocking(move || pushing.push_every(&cfg)).await,
            "the backup push",
        );
    }
}

/// One fetch pass, with the in-flight marker set before the work and cleared on every exit —
/// including an error, or one unreachable host would pin it on forever.
async fn fetch_pass(store: &Arc<GitStore>, cfg: Config) {
    store.status.set_fetching(true);
    let fetching = store.clone();
    let done = tokio::task::spawn_blocking(move || fetching.fetch_every(&cfg)).await;
    store.status.set_fetching(false);
    report(done, "the backup fetch");
}

/// Per-remote outcomes are already in the status, so this is the one place that says a whole
/// pass ended badly.
fn report(done: Result<Result<(), GitErr>, tokio::task::JoinError>, pass: &str) {
    match done {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, pass, "a backup pass failed"),
        Err(e) => tracing::error!(error = %e, pass, "a backup pass did not finish"),
    }
}

/// `config.toml` re-read at the top of every cycle, so an edited fetch interval or remote list
/// takes effect without a restart. A config that stopped parsing keeps the session's own.
fn reloaded(store: &GitStore) -> Config {
    match Config::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(error = %e, "config.toml did not reload; keeping the loaded one");
            (*store.config).clone()
        }
    }
}

/// A failed step, with the child's own words kept for the status record.
#[derive(Debug)]
struct Failed {
    op: GitOp,
    cause: GitErr,
    stderr: String,
}

impl From<Failed> for GitErr {
    fn from(failed: Failed) -> Self {
        failed.cause
    }
}

/// One step of one operation. The stderr is dropped the moment the caller stops caring which
/// remote it belonged to.
type Step<T> = Result<T, Failed>;

fn step_failure(op: GitOp, cause: impl Into<GitErr>) -> Failed {
    Failed {
        op,
        cause: cause.into(),
        stderr: String::new(),
    }
}

/// One finished git child: what it printed and how it left.
struct Ran {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

/// Both ways to a backup host reach it through this one binary: `git` re-parses it out of
/// `GIT_SSH_COMMAND`, [`ssh`] execs it directly.
const SSH_PROGRAM: &str = "/usr/bin/ssh";

/// `-F /dev/null` is the option that keeps a same-uid `~/.ssh/config` from attaching a
/// `ProxyCommand` to a backup connection, and it drops `/etc/ssh/ssh_config` with it, so the
/// host key becomes the only thing authenticating the far end and the file it is checked against
/// has to be named here too. `ssh` expands `~` from the passwd database, never from `$HOME`.
const SSH_FIXED_OPTIONS: [&str; 19] = [
    "-T",
    "-F",
    "/dev/null",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "UserKnownHostsFile=~/.ssh/known_hosts",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectionAttempts=1",
    "-o",
    "PermitLocalCommand=no",
    "-o",
    "ForkAfterAuthentication=no",
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPath=none",
];

/// Every option both ways to a backup host carry. `BatchMode=yes` is load-bearing twice over: a
/// background task must never stop on a password prompt, and it is what turns the unknown host
/// `StrictHostKeyChecking=yes` refuses into a refusal rather than a prompt.
fn ssh_options() -> Vec<String> {
    let mut options: Vec<String> = SSH_FIXED_OPTIONS.iter().map(|o| (*o).to_string()).collect();
    options.extend([
        "-o".to_string(),
        format!("ConnectTimeout={CONNECT_TIMEOUT_SECS}"),
        "-o".to_string(),
        format!("ServerAliveInterval={ALIVE_INTERVAL_SECS}"),
        "-o".to_string(),
        format!("ServerAliveCountMax={ALIVE_COUNT_MAX}"),
    ]);
    options
}

/// The one `Command` constructor here. `store` is `Some` for anything addressing the store's
/// repository and `None` for a clone or a bare URL probe, which have no repository to be inside
/// yet.
fn scrubbed(store: Option<&Path>) -> Command {
    let mut cmd = Command::new("/usr/bin/git");
    for (name, _) in std::env::vars_os() {
        if is_scrubbed(&name.to_string_lossy()) {
            cmd.env_remove(&name);
        }
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env(
            "GIT_SSH_COMMAND",
            format!("{SSH_PROGRAM} {}", ssh_options().join(" ")),
        )
        .stdin(Stdio::null());
    if let Some(store) = store {
        // Name both halves explicitly. An inherited variable or a hostile `core.worktree` in
        // `.git/config` must not make `add -A` stage a directory outside the key store.
        cmd.arg("--git-dir")
            .arg(store.join(GIT_DIR))
            .arg("--work-tree")
            .arg(store);
    }
    cmd.arg("-c")
        .arg("commit.gpgsign=false")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("core.attributesFile=/dev/null")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("protocol.ext.allow=never");
    cmd
}

fn owned(argv: &[&str]) -> Vec<String> {
    argv.iter().map(|a| (*a).to_string()).collect()
}

/// Non-empty trimmed lines of a child's stdout.
/// NUL-delimited pathnames from git, escaped before they reach a log or confirmation prompt.
fn nul_paths(stdout: &[u8]) -> Vec<String> {
    stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(hc_core::safe_diagnostic)
        .collect()
}

/// Pin Git's receive path before the subcommand. `fetch.fsckObjects` is also what guarantees even
/// a one-object response goes through `index-pack` rather than becoming an arbitrary number of
/// loose writes that could each sit below [`MAX_FETCH_FILE_BYTES`].
fn harden_fetch(command: &mut Command) -> std::io::Result<()> {
    command
        .arg("-c")
        .arg("fetch.fsckObjects=true")
        .arg("-c")
        .arg("fetch.unpackLimit=1")
        .arg("-c")
        .arg("fetch.writeCommitGraph=false")
        .arg("-c")
        .arg("maintenance.auto=false")
        .arg("-c")
        .arg("gc.auto=0")
        .arg("-c")
        .arg("submodule.recurse=false")
        .arg("-c")
        .arg("core.bigFileThreshold=1m")
        .arg("-c")
        .arg("core.deltaBaseCacheLimit=16m")
        .arg("-c")
        .arg("pack.threads=1");
    hc_core::limit_child_file_size(command, MAX_FETCH_FILE_BYTES)
}

/// Bound what earlier fetches have retained. `fetch.unpackLimit=1` makes every non-empty native
/// receive go through `index-pack`, so hostile remote growth is concentrated in this one flat
/// directory. The check runs both before and after each fetch: the after-check catches the fetch
/// that crosses the line, while the next before-check prevents any further growth. Nothing is
/// deleted here — [`reclaim_fetch_objects`] is the one path that reclaims, and it runs only where
/// no concurrent local write can be relying on an object it has just written.
fn fetch_object_budget(store: &Path) -> Result<(), GitErr> {
    let (files, bytes) = pack_store(store)?;
    if files <= MAX_FETCH_OBJECT_FILES && bytes <= MAX_FETCH_OBJECT_BYTES {
        return Ok(());
    }
    Err(GitErr::FetchObjectStoreTooLarge {
        files,
        bytes,
        max_files: MAX_FETCH_OBJECT_FILES,
        max_bytes: MAX_FETCH_OBJECT_BYTES,
    })
}

/// Entries and bytes `.git/objects/pack` holds right now. Anything in there that is not a plain
/// file is refused rather than measured: the directory is git's, and a symlink or device node in
/// it is not something a size check can answer for.
fn pack_store(store: &Path) -> Result<(usize, u64), GitErr> {
    let pack = store.join(GIT_DIR).join("objects").join("pack");
    let entries = match std::fs::read_dir(&pack) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(error) => return Err(error.into()),
    };
    let mut files = 0usize;
    let mut bytes = 0u64;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            return Err(GitErr::UnsafeFetchObject { path });
        }
        files = files.saturating_add(1);
        bytes = bytes.saturating_add(metadata.len());
    }
    Ok((files, bytes))
}

/// Make an over-budget pack store recoverable instead of terminal. Without this one hostile
/// remote can leave the ceiling crossed for good: every later fetch fails its before-check,
/// including the fetch a restore depends on, and nothing in git prunes with `gc.auto=0`.
///
/// Only objects no local ref, reflog, index or `HEAD` still reaches are dropped, so this can
/// return the store to budget but can never cost it local history. Callers hold the mutation
/// guard because `--prune=now` waives the grace period that would otherwise cover an object a
/// concurrent `git add` has written but not yet referenced.
fn reclaim_fetch_objects(store: &Path, max_files: usize, max_bytes: u64) -> Result<(), GitErr> {
    let (files, bytes) = pack_store(store)?;
    if files <= max_files && bytes <= max_bytes {
        return Ok(());
    }
    tracing::warn!(
        files,
        bytes,
        "the fetched-object store is over budget; dropping what no local ref reaches"
    );
    git(
        Some(store),
        GitOp::Fetch,
        &["-c", "gc.cruftPacks=false", "gc", "--prune=now", "--quiet"],
    )?;
    Ok(())
}

/// Run one git and hand back its exit code, for the commands whose non-zero exits are answers
/// rather than failures. Both streams are captured: a console owns the terminal and library
/// code may not draw into it.
fn run(store: Option<&Path>, op: GitOp, argv: &[&str]) -> Step<Ran> {
    let mut command = scrubbed(store);
    let is_fetch = argv.first() == Some(&"fetch");
    if is_fetch {
        let store = store.ok_or_else(|| step_failure(op, GitErr::MalformedRemoteTree))?;
        fetch_object_budget(store).map_err(|error| step_failure(op, error))?;
        harden_fetch(&mut command).map_err(|error| step_failure(op, error))?;
    }
    command.args(argv);
    let output = hc_core::output_bounded_timeout_memory(
        &mut command,
        MAX_COMMAND_STDOUT_BYTES,
        MAX_COMMAND_STDERR_BYTES,
        GIT_COMMAND_TIMEOUT,
        MAX_GIT_PROCESS_MEMORY_BYTES,
    );
    let out = match output {
        Ok(out) => out,
        Err(e) => {
            if let Some(store) = store.filter(|_| is_fetch) {
                if let Err(error) = fetch_object_budget(store) {
                    return Err(step_failure(op, error));
                }
            }
            return Err(Failed {
                op,
                cause: e.into(),
                stderr: String::new(),
            });
        }
    };
    if let Some(store) = store.filter(|_| is_fetch) {
        fetch_object_budget(store).map_err(|error| step_failure(op, error))?;
    }
    let stderr = hc_core::safe_diagnostic(&out.stderr);
    match out.status.code() {
        Some(code) => Ok(Ran {
            code,
            stdout: out.stdout,
            stderr,
        }),
        None => Err(Failed {
            op,
            cause: GitErr::GitSignal { argv: owned(argv) },
            stderr,
        }),
    }
}

/// Run one git that must succeed, and hand back its stdout.
fn git(store: Option<&Path>, op: GitOp, argv: &[&str]) -> Step<Vec<u8>> {
    let ran = run(store, op, argv)?;
    if ran.code != 0 {
        tracing::warn!(?op, ?argv, stderr = %ran.stderr, "git failed");
        return Err(Failed {
            op,
            cause: GitErr::GitFailed {
                argv: owned(argv),
                code: ran.code,
            },
            stderr: ran.stderr,
        });
    }
    Ok(ran.stdout)
}

/// Run one command on a backup host, under the same [`ssh_options`] the git transport carries.
fn ssh(remote: &BackupRemote, argv: &[&str]) -> Result<Vec<u8>, GitErr> {
    let mut command = Command::new(SSH_PROGRAM);
    for name in SCRUBBED_ASKPASS {
        command.env_remove(name);
    }
    command
        .args(ssh_options())
        .arg(&remote.host)
        .args(argv)
        .stdin(Stdio::null());
    let out = hc_core::output_bounded_timeout(
        &mut command,
        MAX_COMMAND_STDOUT_BYTES,
        MAX_COMMAND_STDERR_BYTES,
        SSH_COMMAND_TIMEOUT,
    )?;
    if out.status.success() {
        return Ok(out.stdout);
    }
    tracing::warn!(
        host = %remote.host,
        stderr = %hc_core::safe_diagnostic(&out.stderr),
        "ssh to a backup host failed"
    );
    match out.status.code() {
        Some(code) => Err(GitErr::SshFailed {
            host: remote.host.clone(),
            code,
        }),
        None => Err(GitErr::SshSignal {
            host: remote.host.clone(),
        }),
    }
}

/// `<folder>/<vault>.git` as the remote's own shell sees it. A relative folder is already
/// home-relative in both scp syntax and a login shell, so no `~/` is emitted.
fn remote_repo(remote: &BackupRemote, vault: &VaultId) -> String {
    format!(
        "{}/{vault}{BARE_SUFFIX}",
        remote.folder.trim_end_matches('/')
    )
}

/// The scp-syntax URL of one vault's bare repository on one remote.
fn url(remote: &BackupRemote, vault: &VaultId) -> String {
    format!("{}:{}", remote.host, remote_repo(remote, vault))
}

/// Read the store's vault id from cleartext `keyring.json`. Unlocks nothing.
pub fn local_vault(store: &Path) -> Result<LocalVault, GitErr> {
    let path = store.join(KEYRING_FILE);
    if !path.exists() {
        return Ok(LocalVault::Absent);
    }
    match Keyring::load(&path)?.vault_id {
        Some(v) => Ok(LocalVault::Id(v)),
        None => Ok(LocalVault::Legacy),
    }
}

/// This install's vault id, minting and saving one for a keyring written before vault ids
/// existed. That minting is the whole of the deleted `backup adopt`, run without asking.
fn store_vault(store: &Path) -> Result<VaultId, GitErr> {
    let path = store.join(KEYRING_FILE);
    match local_vault(store)? {
        LocalVault::Id(v) => Ok(v),
        LocalVault::Absent => Err(GitErr::LocalKeyringMissing {
            store: store.to_path_buf(),
        }),
        LocalVault::Legacy => {
            let mut keyring = Keyring::load(&path)?;
            let vault = VaultId::random();
            keyring.vault_id = Some(vault.clone());
            keyring.save(&path)?;
            tracing::info!(%vault, "minted a vault id for a keyring written before they existed");
            Ok(vault)
        }
    }
}

/// Refuse when a vault id is not the one that was asked for. `None` means "a keyring with no
/// vault id", which is a DIFFERENT vault from any `v_…` id.
fn require_vault(
    site: VaultSite,
    requested: Option<&VaultId>,
    found: Option<&VaultId>,
) -> Result<(), GitErr> {
    if requested == found {
        return Ok(());
    }
    Err(GitErr::VaultMismatch {
        site,
        requested: requested.cloned(),
        found: found.cloned(),
    })
}

/// One local ref's commit. `None` is the unborn branch of a store with nothing to commit yet,
/// which is a correct answer and not a failure.
fn rev(store: &Path, name: &str) -> Step<Option<CommitId>> {
    let argv = ["rev-parse", "--verify", "--quiet", name];
    let ran = run(Some(store), GitOp::Commit, &argv)?;
    match ran.code {
        1 => Ok(None),
        0 => Ok(Some(parse_id(&ran.stdout, GitOp::Commit)?)),
        code => Err(Failed {
            op: GitOp::Commit,
            cause: GitErr::GitFailed {
                argv: owned(&argv),
                code,
            },
            stderr: ran.stderr,
        }),
    }
}

/// The commit the last fetch into this repository landed.
fn fetch_head(store: &Path) -> Step<CommitId> {
    let out = git(Some(store), GitOp::Fetch, &["rev-parse", "FETCH_HEAD"])?;
    parse_id(&out, GitOp::Fetch)
}

/// Refuse any fetched tree that is not exactly a bounded hot_cheese store. In particular,
/// symlinks and gitlinks never reach a checkout, and a remote cannot turn the store into an
/// arbitrary file hierarchy that later code follows.
fn validate_remote_tree(store: &Path, commit: CommitId, op: GitOp) -> Step<()> {
    let tree = git(
        Some(store),
        op,
        &["ls-tree", "-rlz", "--full-tree", &commit.to_string()],
    )?;
    let mut files = 0usize;
    let mut bytes = 0u64;
    for record in tree.split(|byte| *byte == 0).filter(|r| !r.is_empty()) {
        files = files.saturating_add(1);
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| step_failure(op, GitErr::MalformedRemoteTree))?;
        let header = std::str::from_utf8(&record[..tab]).map_err(|err| step_failure(op, err))?;
        let path = std::str::from_utf8(&record[tab + 1..]).map_err(|err| step_failure(op, err))?;
        let mut terms = header.split_ascii_whitespace();
        let (Some(mode), Some(kind), Some(_object), Some(size)) =
            (terms.next(), terms.next(), terms.next(), terms.next())
        else {
            return Err(step_failure(op, GitErr::MalformedRemoteTree));
        };
        if terms.next().is_some() {
            return Err(step_failure(op, GitErr::MalformedRemoteTree));
        }
        if mode != "100644" || kind != "blob" {
            return Err(step_failure(
                op,
                GitErr::UnsupportedRemoteEntry {
                    path: hc_core::safe_diagnostic_text(path),
                    mode: hc_core::safe_diagnostic_text(mode),
                    kind: hc_core::safe_diagnostic_text(kind),
                },
            ));
        }
        let size: u64 = size.parse().map_err(|err| step_failure(op, err))?;
        validate_remote_path(path, size).map_err(|err| step_failure(op, err))?;
        bytes = bytes
            .checked_add(size)
            .ok_or_else(|| step_failure(op, GitErr::RemoteTreeTooLarge { files, bytes }))?;
        if files > MAX_STORE_FILES || bytes > MAX_STORE_BYTES {
            return Err(step_failure(
                op,
                GitErr::RemoteTreeTooLarge { files, bytes },
            ));
        }
    }
    Ok(())
}

fn validate_remote_path(path: &str, size: u64) -> Result<(), GitErr> {
    let Some(max) = store_path_limit(path) else {
        return Err(GitErr::UnsafeRemotePath {
            path: hc_core::safe_diagnostic_text(path),
        });
    };
    if size > max {
        return Err(GitErr::RemoteBlobTooLarge {
            path: hc_core::safe_diagnostic_text(path),
            size,
            max,
        });
    }
    Ok(())
}

/// Per-file ceiling for the complete store namespace. Returning `None` means the path is not a
/// store object at all. Both fetched trees and the local pre-commit scan use this one grammar, so
/// a path cannot be accepted for upload but refused on restore (or vice versa).
fn store_path_limit(path: &str) -> Option<u64> {
    let max = if path == KEYRING_FILE {
        MAX_KEYRING_BYTES
    } else if !path.contains('/') && is_valid_key_name(path) {
        MAX_KEYSTORE_FILE_BYTES
    } else if let Some(file) = path.strip_prefix("policies/") {
        let name = file.strip_suffix(".toml")?;
        if file.contains('/') || !is_valid_key_name(name) {
            return None;
        }
        MAX_POLICY_BYTES
    } else {
        return None;
    };
    Some(max)
}

/// Refuse to stage anything outside the bounded store grammar. This check happens before
/// `git add`, so a misplaced document or an unexpectedly huge file is neither copied into the
/// object database nor sent to a backup. The staged-tree validation in [`commit`] repeats the
/// grammar after `git add`; this filesystem pass is the early, resource-safe half of the pair.
fn validate_local_store_tree(store: &Path) -> Result<(), GitErr> {
    let store_meta = std::fs::symlink_metadata(store)?;
    if !store_meta.file_type().is_dir() {
        return Err(GitErr::UnsafeLocalStoreEntry {
            path: store.to_path_buf(),
        });
    }

    let mut inspected = 0usize;
    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut inspect_file = |path: PathBuf, relative: &str, size: u64| -> Result<(), GitErr> {
        let Some(max) = store_path_limit(relative) else {
            return Err(GitErr::UnsafeLocalStoreEntry { path });
        };
        if size > max {
            return Err(GitErr::LocalBlobTooLarge { path, size, max });
        }
        files = files.saturating_add(1);
        bytes = bytes.checked_add(size).ok_or(GitErr::LocalTreeTooLarge {
            files,
            bytes: u64::MAX,
        })?;
        if files > MAX_STORE_FILES || bytes > MAX_STORE_BYTES {
            return Err(GitErr::LocalTreeTooLarge { files, bytes });
        }
        Ok(())
    };

    let mut count_entry = || -> Result<(), GitErr> {
        inspected = inspected.saturating_add(1);
        if inspected > hc_core::MAX_STORE_ENUM_ENTRIES {
            return Err(GitErr::TooManyLocalStoreEntries {
                found: inspected,
                max: hc_core::MAX_STORE_ENUM_ENTRIES,
            });
        }
        Ok(())
    };

    for entry in std::fs::read_dir(store)? {
        count_entry()?;
        let entry = entry?;
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(GitErr::UnsafeLocalStoreEntry { path });
        };
        let kind = entry.file_type()?;
        if name == GIT_DIR {
            if !kind.is_dir() {
                return Err(GitErr::UnsafeLocalStoreEntry { path });
            }
            continue;
        }
        if name.ends_with(".hctmp") {
            if !kind.is_file() {
                return Err(GitErr::UnsafeLocalStoreEntry { path });
            }
            continue;
        }
        if name == "policies" {
            if !kind.is_dir() {
                return Err(GitErr::UnsafeLocalStoreEntry { path });
            }
            for policy in std::fs::read_dir(&path)? {
                count_entry()?;
                let policy = policy?;
                let policy_path = policy.path();
                let Some(file) = policy.file_name().to_str().map(str::to_owned) else {
                    return Err(GitErr::UnsafeLocalStoreEntry { path: policy_path });
                };
                let policy_kind = policy.file_type()?;
                if file.ends_with(".hctmp") {
                    if !policy_kind.is_file() {
                        return Err(GitErr::UnsafeLocalStoreEntry { path: policy_path });
                    }
                    continue;
                }
                if !policy_kind.is_file() {
                    return Err(GitErr::UnsafeLocalStoreEntry { path: policy_path });
                }
                let relative = format!("policies/{file}");
                inspect_file(policy_path, &relative, policy.metadata()?.len())?;
            }
            continue;
        }
        if !kind.is_file() {
            return Err(GitErr::UnsafeLocalStoreEntry { path });
        }
        inspect_file(path, &name, entry.metadata()?.len())?;
    }
    Ok(())
}

/// The keyring one commit or tree carries, parsed strictly and validated. Reads out of the object
/// database, so nothing here depends on what is currently in the worktree.
fn keyring_at(store: &Path, at: CommitId, op: GitOp) -> Step<Keyring> {
    let blob = git(Some(store), op, &["show", &format!("{at}:{KEYRING_FILE}")])?;
    let keyring: Keyring =
        hc_core::wire::strict_json_from_slice(&blob).map_err(|err| step_failure(op, err))?;
    keyring.validate().map_err(|err| step_failure(op, err))?;
    Ok(keyring)
}

fn validate_remote_keyring(
    store: &Path,
    commit: CommitId,
    vault: &VaultId,
    op: GitOp,
) -> Step<Keyring> {
    let theirs = keyring_at(store, commit, op)?;
    require_vault(VaultSite::Pulled, Some(vault), theirs.vault_id.as_ref())
        .map_err(|err| step_failure(op, err))?;
    Ok(theirs)
}

/// Enrollment ids the staged keyring drops. Nothing in this product removes an unlock path, so a
/// mutation that would is a local accident or a local attacker, and replicating it would push
/// that loss to every backup as a clean fast-forward.
fn dropped_enrollments(previous: &Keyring, staged: &Keyring) -> Vec<String> {
    let kept: BTreeSet<&str> = staged
        .enrollments
        .iter()
        .map(|enrollment| enrollment.id.as_str())
        .collect();
    let mut dropped = Vec::new();
    for enrollment in &previous.enrollments {
        if !kept.contains(enrollment.id.as_str()) {
            dropped.push(enrollment.id.clone());
        }
    }
    dropped
}

/// Enrollment ids this machine is left without: every one its keyring records, when the incoming
/// keyring keeps none of them. A `keyring.json` that lost the last enrollment this machine can use
/// arrives as a modification rather than a deletion, so nothing else in the pull path notices that
/// the DEK becomes unreachable the moment it applies. Empty while any local unlock path survives,
/// and for a store with no keyring to lose — which is the machine a restore is rebuilding.
fn stranded_enrollments(store: &Path, incoming: CommitId, op: GitOp) -> Step<Vec<String>> {
    let path = store.join(KEYRING_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mine = Keyring::load(&path).map_err(|err| step_failure(op, err))?;
    let dropped = dropped_enrollments(&mine, &keyring_at(store, incoming, op)?);
    match dropped.len() == mine.enrollments.len() {
        true => Ok(dropped),
        false => Ok(Vec::new()),
    }
}

fn inspect_fetched(store: &Path, remote_head: CommitId, vault: &VaultId, op: GitOp) -> Step<Found> {
    validate_remote_tree(store, remote_head, op)?;
    validate_remote_keyring(store, remote_head, vault, op)?;
    let local = rev(store, "HEAD")?;
    let relation = match local {
        None => Relation::RemoteAhead,
        Some(local) if local == remote_head => Relation::InSync,
        Some(local) => ancestry(store, local, remote_head)?,
    };
    Ok(Found {
        relation,
        local,
        remote: Some(remote_head),
    })
}

/// The local commit a push may publish. Commit-time validation protects normal mutations, but a
/// repository can predate this version or be edited with Git directly; the network boundary must
/// therefore validate the published ref again rather than assuming every commit came through
/// [`commit`]. That ref is [`HEAD_REF`], which a detached or renamed `HEAD` does not answer for.
fn publishable_head(store: &Path, vault: &VaultId) -> Result<Option<CommitId>, GitErr> {
    let Some(head) = rev(store, HEAD_REF)? else {
        return Ok(None);
    };
    validate_remote_tree(store, head, GitOp::Push)?;
    validate_remote_keyring(store, head, vault, GitOp::Push)?;
    Ok(Some(head))
}

fn parse_id(stdout: &[u8], op: GitOp) -> Step<CommitId> {
    match String::from_utf8_lossy(stdout).trim().parse() {
        Ok(id) => Ok(id),
        Err(cause) => Err(Failed {
            op,
            cause,
            stderr: String::new(),
        }),
    }
}

/// Which way one commit stands to another. Exit 0 and 1 are the two answers; anything above is
/// git failing to decide, which must never be read as "not an ancestor".
fn ancestry(store: &Path, local: CommitId, remote: CommitId) -> Step<Relation> {
    let (l, r) = (local.to_string(), remote.to_string());
    for (a, b, relation) in [
        (&l, &r, Relation::RemoteAhead),
        (&r, &l, Relation::LocalAhead),
    ] {
        let argv = ["merge-base", "--is-ancestor", a, b];
        let ran = run(Some(store), GitOp::Fetch, &argv)?;
        match ran.code {
            0 => return Ok(relation),
            1 => {}
            code => {
                return Err(Failed {
                    op: GitOp::Fetch,
                    cause: GitErr::AncestryUndecidable {
                        argv: owned(&argv),
                        code,
                    },
                    stderr: ran.stderr,
                })
            }
        }
    }
    Ok(Relation::Diverged)
}

/// Store files the index drops relative to `previous`. `git add -A` stages a deletion as
/// faithfully as an edit, so a keystore removed by a bug, a half-finished write or anyone with
/// local write access would otherwise reach every backup as a clean fast-forward.
fn staged_removals(store: &Path, previous: CommitId) -> Step<Vec<String>> {
    let removed = git(
        Some(store),
        GitOp::Commit,
        &[
            "diff",
            "--no-ext-diff",
            "--cached",
            "--no-renames",
            "--name-only",
            "--diff-filter=D",
            "-z",
            &previous.to_string(),
            "--",
        ],
    )?;
    Ok(nul_paths(&removed))
}

/// Tighten every mode, stage the worktree, validate what was staged rather than only the paths
/// seen before `git add` — a pre-existing tracked ignored file must not bypass the filesystem scan
/// and enter a backup — and name what the staged index drops against the committed tip.
///
/// Enrollment ids belong to the vault whose DEK they wrap, so the drop check runs only while the
/// committed keyring and the staged one name the same vault. A store that has just been replaced
/// carries a new vault to a repository of its own, where the old vault's backup is untouched.
fn stage(store: &Path, vault: &VaultId) -> Step<Missing> {
    validate_local_store_tree(store).map_err(|e| Failed {
        op: GitOp::Commit,
        cause: e,
        stderr: String::new(),
    })?;
    enforce_store_modes(store).map_err(|e| Failed {
        op: GitOp::Commit,
        cause: e.into(),
        stderr: String::new(),
    })?;
    git(Some(store), GitOp::Commit, &["add", "-A"])?;
    let tree = parse_id(
        &git(Some(store), GitOp::Commit, &["write-tree"])?,
        GitOp::Commit,
    )?;
    validate_remote_tree(store, tree, GitOp::Commit)?;
    let staged = validate_remote_keyring(store, tree, vault, GitOp::Commit)?;
    let Some(previous) = rev(store, "HEAD")? else {
        return Ok(Missing::default());
    };
    let committed = keyring_at(store, previous, GitOp::Commit)?;
    let ids = match committed.vault_id.as_ref() == Some(vault) {
        true => dropped_enrollments(&committed, &staged),
        false => Vec::new(),
    };
    Ok(Missing {
        paths: staged_removals(store, previous)?,
        ids,
    })
}

/// Commit only when something was staged. The staged check is what stops a no-op mutation pushing
/// an empty commit to every remote forever.
///
/// A mutation that deletes a committed store file, or drops one of this vault's enrollments, is
/// refused instead: no subcommand does either, the backup exists to survive exactly that loss, and
/// the only way back to an earlier commit is an operator-driven forced pull. A [`Consent`] the
/// operator minted by typing a [`Destruction`]'s phrase is the one thing that records it anyway,
/// and it is spent doing so — without that, the refusal is permanent and takes every later `open`
/// down with it.
///
/// The message is `hot_cheese <vault> <unix secs>` and nothing else: the diff already reveals
/// which files changed, but naming the operation would put a signing history on a remote that
/// has never held one.
fn commit(store: &Path, vault: &VaultId, consent: Option<Consent>) -> Step<Option<CommitId>> {
    let missing = stage(store, vault)?;
    match consent {
        Some(Consent(destruction)) => tracing::warn!(
            ?destruction,
            files = missing.paths.len(),
            enrollments = missing.ids.len(),
            "recording a destruction of store state the operator confirmed"
        ),
        None => {
            if !missing.paths.is_empty() {
                return Err(step_failure(
                    GitOp::Commit,
                    GitErr::CommitWouldDeleteStoreFiles {
                        paths: missing.paths,
                    },
                ));
            }
            if !missing.ids.is_empty() {
                return Err(step_failure(
                    GitOp::Commit,
                    GitErr::CommitWouldDropEnrollments { ids: missing.ids },
                ));
            }
        }
    }
    let argv = ["diff", "--cached", "--quiet"];
    let staged = run(Some(store), GitOp::Commit, &argv)?;
    match staged.code {
        0 => return Ok(None),
        1 => {}
        code => {
            return Err(Failed {
                op: GitOp::Commit,
                cause: GitErr::GitFailed {
                    argv: owned(&argv),
                    code,
                },
                stderr: staged.stderr,
            })
        }
    }
    let at = now_secs().map_err(|cause| Failed {
        op: GitOp::Commit,
        cause: cause.into(),
        stderr: String::new(),
    })?;
    let message = format!("hot_cheese {vault} {at}");
    git(
        Some(store),
        GitOp::Commit,
        &["commit", "-q", "-m", &message],
    )?;
    rev(store, "HEAD")
}

/// Make `<store>` a repository on `main`, with the exclude and the pinned identity everything
/// else depends on, and commit whatever is already there. Idempotent.
///
/// `--template=` is not decoration: an `init.templateDir` in the operator's `~/.gitconfig`
/// would install that directory's hooks here, and a `pre-commit` from it runs inside our commit
/// — arbitrary code in the process holding the store lock, on every mutation. It also leaves no
/// `.git/info` at all, and a clone's default exclude carries no `*.hctmp` rule, which is why
/// both the directory and the rule are written here on every open rather than once at creation.
///
/// `consent` is `Some` only where the operator has just confirmed destroying the store's key
/// material; every other caller, including every `open`, passes `None` and gets the guards.
pub fn ensure_repo(store: &Path, consent: Option<Consent>) -> Result<Option<CommitId>, GitErr> {
    std::fs::create_dir_all(store)?;
    validate_local_store_tree(store)?;
    let dot_git = store.join(GIT_DIR);
    match std::fs::symlink_metadata(&dot_git) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            git(Some(store), GitOp::Commit, &["init", "-q", "--template="])?;
            git(
                Some(store),
                GitOp::Commit,
                &["symbolic-ref", "HEAD", HEAD_REF],
            )?;
        }
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(GitErr::UnsafeGitDirectory { path: dot_git }),
        Err(error) => return Err(error.into()),
    }
    let info = dot_git.join("info");
    match std::fs::symlink_metadata(&info) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&info)?;
        }
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(GitErr::UnsafeGitDirectory { path: info }),
        Err(error) => return Err(error.into()),
    }
    hc_core::crypto::envelope::atomic_write(&info.join("exclude"), EXCLUDE.as_bytes())?;
    // Repository-local attributes can select arbitrary clean/smudge or diff drivers. The store
    // format has no attributes, so erase that execution surface on every open.
    hc_core::crypto::envelope::atomic_write(&info.join("attributes"), b"")?;
    for (key, value) in LOCAL_CONFIG {
        git(Some(store), GitOp::Commit, &["config", key, value])?;
    }
    let on = git(Some(store), GitOp::Commit, &["symbolic-ref", "-q", "HEAD"])?;
    if String::from_utf8_lossy(&on).trim() != HEAD_REF {
        return Err(GitErr::HeadNotOnBranch);
    }
    match local_vault(store)? {
        LocalVault::Absent => Ok(None),
        _ => Ok(commit(store, &store_vault(store)?, consent)?),
    }
}

/// Create one vault's bare repository on a backup host, idempotently.
///
/// `symbolic-ref` because a fresh bare repo's HEAD is `refs/heads/master`, and a plain
/// `git clone` of that checks out nothing while still exiting 0 — a backup that looks lost. The
/// two `receive.deny*` settings are both needed: `denyNonFastForwards` refuses a history rewrite
/// but not a ref deletion.
fn ensure_remote(remote: &BackupRemote, vault: &VaultId) -> Result<(), GitErr> {
    let repo = remote_repo(remote, vault);
    let git_dir = format!("--git-dir={repo}");
    ssh(
        remote,
        &["git", "init", "-q", "--bare", "--template=", "--", &repo],
    )?;
    for argv in [
        ["git", &git_dir, "symbolic-ref", "HEAD", HEAD_REF],
        [
            "git",
            &git_dir,
            "config",
            "receive.denyNonFastForwards",
            "true",
        ],
        ["git", &git_dir, "config", "receive.denyDeletes", "true"],
    ] {
        ssh(remote, &argv)?;
    }
    Ok(())
}

fn parse_remote_vaults(stdout: &[u8]) -> Result<RemoteVaults, GitErr> {
    let mut found = RemoteVaults::default();
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines().filter(|line| !line.is_empty()) {
        match line.strip_suffix(BARE_SUFFIX) {
            Some(name) => {
                if let Ok(v) = name.parse::<VaultId>() {
                    if found.git.contains(&v) {
                        continue;
                    }
                    let total = found.git.len().saturating_add(found.legacy.len());
                    if total >= MAX_REMOTE_VAULTS {
                        return Err(GitErr::TooManyRemoteVaults {
                            found: total + 1,
                            max: MAX_REMOTE_VAULTS,
                        });
                    }
                    found.git.push(v);
                }
            }
            None => {
                if let Ok(v) = line.parse::<VaultId>() {
                    if found.legacy.contains(&v) {
                        continue;
                    }
                    let total = found.git.len().saturating_add(found.legacy.len());
                    if total >= MAX_REMOTE_VAULTS {
                        return Err(GitErr::TooManyRemoteVaults {
                            found: total + 1,
                            max: MAX_REMOTE_VAULTS,
                        });
                    }
                    found.legacy.push(v);
                }
            }
        }
    }
    Ok(found)
}

/// Vaults present in one remote's folder, in both layouts. A plain `<id>` directory beside our
/// `<id>.git` means a machine that has not been upgraded is still rsyncing into the same folder,
/// so the two have silently stopped converging.
pub fn list_vaults(remote: &BackupRemote) -> Result<RemoteVaults, GitErr> {
    let stdout = ssh(remote, &["ls", "-1", "--", remote.folder.as_str()])?;
    let found = parse_remote_vaults(&stdout)?;
    for stale in &found.legacy {
        if found.git.contains(stale) {
            tracing::warn!(
                host = %remote.host,
                folder = %remote.folder,
                vault = %stale,
                "a pre-git backup of this vault sits beside its repository: a machine that has \
                 not been upgraded is still rsyncing here, and the two no longer converge"
            );
        }
    }
    Ok(found)
}

/// The vault a pull should fetch: `explicit` when given, else this install's own id, else —
/// with no local keyring at all — the remote's single vault. More than one is never guessed at.
pub fn pull_vault(
    cfg: &Config,
    remote: &BackupRemote,
    explicit: Option<VaultId>,
) -> Result<VaultId, GitErr> {
    if let Some(v) = explicit {
        return Ok(v);
    }
    let store = cfg.store_path();
    match local_vault(&store)? {
        LocalVault::Id(v) => Ok(v),
        LocalVault::Legacy => store_vault(&store),
        LocalVault::Absent => {
            let mut vaults = list_vaults(remote)?.git;
            if vaults.len() > 1 {
                return Err(GitErr::AmbiguousRemoteTryPullVault { vaults });
            }
            vaults.pop().ok_or_else(|| GitErr::NoVaultOnRemote {
                host: remote.host.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hc_git_store_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make the scratch dir");
        dir
    }

    /// An enumerated deny-list stayed one variable behind the ones that matter, so nothing from
    /// git's namespace is inherited at all — while ssh keeps the environment it reaches a backup
    /// host through, which an `env_clear` would have taken away.
    #[test]
    fn no_git_variable_is_inherited_and_ssh_keeps_its_own_environment() {
        for hostile in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_CONFIG",
            "GIT_CONFIG_GLOBAL",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALLOW_PROTOCOL",
            "GIT_PROTOCOL_FROM_USER",
            "GIT_TRACE",
            "GIT_TRACE2_EVENT",
            "GIT_EXTERNAL_DIFF",
            "GIT_AUTHOR_EMAIL",
            "GIT_SSH",
            "SSH_ASKPASS",
            "SSH_ASKPASS_REQUIRE",
        ] {
            assert!(is_scrubbed(hostile), "{hostile} reaches a git child");
        }
        for keep in ["HOME", "SSH_AUTH_SOCK", "PATH", "USER", "TMPDIR"] {
            assert!(!is_scrubbed(keep), "{keep} was taken from ssh");
        }
        let command = scrubbed(None);
        for (name, value) in command.get_envs() {
            if value.is_none() {
                assert!(
                    is_scrubbed(&name.to_string_lossy()),
                    "{name:?} was taken from a git child for no reason"
                );
            }
        }
        assert!(
            command
                .get_envs()
                .any(|(name, value)| name == "GIT_CONFIG_GLOBAL"
                    && value.is_some_and(|set| set.to_string_lossy() == "/dev/null")),
            "the sweep must run before the settings this code installs, not after"
        );
    }

    /// git re-parses these options out of `GIT_SSH_COMMAND` through `/bin/sh` while [`ssh`] hands
    /// the same list to `execve`, so an option only one of the two strings carries, or one that is
    /// not a single shell word, reaches only one of the two ways to a backup host.
    #[test]
    fn both_backup_transports_carry_the_same_pinned_ssh_options() {
        let options = ssh_options();
        for pinned in [
            "-F",
            "/dev/null",
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=~/.ssh/known_hosts",
            "BatchMode=yes",
        ] {
            assert!(
                options.iter().any(|option| option == pinned),
                "{pinned} is not among the ssh options"
            );
        }
        for option in &options {
            assert!(
                !option.starts_with('~')
                    && option
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_./=~".contains(c)),
                "{option} is not a single shell word"
            );
        }
        let expected = std::ffi::OsString::from(format!("{SSH_PROGRAM} {}", options.join(" ")));
        assert!(
            scrubbed(None)
                .get_envs()
                .any(|(name, value)| name == "GIT_SSH_COMMAND"
                    && value == Some(expected.as_os_str())),
            "the git transport reaches a backup host through different ssh options"
        );
    }

    #[test]
    fn fetches_pin_the_verified_pack_path_and_resource_controls() {
        let mut command = scrubbed(None);
        harden_fetch(&mut command).expect("install the fixed fetch limits");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for required in [
            "fetch.fsckObjects=true",
            "fetch.unpackLimit=1",
            "fetch.writeCommitGraph=false",
            "maintenance.auto=false",
            "gc.auto=0",
            "submodule.recurse=false",
            "core.bigFileThreshold=1m",
            "core.deltaBaseCacheLimit=16m",
            "pack.threads=1",
        ] {
            assert!(args.iter().any(|arg| arg == required), "missing {required}");
        }

        let dir = scratch("fetch_file_limit");
        let output = dir.join("oversized");
        let mut writer = Command::new("/bin/dd");
        writer
            .arg("if=/dev/zero")
            .arg(format!("of={}", output.display()))
            .arg("bs=2048")
            .arg("count=1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        hc_core::limit_child_file_size(&mut writer, 1024)
            .expect("install the test file-size limit");
        assert!(
            !writer.status().expect("run the bounded writer").success(),
            "the inherited file-size ceiling must stop an oversized write"
        );
        assert!(
            std::fs::metadata(&output)
                .map(|metadata| metadata.len() <= 1024)
                .unwrap_or(true),
            "the child crossed its file-size ceiling"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn repeated_fetches_cannot_grow_the_pack_store_without_a_total_ceiling() {
        let dir = scratch("fetch_object_budget");
        let pack = dir.join(GIT_DIR).join("objects").join("pack");
        std::fs::create_dir_all(&pack).expect("make the pack directory");
        std::fs::write(pack.join("pack-small.pack"), b"pack").expect("write a small pack");
        fetch_object_budget(&dir).expect("a small retained pack is within budget");

        let oversized = std::fs::File::create(pack.join("pack-hostile.pack"))
            .expect("reserve a sparse hostile pack");
        oversized
            .set_len(MAX_FETCH_OBJECT_BYTES + 1)
            .expect("make the sparse file exceed the cumulative ceiling");
        assert!(matches!(
            fetch_object_budget(&dir),
            Err(GitErr::FetchObjectStoreTooLarge {
                max_files: MAX_FETCH_OBJECT_FILES,
                max_bytes: MAX_FETCH_OBJECT_BYTES,
                ..
            })
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_remote_cannot_publish_an_unbounded_vault_listing() {
        let mut listing = String::new();
        for at in 0..=MAX_REMOTE_VAULTS {
            listing.push_str(&format!("v_{at:032x}.git\n"));
        }
        assert!(matches!(
            parse_remote_vaults(listing.as_bytes()),
            Err(GitErr::TooManyRemoteVaults {
                found,
                max: MAX_REMOTE_VAULTS,
            }) if found == MAX_REMOTE_VAULTS + 1
        ));

        let one = "v_0000000000000000000000000000002a.git\n";
        let deduplicated = parse_remote_vaults(format!("{one}{one}").as_bytes())
            .expect("duplicates do not consume the bounded result");
        assert_eq!(deduplicated.git.len(), 1);
    }

    const FIRST_ENROLLMENT: &str = "enr_00000000000000000000000000000000";

    /// A keyring naming `vault` and exactly `enrollments`, which is how a fixture becomes another
    /// vault, or another set of unlock paths, without unlocking anything.
    fn write_keyring(store: &Path, vault: &VaultId, enrollments: &[&str]) {
        let mut recorded = Vec::new();
        for id in enrollments {
            recorded.push(serde_json::json!({
                "id": id,
                "label": "test recovery",
                "created_at": 1,
                "params": {
                    "kind": "passphrase",
                    "kdf": "argon2id",
                    "salt": "00000000000000000000000000000000",
                    "m_cost": 65536,
                    "t_cost": 3,
                    "p_cost": 1
                },
                "wrapped_dek": {
                    "v": 1,
                    "cipher": "xchacha20poly1305",
                    "nonce": "000000000000000000000000000000000000000000000000",
                    "ct": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                }
            }));
        }
        let keyring = serde_json::json!({
            "v": 1,
            "vault_id": vault.to_string(),
            "enrollments": recorded,
        });
        std::fs::write(
            store.join(KEYRING_FILE),
            serde_json::to_vec(&keyring).expect("serialize fixture keyring"),
        )
        .expect("write the keyring");
    }

    /// A store with a keyring, a keystore and a policy: what every one of these tests commits.
    fn store_at(dir: &Path, vault: &VaultId) -> PathBuf {
        let store = dir.join("store");
        std::fs::create_dir_all(store.join("policies")).expect("make the store");
        write_keyring(&store, vault, &[FIRST_ENROLLMENT]);
        std::fs::write(store.join("TREASURY"), b"keystore-one").expect("write a keystore");
        std::fs::write(store.join("policies").join("x.toml"), b"safe = \"0x0\"\n")
            .expect("write a policy");
        store
    }

    /// A bare repository at the same path a real remote would hold, so a push needs no network.
    fn bare_at(dir: &Path, vault: &VaultId) -> String {
        let path = dir
            .join(format!("{vault}{BARE_SUFFIX}"))
            .to_string_lossy()
            .into_owned();
        git(
            None,
            GitOp::EnsureRemote,
            &["init", "-q", "--bare", "--template=", "--", &path],
        )
        .expect("the bare repo is created");
        git(
            None,
            GitOp::EnsureRemote,
            &[
                &format!("--git-dir={path}"),
                "symbolic-ref",
                "HEAD",
                HEAD_REF,
            ],
        )
        .expect("the bare repo's HEAD names main");
        path
    }

    fn clone_at(bare: &str, into: &Path) {
        git(
            None,
            GitOp::Fetch,
            &[
                "-c",
                "core.fileMode=false",
                "clone",
                "--quiet",
                "--branch",
                BRANCH,
                "--",
                bare,
                &into.to_string_lossy(),
            ],
        )
        .expect("the clone lands");
        for (key, value) in LOCAL_CONFIG {
            git(Some(into), GitOp::Fetch, &["config", key, value]).expect("the clone configures");
        }
    }

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .expect("the path exists")
            .permissions()
            .mode()
            & 0o777
    }

    fn bare_head(bare: &str) -> Vec<u8> {
        git(
            None,
            GitOp::Fetch,
            &[&format!("--git-dir={bare}"), "rev-parse", HEAD_REF],
        )
        .expect("the bare repo has main")
    }

    /// A checkout recreates every file at the process umask, so the 0600 this stage establishes
    /// survives neither a clone nor a fast-forward that rewrites an existing keystore — and the
    /// fixup must not dirty the tree, which is what pins `core.fileMode false` and the
    /// skip-`.git` rule together. No `umask()` call: umask is process-global and tests share a
    /// process.
    #[test]
    fn store_modes_survive_a_checkout() {
        let dir = scratch("modes");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let bare = bare_at(&dir, &vault);
        assert!(
            bare.ends_with(&format!("{vault}{BARE_SUFFIX}")),
            "a vault's repository is named after it, so two vaults never share one location"
        );

        ensure_repo(&store, None).expect("the store becomes a repo");
        assert_eq!(mode(&store.join("TREASURY")), 0o600);
        assert_eq!(mode(&store), 0o700);
        git(
            Some(&store),
            GitOp::Push,
            &["push", "--quiet", &bare, REFSPEC],
        )
        .expect("the first push creates main");

        let copy = dir.join("clone");
        clone_at(&bare, &copy);
        assert_eq!(
            mode(&copy.join("TREASURY")),
            0o644,
            "a checkout recreates files at the umask; this is the hazard"
        );
        enforce_store_modes(&copy).expect("the clone is tightened");
        assert_eq!(mode(&copy.join("TREASURY")), 0o600);
        assert_eq!(mode(&copy.join(KEYRING_FILE)), 0o600);
        assert_eq!(mode(&copy.join("policies").join("x.toml")), 0o600);
        assert_eq!(mode(&copy), 0o700);
        assert_eq!(mode(&copy.join("policies")), 0o700);
        assert!(
            git(Some(&copy), GitOp::Commit, &["status", "--porcelain"])
                .expect("status runs")
                .is_empty(),
            "tightening the modes must not dirty the tree"
        );

        std::fs::write(store.join("TREASURY"), b"keystore-two").expect("edit the keystore");
        commit(&store, &vault, None).expect("the edit commits");
        git(
            Some(&store),
            GitOp::Push,
            &["push", "--quiet", &bare, REFSPEC],
        )
        .expect("the edit pushes");
        git(
            Some(&copy),
            GitOp::Fetch,
            &["fetch", "--quiet", &bare, HEAD_REF],
        )
        .expect("the clone fetches");
        git(
            Some(&copy),
            GitOp::ForcedPull,
            &["merge", "--ff-only", "--quiet", "FETCH_HEAD"],
        )
        .expect("the fast-forward applies");
        assert_eq!(
            mode(&copy.join("TREASURY")),
            0o644,
            "a merge rewrites a modified tracked file at the umask too"
        );
        enforce_store_modes(&copy).expect("the merge is tightened");
        assert_eq!(mode(&copy.join("TREASURY")), 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inspecting_a_fast_forward_never_changes_the_active_store() {
        let dir = scratch("fetch_only");
        let vault = VaultId::random();
        let upstream = store_at(&dir, &vault);
        let bare = bare_at(&dir, &vault);
        ensure_repo(&upstream, None).expect("the upstream becomes a repo");
        git(
            Some(&upstream),
            GitOp::Push,
            &["push", "--quiet", &bare, REFSPEC],
        )
        .expect("the first push creates main");

        let active = dir.join("active");
        clone_at(&bare, &active);
        let active_head = rev(&active, "HEAD")
            .expect("head reads")
            .expect("head exists");
        let active_key = std::fs::read(active.join("TREASURY")).expect("active key reads");

        std::fs::write(upstream.join("TREASURY"), b"remote replacement")
            .expect("remote changes a key");
        commit(&upstream, &vault, None).expect("remote change commits");
        git(
            Some(&upstream),
            GitOp::Push,
            &["push", "--quiet", &bare, REFSPEC],
        )
        .expect("remote change pushes");
        git(
            Some(&active),
            GitOp::Fetch,
            &["fetch", "--quiet", &bare, HEAD_REF],
        )
        .expect("active store fetches into object storage");

        let remote_head = fetch_head(&active).expect("fetched head parses");
        let found = inspect_fetched(&active, remote_head, &vault, GitOp::Fetch)
            .expect("valid remote history is inspected");
        assert_eq!(found.relation, Relation::RemoteAhead);
        assert_eq!(rev(&active, "HEAD").expect("head reads"), Some(active_head));
        assert_eq!(
            std::fs::read(active.join("TREASURY")).expect("active key still reads"),
            active_key,
            "fetching an untrusted fast-forward must not make its key or policy active"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remote_tree_validation_rejects_symlinks_and_non_store_paths() {
        let dir = scratch("tree_validation");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        ensure_repo(&store, None).expect("the store becomes a repo");
        std::os::unix::fs::symlink("TREASURY", store.join("LINK"))
            .expect("make a malicious symlink");
        assert!(matches!(
            commit(&store, &vault, None),
            Err(Failed {
                cause: GitErr::UnsafeLocalStoreEntry { .. },
                ..
            })
        ));
        // Build the hostile commit by bypassing the production chokepoint; fetched history can
        // still contain one and must independently fail its object-tree validation.
        git(Some(&store), GitOp::Commit, &["add", "-f", "LINK"])
            .expect("force-add the hostile fixture");
        git(
            Some(&store),
            GitOp::Commit,
            &["commit", "-q", "-m", "hostile symlink fixture"],
        )
        .expect("commit the hostile fixture");
        let symlink_head = rev(&store, "HEAD")
            .expect("head reads")
            .expect("the fixture moved head");
        assert!(matches!(
            validate_remote_tree(&store, symlink_head, GitOp::Fetch),
            Err(Failed {
                cause: GitErr::UnsupportedRemoteEntry { .. },
                ..
            })
        ));
        assert!(matches!(
            publishable_head(&store, &vault),
            Err(GitErr::UnsupportedRemoteEntry { .. })
        ));

        assert!(matches!(
            validate_remote_path("../keyring.json", 1),
            Err(GitErr::UnsafeRemotePath { .. })
        ));
        assert!(matches!(
            validate_remote_path("policies/K.toml/extra", 1),
            Err(GitErr::UnsafeRemotePath { .. })
        ));
        assert!(matches!(
            validate_remote_path("policies", 1),
            Err(GitErr::UnsafeRemotePath { .. })
        ));
        assert!(matches!(
            validate_remote_path("K", MAX_KEYSTORE_FILE_BYTES + 1),
            Err(GitErr::RemoteBlobTooLarge { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_commits_refuse_files_outside_the_store_schema_before_staging() {
        let dir = scratch("local_tree_validation");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let notes = store.join("operator-notes.txt");
        std::fs::write(&notes, b"must never enter a backup").expect("write an accidental file");

        assert!(matches!(
            ensure_repo(&store, None),
            Err(GitErr::UnsafeLocalStoreEntry { path }) if path == notes
        ));
        assert!(
            !store.join(GIT_DIR).exists(),
            "validation runs before git can copy the accidental file into its object database"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staged_tree_validation_catches_a_previously_tracked_ignored_file() {
        let dir = scratch("staged_tree_validation");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        ensure_repo(&store, None).expect("the store becomes a repo");
        std::fs::write(store.join("LEFTOVER.hctmp"), b"half written")
            .expect("write an ignored temporary");
        git(
            Some(&store),
            GitOp::Commit,
            &["add", "-f", "LEFTOVER.hctmp"],
        )
        .expect("force-add the pre-existing tracked fixture");
        git(
            Some(&store),
            GitOp::Commit,
            &["commit", "-q", "-m", "tracked ignored fixture"],
        )
        .expect("commit the fixture outside the production chokepoint");

        assert!(matches!(
            commit(&store, &vault, None),
            Err(Failed {
                cause: GitErr::UnsafeRemotePath { .. },
                ..
            })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two histories that both moved must be refused rather than merged, and the refusal must
    /// leave both sides untouched: this is the whole of "divergence is a surfaced state, never a
    /// silent overwrite".
    #[test]
    fn divergence_is_refused_not_merged() {
        let dir = scratch("diverge");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let bare = bare_at(&dir, &vault);
        ensure_repo(&store, None).expect("the store becomes a repo");
        git(
            Some(&store),
            GitOp::Push,
            &["push", "--quiet", &bare, REFSPEC],
        )
        .expect("the first push creates main");

        let other = dir.join("other");
        clone_at(&bare, &other);

        std::fs::write(store.join("TREASURY"), b"ours").expect("our edit");
        commit(&store, &vault, None).expect("our commit");
        git(
            Some(&store),
            GitOp::Push,
            &["push", "--quiet", &bare, REFSPEC],
        )
        .expect("our push");

        std::fs::write(other.join("OPS"), b"theirs").expect("their edit");
        commit(&other, &vault, None).expect("their commit");
        let before = std::fs::read(other.join("OPS")).expect("their file exists");

        git(
            Some(&other),
            GitOp::Fetch,
            &["fetch", "--quiet", &bare, HEAD_REF],
        )
        .expect("they fetch");
        let local = rev(&other, "HEAD")
            .expect("head reads")
            .expect("their branch is born");
        let remote = fetch_head(&other).expect("FETCH_HEAD parses");
        assert_eq!(
            ancestry(&other, local, remote).expect("ancestry decides"),
            Relation::Diverged
        );
        assert!(
            git(
                Some(&other),
                GitOp::ForcedPull,
                &["merge", "--ff-only", "--quiet", "FETCH_HEAD"]
            )
            .is_err(),
            "a fast-forward-only merge must refuse a fork"
        );
        assert_eq!(
            std::fs::read(other.join("OPS")).expect("their file survives"),
            before,
            "a refused merge must leave the worktree byte-identical"
        );

        let unmoved = bare_head(&bare);
        assert!(
            git(
                Some(&other),
                GitOp::Push,
                &["push", "--quiet", &bare, REFSPEC]
            )
            .is_err(),
            "a diverged push must be refused"
        );
        assert_eq!(
            unmoved,
            bare_head(&bare),
            "a refused push must leave the remote unmoved"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without the staged-nothing check every no-op mutation would push an empty commit to
    /// every remote forever.
    #[test]
    fn commit_skips_when_nothing_changed() {
        let dir = scratch("empty");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let first = ensure_repo(&store, None)
            .expect("the store becomes a repo")
            .expect("a populated store commits once");

        assert!(commit(&store, &vault, None)
            .expect("a no-op runs")
            .is_none());
        assert!(commit(&store, &vault, None)
            .expect("a no-op runs")
            .is_none());
        assert_eq!(
            rev(&store, "HEAD").expect("head reads").expect("born"),
            first,
            "two no-op mutations must not move HEAD"
        );

        std::fs::write(store.join("TREASURY"), b"changed").expect("touch a keystore");
        let second = commit(&store, &vault, None)
            .expect("a real change commits")
            .expect("a real change moves HEAD");
        assert_ne!(second, first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `reset --hard` destroys index and worktree edits as well as committed divergence. The
    /// preview must name all three classes, and a newline in an untracked filename must stay one
    /// escaped row rather than forging a second doomed path in the confirmation.
    #[test]
    fn forced_pull_preview_includes_staged_unstaged_and_safely_framed_untracked_paths() {
        let dir = scratch("preview_paths");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let local = ensure_repo(&store, None)
            .expect("the store becomes a repo")
            .expect("the initial store has a head");

        std::fs::write(store.join("TREASURY"), b"remote replacement")
            .expect("make the future remote commit");
        let remote = commit(&store, &vault, None)
            .expect("commit the future remote")
            .expect("the future remote moves head");
        git(
            Some(&store),
            GitOp::ForcedPull,
            &["reset", "--hard", "--quiet", &local.to_string()],
        )
        .expect("return to the local head");

        std::fs::write(
            store.join("policies").join("x.toml"),
            b"unstaged local edit",
        )
        .expect("make an unstaged edit");
        std::fs::write(store.join(KEYRING_FILE), b"staged local edit").expect("make a staged edit");
        git(
            Some(&store),
            GitOp::ForcedPull,
            &["add", "--", KEYRING_FILE],
        )
        .expect("stage the keyring edit");
        std::fs::write(store.join("forged\nTREASURY"), b"untracked")
            .expect("make an untracked path with a newline");

        let doing =
            doomed_paths(&store, Some(local), remote).expect("build the destructive preview");
        for expected in ["TREASURY", KEYRING_FILE, "policies/x.toml"] {
            assert!(
                doing.tracked.iter().any(|path| path == expected),
                "missing {expected}"
            );
        }
        assert_eq!(doing.untracked, vec!["forged\\nTREASURY"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An in-flight `*.hctmp` from another writer must survive both the commit and the forced
    /// pull, which is only true because the exclude rule is written on every open — a clone's
    /// default exclude has no such rule and `clean -ffd` would delete it. Double force also
    /// removes an untracked nested repository rather than reporting a restore that left it.
    #[test]
    fn a_half_written_keystore_is_never_committed_or_cleaned() {
        let dir = scratch("hctmp");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        ensure_repo(&store, None).expect("the store becomes a repo");
        std::fs::write(store.join("TREASURY.hctmp"), b"half").expect("a half-written keystore");
        std::fs::write(store.join("policies").join("x.hctmp"), b"half").expect("and one nested");

        assert!(
            commit(&store, &vault, None)
                .expect("a commit runs")
                .is_none(),
            "a store whose only new files are temporary has nothing to commit"
        );
        let nested = store.join("old-vault");
        std::fs::create_dir(&nested).expect("make an untracked nested repository");
        git(
            None,
            GitOp::Commit,
            &["init", "-q", "--template=", "--", &nested.to_string_lossy()],
        )
        .expect("initialize the nested repository");
        let doing = doomed_paths(
            &store,
            rev(&store, "HEAD").expect("head reads"),
            rev(&store, "HEAD")
                .expect("head still reads")
                .expect("the store has a head"),
        )
        .expect("preview the clean");
        assert!(doing.untracked.iter().any(|path| path == "old-vault/"));
        git(Some(&store), GitOp::ForcedPull, &["clean", "-ffdq"]).expect("clean runs");
        assert!(store.join("TREASURY.hctmp").exists());
        assert!(store.join("policies").join("x.hctmp").exists());
        assert!(!nested.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sharing one folder is only safe if a pull that lands on the wrong vault is refused, in
    /// both directions: a store already holding another vault, and a remote that declared
    /// another vault's keyring. A keyring with no id is its own vault, so it must not silently
    /// absorb — or be absorbed by — a namespaced one.
    #[test]
    fn a_pull_refuses_every_vault_but_the_requested_one() {
        let mine: VaultId = "v_0f1e2d3c4b5a69788796a5b4c3d2e1f0"
            .parse()
            .expect("fixed vault id parses");
        let theirs: VaultId = "v_ffeeddccbbaa99887766554433221100"
            .parse()
            .expect("other vault id parses");

        require_vault(VaultSite::LocalStore, Some(&mine), Some(&mine)).expect("same vault passes");
        require_vault(VaultSite::Pulled, None, None).expect("legacy to legacy passes");

        match require_vault(VaultSite::Pulled, Some(&mine), Some(&theirs)) {
            Err(GitErr::VaultMismatch {
                site,
                requested,
                found,
            }) => {
                assert_eq!(site, VaultSite::Pulled);
                assert_eq!(requested, Some(mine.clone()));
                assert_eq!(found, Some(theirs.clone()));
            }
            other => panic!("expected a mismatch, got {other:?}"),
        }

        assert!(require_vault(VaultSite::LocalStore, Some(&mine), Some(&theirs)).is_err());
        assert!(require_vault(VaultSite::LocalStore, Some(&mine), None).is_err());
        assert!(require_vault(VaultSite::LocalStore, None, Some(&theirs)).is_err());
    }

    /// A remote reached over a path rather than ssh, so the whole chokepoint runs offline. The
    /// colon is what `url` puts between host and folder, and git reads a string whose first
    /// slash precedes its first colon as a local path.
    fn local_remote(dir: &Path, vault: &VaultId) -> (BackupRemote, String) {
        let remote = BackupRemote {
            host: dir.join("remote").to_string_lossy().into_owned(),
            folder: "vaults".to_string(),
        };
        let folder = dir.join("remote:vaults");
        std::fs::create_dir_all(&folder).expect("make the remote folder");
        let bare = folder
            .join(format!("{vault}{BARE_SUFFIX}"))
            .to_string_lossy()
            .into_owned();
        git(
            None,
            GitOp::EnsureRemote,
            &["init", "-q", "--bare", "--template=", "--", &bare],
        )
        .expect("the bare repo is created");
        git(
            None,
            GitOp::EnsureRemote,
            &[
                &format!("--git-dir={bare}"),
                "symbolic-ref",
                "HEAD",
                HEAD_REF,
            ],
        )
        .expect("the bare repo's HEAD names main");
        assert_eq!(url(&remote, vault), bare, "the fixture is the URL git gets");
        (remote, bare)
    }

    fn cli_store(dir: &Path, store: &Path, remotes: Vec<BackupRemote>) -> GitStore {
        let config: Config = serde_json::from_value(serde_json::json!({
            "service": "test",
            "account": "test",
            "store": store.to_string_lossy(),
            "backup_remotes": remotes.iter().map(|remote| serde_json::json!({
                "host": remote.host,
                "folder": remote.folder,
            })).collect::<Vec<_>>(),
        }))
        .expect("build the fixture config");
        let claim = flock::Claim::take(&dir.join("store.lock")).expect("claim the fixture store");
        GitStore::cli(Arc::new(config), claim).expect("open the fixture store")
    }

    /// The chokepoint pushed while still holding the store's mutation guard, and the push takes
    /// that same guard again to read the vault: every mutation of an install with a backup remote
    /// hung forever, holding the lock that excludes every other operation.
    #[test]
    fn a_mutation_with_a_backup_remote_finishes_and_publishes_what_it_validated() {
        let dir = scratch("mutation_push");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let (remote, bare) = local_remote(&dir, &vault);
        let git_store = cli_store(&dir, &store, vec![remote]);
        git_store.open().expect("the store becomes a repo");
        std::fs::write(store.join("TREASURY"), b"rotated").expect("mutate a keystore");

        let mutating = std::thread::spawn(move || (git_store.after_mutation(), git_store));
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while !mutating.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            mutating.is_finished(),
            "the mutation is deadlocked while holding the store lock"
        );
        let (done, git_store) = mutating.join().expect("the mutation thread did not panic");
        done.expect("the mutation commits and pushes");

        let head = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the mutation committed");
        assert_eq!(
            String::from_utf8_lossy(&bare_head(&bare)).trim(),
            head.to_string(),
            "the backup must hold exactly the commit the push validated"
        );
        drop(git_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `git add -A` stages a deletion as faithfully as an edit, so a keystore or an enrollment
    /// lost locally would reach every backup as a clean fast-forward — and nothing here removes
    /// either, so a mutation that does is refused with the names it would have destroyed.
    #[test]
    fn a_mutation_that_destroys_key_material_is_never_replicated() {
        let dir = scratch("deletions");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let before = ensure_repo(&store, None)
            .expect("the store becomes a repo")
            .expect("a populated store commits once");

        std::fs::remove_file(store.join("TREASURY")).expect("lose a keystore");
        match commit(&store, &vault, None) {
            Err(Failed {
                cause: GitErr::CommitWouldDeleteStoreFiles { paths },
                ..
            }) => assert_eq!(paths, vec!["TREASURY".to_string()]),
            other => panic!("a deleted keystore must not commit, got {other:?}"),
        }
        assert_eq!(
            rev(&store, "HEAD").expect("head reads"),
            Some(before),
            "a refused mutation must not move history"
        );

        std::fs::write(store.join("TREASURY"), b"restored").expect("restore the keystore");
        let path = store.join(KEYRING_FILE);
        let mut keyring: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read the keyring"))
                .expect("the fixture keyring parses");
        let enrollments = keyring["enrollments"]
            .as_array_mut()
            .expect("the fixture has enrollments");
        let mut second = enrollments[0].clone();
        second["id"] = serde_json::json!("enr_11111111111111111111111111111111");
        second["label"] = serde_json::json!("second recovery");
        enrollments.push(second);
        std::fs::write(&path, serde_json::to_vec(&keyring).expect("serialize")).expect("enroll");
        commit(&store, &vault, None)
            .expect("enrolling commits")
            .expect("enrolling moves head");

        keyring["enrollments"]
            .as_array_mut()
            .expect("the keyring still has enrollments")
            .pop();
        std::fs::write(&path, serde_json::to_vec(&keyring).expect("serialize")).expect("un-enroll");
        match commit(&store, &vault, None) {
            Err(Failed {
                cause: GitErr::CommitWouldDropEnrollments { ids },
                ..
            }) => assert_eq!(
                ids,
                vec!["enr_11111111111111111111111111111111".to_string()]
            ),
            other => panic!("a dropped enrollment must not commit, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The refusal that stops a routine mutation replicating a loss must not also stop the one
    /// operation whose whole purpose is that loss: `init --force` writes a new keyring for a new
    /// vault, and before this its commit failed, taking every later `open` — and with it `serve`,
    /// `generate` and the documented `backup pull` recovery — down for good.
    #[test]
    fn a_confirmed_replacement_records_what_a_routine_mutation_must_not() {
        let dir = scratch("replacement");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let before = ensure_repo(&store, None)
            .expect("the store becomes a repo")
            .expect("a populated store commits once");

        let replaced = VaultId::random();
        let second = "enr_11111111111111111111111111111111";
        write_keyring(&store, &replaced, &[second]);
        std::fs::remove_file(store.join("TREASURY")).expect("drop the orphaned keystore");
        match commit(&store, &replaced, None) {
            Err(Failed {
                cause: GitErr::CommitWouldDeleteStoreFiles { paths },
                ..
            }) => assert_eq!(paths, vec!["TREASURY".to_string()]),
            other => panic!("an unconfirmed deletion must not commit, got {other:?}"),
        }
        assert_eq!(rev(&store, "HEAD").expect("head reads"), Some(before));

        assert!(matches!(
            Consent::confirmed(Destruction::Replacement, Destruction::Deletion.phrase()),
            Err(GitErr::DestructionNotConfirmed {
                destruction: Destruction::Replacement
            }),
        ));
        let consent =
            Consent::confirmed(Destruction::Replacement, Destruction::Replacement.phrase())
                .expect("the exact phrase mints");
        let replacing = commit(&store, &replaced, Some(consent))
            .expect("a confirmed replacement commits")
            .expect("the replacement moves head");
        assert_ne!(replacing, before);
        assert!(
            commit(&store, &replaced, None)
                .expect("the store still commits routinely")
                .is_none(),
            "spending the capability must leave an ordinary store behind, not a wedged one"
        );
    }

    /// A store file that disappears — a partial write, a future bug — leaves every later commit
    /// refused, and `open` is a commit: `serve`, `generate` and `backup pull` all die with it, and
    /// only `init --force` could mint the capability that records it. So the loss has to be
    /// nameable and acceptable on its own, or an install in this state is unrecoverable.
    #[test]
    fn a_store_wedged_by_a_deletion_recovers_through_the_confirmed_path() {
        let dir = scratch("wedged_deletion");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let git_store = cli_store(&dir, &store, Vec::new());
        let second = "enr_11111111111111111111111111111111";
        write_keyring(&store, &vault, &[FIRST_ENROLLMENT, second]);
        git_store.open().expect("the store becomes a repo");
        let before = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the store has a head");

        std::fs::remove_file(store.join("TREASURY")).expect("a store file disappears");
        write_keyring(&store, &vault, &[FIRST_ENROLLMENT]);
        for _ in 0..2 {
            match git_store.open() {
                Err(GitErr::CommitWouldDeleteStoreFiles { paths }) => {
                    assert_eq!(paths, vec!["TREASURY".to_string()])
                }
                other => panic!("the wedge is that this never stops failing, got {other:?}"),
            }
        }
        assert_eq!(rev(&store, HEAD_REF).expect("head reads"), Some(before));

        let missing = git_store.missing().expect("the store names what is gone");
        assert_eq!(missing.paths, vec!["TREASURY".to_string()]);
        assert_eq!(missing.ids, vec![second.to_string()]);
        assert_eq!(
            rev(&store, HEAD_REF).expect("head reads"),
            Some(before),
            "naming the loss must not record it"
        );

        assert!(matches!(
            Consent::confirmed(Destruction::Deletion, "yes"),
            Err(GitErr::DestructionNotConfirmed {
                destruction: Destruction::Deletion
            }),
        ));
        let policy = store.join("policies").join("x.toml");
        let written = std::fs::read(&policy).expect("the policy reads");
        std::fs::remove_file(&policy).expect("something else goes while the question is open");
        match git_store.mutation().commit_loss(
            Consent::confirmed(Destruction::Deletion, Destruction::Deletion.phrase())
                .expect("the exact phrase mints"),
            &missing,
        ) {
            Err(GitErr::LossPreviewStale { found }) => assert_eq!(
                found.paths,
                vec!["TREASURY".to_string(), "policies/x.toml".to_string()]
            ),
            other => panic!("consent covers the loss that was shown, got {other:?}"),
        }
        std::fs::write(&policy, &written).expect("put the policy back");

        let consent = Consent::confirmed(Destruction::Deletion, Destruction::Deletion.phrase())
            .expect("the exact phrase mints");
        git_store
            .mutation()
            .commit_loss(consent, &missing)
            .expect("a confirmed loss records");
        assert_ne!(
            rev(&store, HEAD_REF)
                .expect("head reads")
                .expect("the loss moved head"),
            before
        );
        git_store
            .open()
            .expect("every later command opens the store first");
        assert!(
            git_store
                .missing()
                .expect("the recovered store still answers")
                .is_empty(),
            "spending the capability must leave an ordinary store behind, not a wedged one"
        );
        drop(git_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The state a forced init leaves on disk: a keyring for a new vault over a history that still
    /// carries the old vault's enrollments. Comparing enrollment ids across two vaults compares
    /// nothing — the ids wrap different DEKs and the new vault pushes to a repository of its own —
    /// so a store already bricked that way has to open again on this version.
    #[test]
    fn a_store_replaced_under_a_new_vault_opens_again() {
        let dir = scratch("bricked_replacement");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        ensure_repo(&store, None).expect("the store becomes a repo");

        let replaced = VaultId::random();
        write_keyring(&store, &replaced, &["enr_22222222222222222222222222222222"]);
        let recovered = ensure_repo(&store, None)
            .expect("an open after a forced init must not fail forever")
            .expect("the replacement commits");
        assert_eq!(
            rev(&store, "HEAD").expect("head reads"),
            Some(recovered),
            "every later command opens the store first, so this commit is the whole install"
        );

        write_keyring(&store, &replaced, &[]);
        match commit(&store, &replaced, None) {
            Err(Failed {
                cause: GitErr::Keyring(_),
                ..
            }) => {}
            other => panic!("an empty keyring is not a valid store, got {other:?}"),
        }
    }

    /// A hostile remote that holds this machine's tip commits a CHILD of it whose tree puts the
    /// old blobs back: ancestry says fast-forward, the diff says `M` on every path, and nothing is
    /// deleted — so the rewind gate saw nothing while an older keystore, keyring and policy all
    /// became active. Replacing the content of a store file is the rollback.
    #[test]
    fn a_child_commit_that_replays_older_content_is_still_a_rollback() {
        let dir = scratch("content_regression");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let (remote, _bare) = local_remote(&dir, &vault);
        let git_store = cli_store(&dir, &store, vec![remote.clone()]);
        git_store.open().expect("the store becomes a repo");
        let old = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the store has a head");

        std::fs::write(store.join("TREASURY"), b"rotated").expect("rotate the keystore");
        git_store.after_mutation().expect("the rotation commits");
        let mine = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the rotation moved head");

        let reverted = parse_id(
            &git(
                Some(&store),
                GitOp::Commit,
                &[
                    "commit-tree",
                    &format!("{old}^{{tree}}"),
                    "-p",
                    &mine.to_string(),
                    "-m",
                    "hostile revert",
                ],
            )
            .expect("build the hostile child"),
            GitOp::Commit,
        )
        .expect("the hostile child parses");
        git(
            Some(&store),
            GitOp::Push,
            &[
                "push",
                "--quiet",
                "--force",
                &url(&remote, &vault),
                &format!("{reverted}:{HEAD_REF}"),
            ],
        )
        .expect("the hostile host serves the reverting child");

        let mut doomed = git_store
            .pull_preview(&remote, &vault)
            .expect("preview the reverting child");
        assert_eq!(
            doomed.relation,
            Relation::RemoteAhead,
            "the attack is that ancestry is clean; that is what makes it worth catching"
        );
        assert!(doomed.removed.is_empty() && doomed.added.is_empty());
        assert_eq!(doomed.changed, vec!["TREASURY".to_string()]);
        assert_eq!(
            (doomed.rewind, doomed.local_only),
            (Some(Rewind::Contents), 0),
            "reusing Backwards here told the operator their 0 discarded commits were the danger"
        );

        match git_store.pull_apply(&doomed) {
            Err(GitErr::PullRewindNotAccepted { changed, .. }) => {
                assert_eq!(changed, vec!["TREASURY".to_string()])
            }
            other => panic!("an unaccepted content rollback must not apply, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(store.join("TREASURY")).expect("the keystore survives"),
            b"rotated"
        );

        doomed.accept_rewind();
        git_store
            .pull_apply(&doomed)
            .expect("an accepted rollback applies");
        assert_eq!(
            std::fs::read(store.join("TREASURY")).expect("the keystore reads"),
            b"keystore-one",
            "this is the state the confirmation exists to make an operator agree to"
        );
        drop(doomed);
        drop(git_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A keyring that keeps none of this machine's enrollments arrives as a modification, never a
    /// deletion, so the commit-side drop check never sees it: the pull is the one path that can
    /// leave the DEK with no way back into it, and it has to say so by name.
    #[test]
    fn a_pull_that_strands_every_enrollment_is_refused_by_name() {
        let dir = scratch("stranded_enrollments");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let (remote, _bare) = local_remote(&dir, &vault);
        let git_store = cli_store(&dir, &store, vec![remote.clone()]);
        git_store.open().expect("the store becomes a repo");
        let mine = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the store has a head");

        write_keyring(&store, &vault, &["enr_33333333333333333333333333333333"]);
        git(Some(&store), GitOp::Commit, &["add", "-A"]).expect("stage the hostile keyring");
        let tree = String::from_utf8_lossy(
            &git(Some(&store), GitOp::Commit, &["write-tree"]).expect("write the hostile tree"),
        )
        .trim()
        .to_string();
        let hostile = parse_id(
            &git(
                Some(&store),
                GitOp::Commit,
                &["commit-tree", &tree, "-p", &mine.to_string(), "-m", "swap"],
            )
            .expect("build the hostile child"),
            GitOp::Commit,
        )
        .expect("the hostile child parses");
        git(
            Some(&store),
            GitOp::ForcedPull,
            &["reset", "--hard", "--quiet", &mine.to_string()],
        )
        .expect("put this machine's keyring back");
        git(
            Some(&store),
            GitOp::Push,
            &[
                "push",
                "--quiet",
                "--force",
                &url(&remote, &vault),
                &format!("{hostile}:{HEAD_REF}"),
            ],
        )
        .expect("the hostile host serves the swapped keyring");

        let mut doomed = git_store
            .pull_preview(&remote, &vault)
            .expect("preview the swapped keyring");
        assert_eq!(doomed.changed, vec![KEYRING_FILE.to_string()]);
        assert_eq!(doomed.removed, Vec::<String>::new());
        assert_eq!(doomed.lost_enrollments, vec![FIRST_ENROLLMENT.to_string()]);
        match git_store.pull_apply(&doomed) {
            Err(GitErr::PullWouldLoseEveryEnrollment { ids }) => {
                assert_eq!(ids, vec![FIRST_ENROLLMENT.to_string()])
            }
            other => panic!("losing every unlock path must be refused by name, got {other:?}"),
        }
        assert_eq!(rev(&store, HEAD_REF).expect("head reads"), Some(mine));

        doomed.accept_rewind();
        git_store
            .pull_apply(&doomed)
            .expect("an accepted loss applies");
        assert_eq!(rev(&store, HEAD_REF).expect("head reads"), Some(hostile));
        drop(doomed);
        drop(git_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `FETCH_HEAD` is not a gc root, so the reclaim a background fetch runs deleted the commit an
    /// operator was in the middle of accepting, and the restore then failed on an object that no
    /// longer existed — a denial the hostile host could repeat at will.
    #[test]
    fn a_previewed_commit_survives_the_reclaim_that_can_run_beside_it() {
        let dir = scratch("preview_anchor");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let (remote, _bare) = local_remote(&dir, &vault);
        let git_store = cli_store(&dir, &store, vec![remote.clone()]);
        git_store.open().expect("the store becomes a repo");
        let mine = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the store has a head");

        std::fs::write(store.join("OPS"), b"a key the remote adds").expect("write the added key");
        git(Some(&store), GitOp::Commit, &["add", "-A"]).expect("stage the remote's addition");
        let tree = String::from_utf8_lossy(
            &git(Some(&store), GitOp::Commit, &["write-tree"]).expect("write the remote tree"),
        )
        .trim()
        .to_string();
        let ahead = parse_id(
            &git(
                Some(&store),
                GitOp::Commit,
                &["commit-tree", &tree, "-p", &mine.to_string(), "-m", "ahead"],
            )
            .expect("build the remote child"),
            GitOp::Commit,
        )
        .expect("the remote child parses");
        git(
            Some(&store),
            GitOp::ForcedPull,
            &["reset", "--hard", "--quiet", &mine.to_string()],
        )
        .expect("this machine does not have it yet");
        git(Some(&store), GitOp::ForcedPull, &["clean", "-ffdq"]).expect("nor untracked");
        git(
            Some(&store),
            GitOp::Push,
            &[
                "push",
                "--quiet",
                "--force",
                &url(&remote, &vault),
                &format!("{ahead}:{HEAD_REF}"),
            ],
        )
        .expect("the remote serves it");

        let doomed = git_store
            .pull_preview(&remote, &vault)
            .expect("preview the addition");
        assert_eq!(
            doomed.rewind, None,
            "a purely additive tip is not a rollback"
        );
        reclaim_fetch_objects(&store, 0, 0).expect("the reclaim a background fetch would run");
        git(
            Some(&store),
            GitOp::Fetch,
            &["cat-file", "-e", &doomed.remote_head.to_string()],
        )
        .expect("the previewed commit must outlive the reclaim");
        git_store
            .pull_apply(&doomed)
            .expect("the operator's answer still applies");
        assert_eq!(rev(&store, HEAD_REF).expect("head reads"), Some(ahead));

        drop(doomed);
        assert!(
            rev(&store, PREVIEW_REF)
                .expect("the anchor reads")
                .is_none(),
            "the anchor must not outlive the decision, or it pins objects forever"
        );
        drop(git_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A backup host serving an older commit of the store's own history passes every ancestry
    /// check there is, so the rollback has to be named and accepted as one. Until it is, the
    /// forced pull must leave the worktree it was about to replace exactly as it found it.
    #[test]
    fn a_rollback_pull_is_refused_until_that_specific_loss_is_accepted() {
        let dir = scratch("rollback_apply");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let (remote, _bare) = local_remote(&dir, &vault);
        let git_store = cli_store(&dir, &store, vec![remote.clone()]);
        git_store.open().expect("the store becomes a repo");
        git_store
            .push_every(&git_store.config)
            .expect("the backup takes the first commit");
        let backed_up = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the store has a head");

        std::fs::write(store.join("OPS"), b"a key only this machine has").expect("add a keystore");
        git_store.after_mutation().expect("the local work commits");
        let mine = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the local work moved head");
        assert_ne!(mine, backed_up);
        git(
            Some(&store),
            GitOp::Push,
            &[
                "push",
                "--quiet",
                "--force",
                &url(&remote, &vault),
                &format!("{backed_up}:{HEAD_REF}"),
            ],
        )
        .expect("the backup host serves its older commit again");

        let mut doomed = git_store
            .pull_preview(&remote, &vault)
            .expect("preview the rollback");
        assert_eq!(doomed.relation, Relation::LocalAhead);
        assert_eq!(doomed.rewind, Some(Rewind::Backwards));
        assert_eq!(doomed.removed, vec!["OPS".to_string()]);
        assert_eq!((doomed.local_only, doomed.remote_only), (1, 0));
        assert!(doomed.local_at.is_some_and(|at| at >= doomed.remote_at));

        match git_store.pull_apply(&doomed) {
            Err(GitErr::PullRewindNotAccepted {
                rewind: Rewind::Backwards,
                removed,
                ..
            }) => assert_eq!(removed, vec!["OPS".to_string()]),
            other => panic!("an unaccepted rollback must not apply, got {other:?}"),
        }
        assert_eq!(rev(&store, HEAD_REF).expect("head reads"), Some(mine));
        assert!(store.join("OPS").exists(), "the refusal changed the store");

        doomed.accept_rewind();
        git_store
            .pull_apply(&doomed)
            .expect("an accepted rollback applies");
        assert_eq!(rev(&store, HEAD_REF).expect("head reads"), Some(backed_up));
        assert!(!store.join("OPS").exists());
        drop(doomed);
        drop(git_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ancestry proves neither authorship nor freshness, so a confirmation has to say which way
    /// history moves and name what disappears. An older commit served by a backup host is a
    /// rollback, and the files it drops are the point.
    #[test]
    fn a_preview_names_the_rollback_and_the_files_it_would_remove() {
        let dir = scratch("rollback_preview");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let older = ensure_repo(&store, None)
            .expect("the store becomes a repo")
            .expect("the initial store has a head");

        std::fs::write(store.join("OPS"), b"a key only this machine has").expect("add a keystore");
        std::fs::write(store.join("TREASURY"), b"rotated").expect("rotate a keystore");
        let newer = commit(&store, &vault, None)
            .expect("the local work commits")
            .expect("the local work moves head");

        let doing = doomed_paths(&store, Some(newer), older).expect("preview the rollback");
        assert_eq!(doing.removed, vec!["OPS".to_string()]);
        assert_eq!(doing.changed, vec!["TREASURY".to_string()]);
        assert!(doing.added.is_empty());
        assert_eq!(
            commit_counts(&store, Some(newer), older).expect("count both sides"),
            (1, 0),
            "the incoming tip is one commit behind, which is what makes it a rollback"
        );
        assert_eq!(
            ancestry(&store, newer, older).expect("ancestry decides"),
            Relation::LocalAhead
        );
        assert!(
            commit_time(&store, newer).expect("local time reads")
                >= commit_time(&store, older).expect("incoming time reads")
        );

        let forward = doomed_paths(&store, Some(older), newer).expect("preview the fast-forward");
        assert_eq!(forward.added, vec!["OPS".to_string()]);
        assert!(forward.removed.is_empty());
        assert_eq!(
            commit_counts(&store, Some(older), newer).expect("count both sides"),
            (0, 1)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One hostile fetch used to wedge every later fetch and the restore path with it: the
    /// before-check failed forever and nothing in git prunes with `gc.auto=0`. Reclaiming may
    /// drop only what no local ref reaches, so the local commit and its files must survive it.
    #[test]
    fn an_over_budget_pack_store_recovers_without_losing_local_history() {
        let dir = scratch("reclaim");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let mine = ensure_repo(&store, None)
            .expect("the store becomes a repo")
            .expect("the store has a head");

        let hostile = store_at(&dir.join("hostile"), &vault);
        std::fs::write(
            hostile.join("TREASURY"),
            b"a history this machine never made",
        )
        .expect("write the hostile keystore");
        ensure_repo(&hostile, None).expect("the hostile store becomes a repo");
        git(
            Some(&store),
            GitOp::Fetch,
            &[
                "-c",
                "fetch.unpackLimit=1",
                "fetch",
                "--quiet",
                "--no-tags",
                &hostile.to_string_lossy(),
                HEAD_REF,
            ],
        )
        .expect("fetch the hostile history into object storage");
        let fetched = fetch_head(&store).expect("the hostile tip parses");
        let (_, retained) = pack_store(&store).expect("measure the pack store");
        assert!(retained > 0, "the fetch retained a pack to reclaim");

        reclaim_fetch_objects(&store, 0, 0).expect("an over-budget pack store is reclaimed");
        assert!(
            git(
                Some(&store),
                GitOp::Fetch,
                &["cat-file", "-e", &fetched.to_string()]
            )
            .is_err(),
            "the hostile objects are gone"
        );
        assert_eq!(rev(&store, "HEAD").expect("head reads"), Some(mine));
        assert_eq!(
            std::fs::read(store.join("TREASURY")).expect("the local keystore survives"),
            b"keystore-one"
        );
        git(Some(&store), GitOp::Commit, &["fsck", "--no-progress"])
            .expect("the reclaimed repository is intact");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A confirmation that claims to name everything a pull touches must not silently drop a
    /// record it cannot read: the framing is `status NUL path NUL`, and both halves are required.
    #[test]
    fn name_status_records_are_paired_or_refused() {
        assert_eq!(
            name_status(b"").expect("no output is no changes"),
            Vec::new()
        );
        assert_eq!(
            name_status(b"A\0OPS\0M\0TREASURY\0D\0policies/x.toml\0").expect("well-formed output"),
            vec![
                (Change::Added, "OPS".to_string()),
                (Change::Changed, "TREASURY".to_string()),
                (Change::Removed, "policies/x.toml".to_string()),
            ]
        );
        assert!(matches!(
            name_status(b"D\0OPS\0A\0"),
            Err(GitErr::MalformedDiffOutput { fields: 3 })
        ));
        assert!(matches!(
            name_status(b"A\0OPS"),
            Err(GitErr::MalformedDiffOutput { .. })
        ));
        assert!(matches!(
            name_status(b"R100\0OPS\0"),
            Err(GitErr::UnsupportedDiffStatus { .. })
        ));
        assert!(matches!(
            name_status(b"R100\0OPS\0TREASURY\0"),
            Err(GitErr::MalformedDiffOutput { fields: 3 })
        ));
    }
}
