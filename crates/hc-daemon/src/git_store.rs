//! The store as a git repository: every mutation auto-commits, a backup is a push, the
//! freshness probe is a fetch, and applying remote state is always an explicit operator action.
//!
//! A fast-forward proves ancestry, not authorship, and not freshness either: a backup host that
//! serves an older commit of its own history rolls this store back with a proof that checks out,
//! and a child of this machine's own tip whose tree replays older blobs does the same while
//! staying an ancestor-clean fast-forward. Backup hosts are therefore confidentiality-only stores.
//! A background task never lets one rewrite the active worktree; only an explicit operator action
//! — which names the files it will replace, add and delete first — can apply remote history, and
//! every ground on which that costs this machine something needs accepting on top
//! ([`Doomed::accept_rewind`], and [`Doomed::accept_lost_enrollments`] for the one that costs the
//! way back into the DEK). The store grammar admits only security-relevant paths, so an addition
//! is one of those grounds: a `policies/<key>.toml` where none existed turns deny-by-default into
//! allow, and a keystore where none existed puts back one a loss retired. Only a tip that changes
//! nothing this machine already has stays on the single confirmation.
//!
//! The same asymmetry runs the other way: a deletion pushed as a clean fast-forward is a deletion
//! on every backup, so a routine mutation refuses to record one at all. [`ensure_repo`] does not
//! refuse it — it leaves the tip where it is instead, because history still holds the file the
//! worktree lost and blocking `open` would block the very pull and checkout that put it back.
//! Recording the loss anyway takes a [`Destruction`] the operator confirmed: a forced init's
//! replacement, or a loss [`GitStore::missing`] named and they accepted.
//!
//! Both of those are in-process guards, and every in-process guard here has been broken at least
//! once: a [`Destruction`]'s phrase has to be public for an operator to be shown what to type, so
//! any same-uid code can read it off this source and repeat it. Local policy cannot defend against
//! local code, which leaves two guards that do not depend on this process being honest.
//!
//! The first is on the far side of the ssh connection: [`BARE_REPO_SETTINGS`] leaves every backup
//! repository refusing a ref deletion and a history rewrite, enforced by the receiving git, where
//! no flag, config or replacement binary on this machine reaches. [`ReceiveGuards`] reads them back
//! so a repository that predates them — which refuses nothing — is visible rather than silent.
//!
//! The second is [`archive_store`]: a copy of the store, on this machine but outside the home dir,
//! under the digest of its own bytes so a new snapshot can never land on an older one, never
//! rewritten and never pruned by anything here. It runs on every [`GitStore::open`], after every
//! recorded mutation and immediately before [`GitStore::pull_apply`] — and it cannot fail into any
//! of them, because it returns nothing to fail with. Its root is shared by every install on the
//! machine, so a snapshot lands under `<root>/<vault_id>/` for the same reason a push targets
//! `<folder>/<vault_id>.git`: a throwaway `HOT_CHEESE_HOME` mints its own vault on `init` and gets
//! a subtree of its own, and neither [`archive_list`] nor [`GitStore::archive_restore`] reaches
//! another install's. What that costs the operator in return is in
//! [`hc_core::config::store_archive_dir`], and it is not nothing.
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
use hc_core::crypto::envelope::{
    atomic_write_new, enforce_store_modes, EnvErr, GIT_DIR, MAX_KEYSTORE_FILE_BYTES,
};
use hc_core::keyring::{Keyring, KeyringErr, VaultId, KEYRING_FILE, MAX_KEYRING_BYTES};
use hc_core::{is_valid_key_name, MAX_STORE_BYTES, MAX_STORE_FILES};
use hc_sign::grant::{now_secs, GrantErr};
use hc_sign::policy::MAX_POLICY_BYTES;
use parking_lot::Mutex;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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

/// Repository-local settings that are a measurement of the filesystem rather than a decision, so
/// [`pin_repo_config`] carries them across the rewrite: `git init` takes them once, when it creates
/// the repository, and never again.
const PROBED_CONFIG: [&str; 2] = ["core.ignorecase", "core.precomposeunicode"];

/// Every key `.git/config` may hold once [`pin_repo_config`] has run: what `git init` writes, what
/// it measured, and the identity commits are made under. Anything else is refused, because the
/// repository-local file is the one config channel `--git-dir` cannot be told to ignore.
const PINNED_CONFIG: [&str; 8] = [
    "core.repositoryformatversion",
    "core.filemode",
    "core.bare",
    "core.logallrefupdates",
    "core.ignorecase",
    "core.precomposeunicode",
    "user.name",
    "user.email",
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
/// Commits [`keyrings_in_history`] reads back. A replaced keyring is one commit behind the
/// replacement, and every enrollment ever recorded here is worth naming, but a store whose history
/// is long must not turn one question into an unbounded walk of the object database.
const MAX_HISTORY_KEYRINGS: usize = 256;

/// Store files one `hash-object` names at a time. A store may hold [`hc_core::MAX_STORE_FILES`] of
/// them and every path is absolute, so the whole set in one argument list would approach `ARG_MAX`
/// on a store under a deep home.
const HASH_BATCH_FILES: usize = 256;

/// Everything a vault's bare repository on a backup host is set to when this code creates it.
///
/// The two `receive.deny*` settings are the only guard on losing ciphertext that a same-uid process
/// on THIS machine cannot defeat: they are enforced by the receiving git, so no local flag, config,
/// environment variable or replacement binary turns them off. Both are needed —
/// `denyNonFastForwards` refuses a history rewrite but not a ref deletion. `symbolic-ref` is here
/// because a fresh bare repo's HEAD is `refs/heads/master`, and a plain `git clone` of that checks
/// out nothing while still exiting 0: a backup that looks lost.
const BARE_REPO_SETTINGS: [[&str; 3]; 3] = [
    ["symbolic-ref", "HEAD", HEAD_REF],
    ["config", "receive.denyNonFastForwards", "true"],
    ["config", "receive.denyDeletes", "true"],
];

/// The two `receive.*` keys [`ReceiveGuards`] reads back, lowercased the way `git config --list`
/// prints them.
const DENY_DELETES: &str = "receive.denydeletes";
const DENY_NON_FAST_FORWARDS: &str = "receive.denynonfastforwards";

/// The archive's container version, so a format this code does not know is a refusal rather than
/// a misparse.
const ARCHIVE_VERSION: u32 = 1;

/// Suffix of a snapshot file; the rest of its name is the digest of the file's own bytes.
const ARCHIVE_SUFFIX: &str = ".json";
const ARCHIVE_TEMP_SUFFIX: &str = ".hctmp";

/// A snapshot is never rewritten, so it is created read-only and stays that way, in a directory
/// only its owner can reach.
const ARCHIVE_DIR_MODE: u32 = 0o700;
const ARCHIVE_FILE_MODE: u32 = 0o400;

/// Directory entries one archive listing describes before it counts the rest instead.
const MAX_ARCHIVES: usize = 1 << 16;

/// A snapshot carries the whole bounded store hex-encoded, plus its JSON frame.
const MAX_ARCHIVE_BYTES: u64 = MAX_STORE_BYTES * 2 + 1024 * 1024;

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
    PullRewindNotAccepted { rewind: Rewind, local_only: u64, remote_only: u64, added: Vec<String>, removed: Vec<String>, changed: Vec<String> },
    PullWouldLoseEveryEnrollment { ids: Vec<String> },
    CommitWouldDeleteStoreFiles { paths: Vec<String> },
    CommitWouldDropEnrollments { ids: Vec<String> },
    MalformedDiffOutput { fields: usize },
    MalformedStoreDigests { found: usize, files: usize },
    UnsupportedDiffStatus { status: String, path: String },
    MalformedCommitCounts { output: String },
    UnsafeGitDirectory { path: PathBuf },
    UnsafeRepoConfig { key: String },
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
    UnsafeArchiveDirectory { path: PathBuf },
    ArchiveNameIsNotADigest { name: String },
    ArchiveNotFound { digest: String, dir: PathBuf },
    ArchiveDoesNotHashToItsName { path: PathBuf, found: String },
    ArchiveVersionUnsupported { found: u32, supported: u32 },
    ArchiveEntryOutsideTheStoreGrammar { path: String },
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
    /// The keyring this machine's own `HEAD` carries, which survives a deleted worktree file.
    Committed,
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

/// What one backup host's own `receive.*` settings say it will accept.
///
/// Every in-process guard against losing ciphertext is an accident-guard: the confirmation phrases
/// are public constants that any same-uid process can read and repeat, so local policy cannot
/// defend against local code. These two live on the far side of an ssh connection and are enforced
/// by the receiving git, which is what makes them the one guard a local attacker cannot switch off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveGuards {
    /// `receive.denyDeletes`: the remote refuses a push that deletes a branch.
    pub deny_deletes: bool,
    /// `receive.denyNonFastForwards`: the remote refuses a push that rewrites history.
    pub deny_non_fast_forwards: bool,
}

impl ReceiveGuards {
    /// Whether this remote refuses both a deletion and a rewrite. Either one missing leaves the
    /// backup destroyable by anything that can reach it with this machine's key.
    pub fn enforced(self) -> bool {
        self.deny_deletes && self.deny_non_fast_forwards
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
    /// What the remote's own `receive.*` settings said at the last fetch that reached its
    /// repository; `None` until one has.
    pub receive_guards: Option<ReceiveGuards>,
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
        receive_guards: None,
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
    /// The incoming tip adds store files this machine's commit does not have. Additive is not
    /// safe: a missing policy is deny-by-default, so a `policies/<key>.toml` where none existed
    /// converts deny into allow, and a keystore where none existed resurrects one a recorded loss
    /// retired — under the same vault and the same DEK, so it decrypts and signs.
    Widens,
    /// The store directory holds store-grammar files whose bytes no commit here carries, so the
    /// reset overwrites the ones the incoming tip has, the clean deletes the rest, and no local
    /// history puts either back. Measured by [`unrecorded_store_files`] off the filesystem and the
    /// object database alone, because every cheaper source of the same answer — the index, the
    /// untracked list, a branch ref — is a thing a local writer owns.
    Unrecorded,
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
    /// What an operator types to authorize this destruction. Public because they cannot type back
    /// a phrase nothing showed them.
    pub const fn phrase(self) -> &'static str {
        match self {
            Destruction::Replacement => "destroy the existing hot_cheese keys",
            Destruction::Deletion => "record the loss of these hot_cheese files",
        }
    }
}

/// Consent to record a commit that destroys store state, minted from the phrase the operator
/// typed and spent by the one commit that records it. Every other commit is a routine mutation,
/// which `Recording::Refuse` will not let delete a store file or drop an enrollment.
///
/// An accident-guard, not a security boundary. [`Destruction::phrase`] has to be public for the
/// operator to be shown what to type, so any code in this workspace can mint a [`Consent`] from
/// it, and same-uid code that is already inside this process was never going to be stopped by a
/// type. What it does stop is a habitual `-y`, an unattended run, and a caller that reached the
/// destructive commit without ever asking — which a flag, a variable or a `bool` parameter would
/// all have let through.
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

/// What a commit would record as gone, and the staged tree it was read out of. A backup takes a
/// deletion as a clean fast-forward like any other change, so it cannot put back what this names.
///
/// The tree and the parent are part of the value, and part of its equality, because a [`Consent`]
/// is spent against one of these: comparing only the names would let a same-uid `rm` between the
/// question and the answer land a second deletion inside an answer nobody gave.
#[derive(Debug, PartialEq, Eq)]
pub struct Missing {
    /// Committed store files the staged index no longer has.
    pub paths: Vec<String>,
    /// This vault's enrollment ids the staged keyring no longer wraps.
    pub ids: Vec<String>,
    /// The staged tree these were read out of.
    tree: CommitId,
    /// The commit that tree was compared against; `None` before the first commit.
    head: Option<CommitId>,
}

impl Missing {
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.ids.is_empty()
    }
}

/// What a commit does about the store state its staged index drops.
enum Recording {
    /// Refuse. Nothing in this product removes a keystore or an unlock path, so a routine mutation
    /// that would is an accident or a local attacker, and a backup takes it as a fast-forward.
    Refuse,
    /// Leave it uncommitted and the tip where it is, so history keeps holding what the worktree
    /// lost. [`ensure_repo`] takes this: `open` is a commit, and a store file that vanished must
    /// not block the pull or the checkout that restores it.
    Defer,
    /// Record it, spending the consent the operator minted for exactly this.
    Confirmed(Consent),
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
    /// Store files on disk whose bytes no commit here carries, so neither the reset nor the clean
    /// can be undone from local history.
    pub unrecorded: Vec<String>,
    accepted_rewind: bool,
    accepted_lost_enrollments: bool,
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

    /// Record that they separately accepted [`Doomed::lost_enrollments`]. Agreeing to roll a store
    /// back is not agreeing to lose every way into its DEK, so this one is not implied by
    /// [`Doomed::accept_rewind`] and has to be asked for on its own.
    pub fn accept_lost_enrollments(&mut self) {
        self.accepted_lost_enrollments = true;
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
        self.record(Recording::Refuse, None)
    }

    /// Record the loss [`GitStore::missing`] named and the operator confirmed. The consent is
    /// spent here, and covers exactly `accepted`: the staged tree is compared against the one the
    /// operator was shown, and the commit is made out of that same index without staging again, so
    /// a store that lost something else while the question was open is refused rather than
    /// recorded — and one that loses something between the check and the commit records it in the
    /// next mutation, under its own question, instead of inside this answer.
    pub fn commit_loss(self, consent: Consent, accepted: &Missing) -> Result<(), GitErr> {
        self.record(Recording::Confirmed(consent), Some(accepted))
    }

    /// The guard is released before the push, because [`GitStore::push_every`] takes it again for
    /// the vault read and `parking_lot`'s mutex is not re-entrant: pushing under it wedged every
    /// mutation of an install that had a backup remote.
    fn record(self, recording: Recording, accepted: Option<&Missing>) -> Result<(), GitErr> {
        let store = self.store;
        let publish = store.record_mutation(recording, accepted)?;
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
    ///
    /// Hardened before its state is read, because reading it is already a git command: one
    /// unparseable value in `.git/config` makes every git in the repository fatal, including the
    /// `git init` that would clean it, so a store whose config someone else wrote could not be
    /// opened by the very verbs that exist to recover it.
    pub fn cli(config: Arc<Config>, claim: flock::Claim) -> Result<Self, GitErr> {
        {
            let _mutating = claim.mutate();
            harden_repo(&config.store_path())?;
        }
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
        {
            let _mutating = claim.mutate();
            harden_repo(&config.store_path())?;
        }
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
    ///
    /// The store is archived here as well as after each mutation, so an upgrade that only ever
    /// commits what was already on disk still leaves a snapshot, and so the state a mutation is
    /// about to change is archived before it changes rather than only after. A store that has not
    /// changed hashes to a snapshot that already exists and costs one read; nothing is rewritten.
    pub fn open(&self) -> Result<(), GitErr> {
        let store = self.config.store_path();
        let _mutating = self.claim.mutate();
        let head = ensure_repo(&store, None)?;
        let vault = local_vault(&store)?.id().cloned();
        if let Some(vault) = &vault {
            archive_store(&self.config, &store, vault);
        }
        self.status.opened(vault, head);
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
    /// refused is the only store where the answer matters — but still behind `harden_repo`,
    /// because `add -A` in a repository with no exclude rule tracks another writer's in-flight
    /// `*.hctmp` for good, and every later stage, push and pull then fails on it.
    pub fn missing(&self) -> Result<Missing, GitErr> {
        let store = self.config.store_path();
        let _mutating = self.claim.mutate();
        harden_repo(&store)?;
        Ok(stage(&store, &store_vault(&store)?)?)
    }

    /// Put every piece of store state the committed tip still holds and the worktree no longer has
    /// back, out of this machine's own history, without recording anything. The loss is in the
    /// worktree and the state is still in the commit, so a checkout is the whole recovery — and
    /// requiring the loss to be recorded first would mean pushing it to every backup before being
    /// allowed to undo it.
    ///
    /// [`Missing`] has two halves and both wedge every later mutation, so both are recovered here.
    /// A `keyring.json` edited in place to drop an enrollment is a modification, not a removal, so
    /// [`staged_removals`] never names it and walking removals alone left that store wedged with
    /// the recovery reporting success. A `keyring.json` deleted outright is worse still: nothing
    /// downstream can even name the vault, so it is checked back out first and the rest follows.
    pub fn restore_missing(&self) -> Result<Missing, GitErr> {
        let store = self.config.store_path();
        let _mutating = self.claim.mutate();
        harden_repo(&store)?;
        if local_vault(&store)? == LocalVault::Absent
            && committed_vault(&store)? != LocalVault::Absent
        {
            if let Some(head) = rev(&store, "HEAD")? {
                checkout(&store, head, &[KEYRING_FILE.to_string()])?;
                enforce_store_modes(&store)?;
                tracing::warn!(
                    "the store had no keyring.json and this machine's own history did; put it back"
                );
            }
        }
        let vault = store_vault(&store)?;
        let staged = stage(&store, &vault)?;
        let Some(head) = staged.head else {
            return Ok(staged);
        };
        let mut lost = Vec::new();
        for raw in staged_removals(&store, head)? {
            let Ok(path) = std::str::from_utf8(&raw) else {
                continue;
            };
            if store_path_limit(path).is_some() {
                lost.push(path.to_string());
            }
        }

        if !staged.ids.is_empty() && !lost.iter().any(|path| path == KEYRING_FILE) {
            lost.push(KEYRING_FILE.to_string());
        }
        if lost.is_empty() {
            return Ok(staged);
        }
        checkout(&store, head, &lost)?;
        enforce_store_modes(&store)?;
        tracing::warn!(
            files = lost.len(),
            "restored store state out of local history; nothing was recorded and no backup was told"
        );
        Ok(stage(&store, &vault)?)
    }

    /// Put a named snapshot's store files back, adding only what is not already there.
    ///
    /// Add-only in both directions: it never deletes a store file the snapshot does not carry, and
    /// it never replaces one the store already has. A keystore that is present but wrong is
    /// therefore not repaired here — move it aside and run this again — because a restore that
    /// could overwrite would be one more path by which a wrong answer destroys the right one.
    ///
    /// The snapshot has to hash to the name it was asked for, every path it carries has to be one
    /// the store grammar admits, and its vault has to be the vault the store's own keyring names: a
    /// snapshot of another vault is sealed under another DEK, and dropping its keystores in beside
    /// these would leave files nothing on this machine can open.
    ///
    /// Both halves of that vault check are kept, because they refuse different things. The subtree
    /// this reads is this install's own, so a digest that exists only under another vault is not
    /// found at all — structural, and true of a file whose contents were never read. The `vault`
    /// field inside the snapshot is then required to match as well, because a file lands in a
    /// subtree by its name and any same-uid writer can choose a name; that one is what refuses a
    /// snapshot still lying flat in the shared root, which belongs to whichever install wrote it.
    ///
    /// Which vault is this install's comes from [`store_evidence_vault`], not from `keyring.json`
    /// alone. Gating the check on the worktree keyring turned it off on exactly the machine this
    /// verb exists for — one mid-recovery, whose keyring is the file it is trying to get back —
    /// and left a foreign vault's keystores, sealed under a DEK nothing here has, restorable in
    /// beside these.
    pub fn archive_restore(&self, name: &str) -> Result<Restored, GitErr> {
        let store = self.config.store_path();
        let root = self.config.store_archive_path();
        let _mutating = self.claim.mutate();
        let Some(digest) = archive_digest(name) else {
            return Err(GitErr::ArchiveNameIsNotADigest {
                name: hc_core::safe_diagnostic_text(name),
            });
        };
        let (site, mine) = store_evidence_vault(&store);
        let named = format!("{digest}{ARCHIVE_SUFFIX}");
        let missing = || GitErr::ArchiveNotFound {
            digest: digest.to_string(),
            dir: root.clone(),
        };
        let Some(path) = find_archive(&root, mine.id(), &named)? else {
            return Err(missing());
        };
        let file = match hc_core::open_regular_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(missing()),
            Err(error) => return Err(error.into()),
        };
        let bytes = hc_core::read_bounded(file, MAX_ARCHIVE_BYTES)?;
        let found = digest_of(&bytes);
        if found != digest {
            return Err(GitErr::ArchiveDoesNotHashToItsName { path, found });
        }
        let snapshot: Snapshot = hc_core::wire::strict_json_from_slice(&bytes)?;
        if snapshot.v != ARCHIVE_VERSION {
            return Err(GitErr::ArchiveVersionUnsupported {
                found: snapshot.v,
                supported: ARCHIVE_VERSION,
            });
        }
        if mine != LocalVault::Absent {
            require_vault(site, Some(&snapshot.vault), mine.id())?;
        }
        std::fs::create_dir_all(store.join("policies"))?;
        let mut restored = Restored {
            digest: digest.to_string(),
            vault: snapshot.vault,
            written: Vec::new(),
            kept: Vec::new(),
        };
        for archived in snapshot.files {
            let Some(max) = store_path_limit(&archived.path) else {
                return Err(GitErr::ArchiveEntryOutsideTheStoreGrammar { path: archived.path });
            };
            let size = archived.bytes.len() as u64;
            if size > max {
                return Err(GitErr::LocalBlobTooLarge {
                    path: store.join(&archived.path),
                    size,
                    max,
                });
            }
            match atomic_write_new(&store.join(&archived.path), &archived.bytes) {
                Ok(()) => restored.written.push(archived.path),
                Err(EnvErr::StdIo(error))
                    if error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    restored.kept.push(archived.path)
                }
                Err(error) => return Err(error.into()),
            }
        }
        enforce_store_modes(&store)?;
        Ok(restored)
    }

    /// `true` when this session has no background task to replicate for it, so the caller must
    /// push once it has released the mutation guard.
    fn record_mutation(
        &self,
        recording: Recording,
        accepted: Option<&Missing>,
    ) -> Result<bool, GitErr> {
        let store = self.config.store_path();
        let vault = store_vault(&store)?;
        let staged = stage(&store, &vault)?;
        if let Some(accepted) = accepted {
            if &staged != accepted {
                return Err(GitErr::LossPreviewStale { found: staged });
            }
        }
        let committed = commit_staged(&store, &vault, staged, recording)?;
        let Some(head) = committed else {
            return Ok(false);
        };
        archive_store(&self.config, &store, &vault);
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
    ///
    /// Hardened first, like every other path that reaches a remote: a session opens the store once
    /// and then pushes for as long as it runs, so without this a `.git/config` written after that
    /// open re-aims every later transfer for the life of the process.
    pub fn push_every(&self, cfg: &Config) -> Result<(), GitErr> {
        if cfg.backup_remotes.is_empty() {
            return Ok(());
        }
        let store = self.config.store_path();
        {
            let _mutating = self.claim.mutate();
            harden_repo(&store)?;
        }
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
        {
            let _fetch_head = self.fetch_head_guard.lock();
            let _mutating = self.claim.mutate();
            harden_repo(&store)?;
            reclaim_fetch_objects(&store, MAX_FETCH_OBJECT_FILES, MAX_FETCH_OBJECT_BYTES)?;
        }
        let vault = self.vault(&store)?;
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
                        if let Some(guards) = found.guards {
                            r.receive_guards = Some(guards);
                        }
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
        self.status.align(remotes);
        for remote in remotes {
            match ensure_remote(remote, &vault) {
                Ok(guards) => self
                    .status
                    .remote(remote, |r| r.receive_guards = Some(guards)),
                Err(e) => {
                    tracing::warn!(host = %remote.host, error = %e, "could not prepare the backup remote")
                }
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
    /// older history, a fork or a deletion. Adding one is [`Rewind::Widens`] on the same grammar:
    /// a missing policy is deny-by-default, so an added one is an allow this machine did not have.
    /// A machine with no commits yet is the exception — a first restore has no authority to widen
    /// and every path it takes is an addition — and it is the one case that names the incoming
    /// tree's files rather than a diff, so what arrives is still shown before it is agreed to.
    ///
    /// That exception is for a machine that holds nothing, not for one that was made to look like
    /// it. Whether it holds anything is [`unrecorded_store_files`]: the store directory read
    /// against the object database, never the index, the untracked list or a branch ref, because
    /// deleting `.git/refs/heads/main` costs a local writer nothing, destroys no key, and made
    /// every other check here read a store full of keystores as a fresh install. The vault is
    /// required to match the keyring in `HEAD` as well as the one in the worktree for the same
    /// reason: two sources of evidence have to agree before anything applies.
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
        harden_repo(&store)?;
        let mine = local_vault(&store)?;
        if mine != LocalVault::Absent {
            require_vault(VaultSite::LocalStore, Some(vault), mine.id())?;
        }
        let recorded = committed_vault(&store)?;
        if let Some(id) = recorded.id() {
            require_vault(VaultSite::Committed, Some(vault), Some(id))?;
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
        } else if local_head.is_some() && !changed_files.added.is_empty() {
            Some(Rewind::Widens)
        } else if !changed_files.unrecorded.is_empty() {
            Some(Rewind::Unrecorded)
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
            unrecorded: changed_files.unrecorded,
            accepted_rewind: false,
            accepted_lost_enrollments: false,
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
    /// shown that specific loss and took it. Losing every enrollment is gated separately, on
    /// [`Doomed::accept_lost_enrollments`], because it is the one loss that costs the way back
    /// into the DEK and no amount of agreeing to a rollback is agreeing to that. Those unlock
    /// paths are re-read out of the object database here rather than trusted from the preview.
    ///
    /// The last thing before the reset is an [`archive_store`] of what the reset is about to
    /// replace, including the store files no commit records — which are exactly the ones no local
    /// history can put back afterwards.
    pub fn pull_apply(&self, doomed: &Doomed) -> Result<(), GitErr> {
        let store = self.config.store_path();
        let _mutating = self.claim.mutate();
        harden_repo(&store)?;
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
        if !doomed.accepted_lost_enrollments {
            let stranded = stranded_enrollments(&store, doomed.remote_head, GitOp::ForcedPull)?;
            if !stranded.is_empty() {
                return Err(GitErr::PullWouldLoseEveryEnrollment { ids: stranded });
            }
        }
        if !doomed.accepted_rewind {
            if let Some(rewind) = doomed.rewind {
                return Err(GitErr::PullRewindNotAccepted {
                    rewind,
                    local_only: doomed.local_only,
                    remote_only: doomed.remote_only,
                    added: doomed.added.clone(),
                    removed: doomed.removed.clone(),
                    changed: doomed.changed.clone(),
                });
            }
        }
        archive_store(&self.config, &store, &doomed.vault);
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

    /// One remote's validated ancestry as the fetch found it, plus whether that host refuses the
    /// push that would destroy it. Fetch writes only into `.git`; remote state never becomes active
    /// here, including when it is a fast-forward.
    ///
    /// A host that answered the fetch but not the settings read is still a host whose fetch
    /// succeeded, so an unreadable setting is recorded as unknown rather than turned into a fetch
    /// failure that would hide a working backup behind a broken probe.
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
                    guards: None,
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
        let mut found = inspect_fetched(store, remote_head, vault, GitOp::Fetch)?;
        match receive_guards(remote, vault) {
            Ok(guards) => {
                warn_unguarded(remote, guards);
                found.guards = Some(guards);
            }
            Err(error) => tracing::warn!(
                host = %remote.host,
                error = %error,
                "could not read this backup host's receive settings, so whether it refuses a \
                 deletion of the store is unknown"
            ),
        }
        Ok(found)
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
    unrecorded: Vec<String>,
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
///
/// With nothing committed yet there is no diff to take, and taking none named nothing at all while
/// the reset and the clean still replaced the whole directory: every path the incoming tree carries
/// is an addition, so that is what an unborn `HEAD` lists.
fn doomed_paths(
    store: &Path,
    local_head: Option<CommitId>,
    remote_head: CommitId,
) -> Result<Doing, GitErr> {
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    let mut tracked = BTreeSet::new();
    match local_head {
        None => {
            added = nul_paths(&git(
                Some(store),
                GitOp::ForcedPull,
                &[
                    "ls-tree",
                    "-r",
                    "--name-only",
                    "-z",
                    "--full-tree",
                    &remote_head.to_string(),
                ],
            )?);
        }
        Some(local) => {
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
    }
    let others = git(
        Some(store),
        GitOp::ForcedPull,
        &["ls-files", "--others", "--exclude-standard", "-z", "--"],
    )?;
    Ok(Doing {
        added,
        changed,
        removed,
        tracked: tracked.into_iter().collect(),
        untracked: nul_paths(&others),
        unrecorded: unrecorded_store_files(store, local_head)?,
    })
}

/// Store files the store directory holds and this machine's commit does not carry byte for byte.
///
/// This is the whole of "this machine has nothing to lose", and it consumes two things. The
/// filesystem answers what the store holds: a keystore that is on disk is on disk whatever the
/// index, the branch ref or `.git` say about it, and a planted file only adds a confirmation.
/// The object database answers what a commit carries: whichever commit the local ref names, a path
/// it holds at the blob that is on disk is a path this repository can hand back, so a rewritten,
/// deleted or re-created ref moves the answer toward more confirmation and never toward less.
///
/// Neither `git ls-files --others` nor `git status` nor `git diff HEAD` is asked, because all three
/// answer a question about the index, and the index is a file a local writer owns: emptying it,
/// deleting the branch ref under it, or re-initialising the repository around it each made a store
/// still holding keys read as a fresh install.
fn unrecorded_store_files(store: &Path, local_head: Option<CommitId>) -> Result<Vec<String>, GitErr> {
    let held = store_grammar_entries(store)?;
    if held.is_empty() {
        return Ok(Vec::new());
    }
    let carried = match local_head {
        Some(head) => tree_blobs(store, head)?,
        None => BTreeMap::new(),
    };
    let mut unrecorded = Vec::new();
    let mut compare = Vec::new();
    for file in &held {
        match file.regular && carried.contains_key(&file.path) {
            true => compare.push(file),
            false => unrecorded.push(file.path.clone()),
        }
    }
    for (file, on_disk) in compare.iter().zip(disk_blobs(store, &compare)?) {
        if carried.get(&file.path) != Some(&on_disk) {
            unrecorded.push(file.path.clone());
        }
    }
    unrecorded.sort();
    Ok(unrecorded)
}

/// The blob each path carries in one commit's tree. `ls-tree -z` frames a record as
/// `mode SP type SP object TAB path`, so the pathname — the one field a writer chooses — is the
/// tail of the record and can carry anything without displacing a field. Anything that is not a
/// plain blob is skipped: the store grammar has no other entry, and a tree that carries one cannot
/// hand a store file back.
fn tree_blobs(store: &Path, at: CommitId) -> Result<BTreeMap<String, CommitId>, GitErr> {
    let listed = git(
        Some(store),
        GitOp::ForcedPull,
        &["ls-tree", "-r", "-z", "--full-tree", &at.to_string()],
    )?;
    let mut carried = BTreeMap::new();
    for record in listed.split(|byte| *byte == 0).filter(|r| !r.is_empty()) {
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            return Err(GitErr::MalformedRemoteTree);
        };
        let header = std::str::from_utf8(&record[..tab])?;
        let mut terms = header.split_ascii_whitespace();
        let (Some(mode), Some(kind), Some(object), None) =
            (terms.next(), terms.next(), terms.next(), terms.next())
        else {
            return Err(GitErr::MalformedRemoteTree);
        };
        if mode != "100644" || kind != "blob" {
            continue;
        }
        carried.insert(hc_core::safe_diagnostic(&record[tab + 1..]), object.parse()?);
    }
    Ok(carried)
}

/// The blob id each file on disk would have, in the order given. `--no-filters` because a hash
/// taken through a clean filter is not the content, and nothing is written to the object database:
/// this asks what the bytes are, it does not record them. Absolute paths because a git child
/// inherits this process's working directory and resolves a relative one against it.
fn disk_blobs(store: &Path, files: &[&StoreFile]) -> Result<Vec<CommitId>, GitErr> {
    let mut ids = Vec::with_capacity(files.len());
    for batch in files.chunks(HASH_BATCH_FILES) {
        let mut argv = vec!["hash-object", "--no-filters", "--"];
        let named: Vec<String> = batch
            .iter()
            .map(|file| file.on_disk.to_string_lossy().into_owned())
            .collect();
        for path in &named {
            argv.push(path);
        }
        let hashed = git(Some(store), GitOp::ForcedPull, &argv)?;
        let text = String::from_utf8_lossy(&hashed);
        let mut lines = text.lines();
        for _ in batch {
            let Some(line) = lines.next() else {
                return Err(GitErr::MalformedStoreDigests {
                    found: text.lines().count(),
                    files: batch.len(),
                });
            };
            ids.push(line.parse()?);
        }
        if lines.next().is_some() {
            return Err(GitErr::MalformedStoreDigests {
                found: text.lines().count(),
                files: batch.len(),
            });
        }
    }
    Ok(ids)
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
    /// What the host's own `receive.*` settings said; `None` when they could not be read.
    guards: Option<ReceiveGuards>,
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

/// What this machine's own committed history says its vault is, read out of the keyring in `HEAD`.
/// [`local_vault`] reads a cleartext file any same-uid writer can delete; this reads the same field
/// out of the object database, so a check that must not be defeated by removing a non-secret path
/// has a second source to disagree with. `Absent` covers a store that is not a repository, one with
/// nothing committed, and a tip whose tree carries no keyring at all.
pub fn committed_vault(store: &Path) -> Result<LocalVault, GitErr> {
    let git_dir = store.join(GIT_DIR);
    match std::fs::symlink_metadata(&git_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(GitErr::UnsafeGitDirectory { path: git_dir }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LocalVault::Absent)
        }
        Err(error) => return Err(error.into()),
    }
    let Some(head) = rev(store, "HEAD")? else {
        return Ok(LocalVault::Absent);
    };
    let object = format!("{head}:{KEYRING_FILE}");
    if run(Some(store), GitOp::Commit, &["cat-file", "-e", &object])?.code != 0 {
        return Ok(LocalVault::Absent);
    }
    match keyring_at(store, head, GitOp::Commit)?.vault_id {
        Some(v) => Ok(LocalVault::Id(v)),
        None => Ok(LocalVault::Legacy),
    }
}

/// Every keyring this store's own history still holds, newest first, bounded by
/// [`MAX_HISTORY_KEYRINGS`]. A replacing init commits the keyring it is about to overwrite one
/// step before the replacement, so the enrollments only a replaced keyring records — the enclave
/// key an operator is otherwise told to discard — are still readable here. A commit whose tree
/// carries no keyring, or one this version cannot parse, is a commit with no keyring to offer and
/// not a failure.
pub fn keyrings_in_history(store: &Path) -> Result<Vec<(CommitId, Keyring)>, GitErr> {
    let git_dir = store.join(GIT_DIR);
    match std::fs::symlink_metadata(&git_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(GitErr::UnsafeGitDirectory { path: git_dir }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    }
    let Some(head) = rev(store, "HEAD")? else {
        return Ok(Vec::new());
    };
    let bound = MAX_HISTORY_KEYRINGS.to_string();
    let listed = git(
        Some(store),
        GitOp::Commit,
        &["rev-list", "--max-count", &bound, &head.to_string()],
    )?;
    let mut held = Vec::new();
    for line in String::from_utf8_lossy(&listed).lines() {
        let Ok(commit) = parse_id(line.as_bytes(), GitOp::Commit) else {
            continue;
        };
        if let Ok(keyring) = keyring_at(store, commit, GitOp::Commit) {
            held.push((commit, keyring));
        }
    }
    Ok(held)
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

/// The store directory itself. A symlink here would put `git init`, the index and every path below
/// it somewhere `config.toml` never named, so it is refused before anything writes into it.
fn store_dir(store: &Path) -> Result<(), GitErr> {
    match std::fs::symlink_metadata(store)?.file_type().is_dir() {
        true => Ok(()),
        false => Err(GitErr::UnsafeLocalStoreEntry {
            path: store.to_path_buf(),
        }),
    }
}

/// Refuse to stage anything outside the bounded store grammar. This check happens before
/// `git add`, so a misplaced document or an unexpectedly huge file is neither copied into the
/// object database nor sent to a backup. The staged-tree validation in [`commit_staged`] repeats
/// the grammar after `git add`; this filesystem pass is the early, resource-safe half of the pair.
fn validate_local_store_tree(store: &Path) -> Result<(), GitErr> {
    store_dir(store)?;

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
        guards: None,
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

/// Store files the index drops relative to `previous`, exactly as git framed them. `git add -A`
/// stages a deletion as faithfully as an edit, so a keystore removed by a bug, a half-finished
/// write or anyone with local write access would otherwise reach every backup as a clean
/// fast-forward. Left unescaped here because [`GitStore::restore_missing`] hands these back to git
/// as arguments; the escaping belongs at the boundary that displays them.
fn staged_removals(store: &Path, previous: CommitId) -> Step<Vec<Vec<u8>>> {
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
    let mut paths = Vec::new();
    for path in removed.split(|byte| *byte == 0) {
        if !path.is_empty() {
            paths.push(path.to_vec());
        }
    }
    Ok(paths)
}

/// Put committed content back into both the index and the worktree, which is the whole of a
/// recovery that moves no ref, records nothing and tells no backup.
fn checkout(store: &Path, at: CommitId, paths: &[String]) -> Result<(), GitErr> {
    let at = at.to_string();
    let mut argv = vec!["checkout", &at, "--"];
    for path in paths {
        argv.push(path);
    }
    git(Some(store), GitOp::Commit, &argv)?;
    Ok(())
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
        return Ok(Missing {
            paths: Vec::new(),
            ids: Vec::new(),
            tree,
            head: None,
        });
    };
    let committed = keyring_at(store, previous, GitOp::Commit)?;
    let ids = match committed.vault_id.as_ref() == Some(vault) {
        true => dropped_enrollments(&committed, &staged),
        false => Vec::new(),
    };
    let mut paths = Vec::new();
    for path in staged_removals(store, previous)? {
        paths.push(hc_core::safe_diagnostic(&path));
    }
    Ok(Missing {
        paths,
        ids,
        tree,
        head: Some(previous),
    })
}

fn commit(store: &Path, vault: &VaultId, recording: Recording) -> Step<Option<CommitId>> {
    let staged = stage(store, vault)?;
    commit_staged(store, vault, staged, recording)
}

/// Commit the index exactly as `staged` was read out of it. There is deliberately no second
/// `git add` here: a [`Consent`] is spent against one staged tree, and re-deriving the tree after
/// the operator answered would let a same-uid `rm` in the gap land a deletion inside that answer.
///
/// Commit only when something was staged. The staged check is what stops a no-op mutation pushing
/// an empty commit to every remote forever.
///
/// A mutation that deletes a committed store file, or drops one of this vault's enrollments, is
/// refused instead: no subcommand does either, the backup exists to survive exactly that loss, and
/// the only way back to an earlier commit is an operator-driven forced pull. [`Recording::Defer`]
/// neither refuses nor records — `open` takes it so the file history still holds cannot block the
/// pull or the checkout that restores it — and a [`Consent`] the operator minted by typing a
/// [`Destruction`]'s phrase is the one thing that records the loss instead.
///
/// The message is `hot_cheese <vault> <unix secs>` and nothing else: the diff already reveals
/// which files changed, but naming the operation would put a signing history on a remote that
/// has never held one.
fn commit_staged(
    store: &Path,
    vault: &VaultId,
    staged: Missing,
    recording: Recording,
) -> Step<Option<CommitId>> {
    match recording {
        Recording::Confirmed(Consent(destruction)) => tracing::warn!(
            ?destruction,
            files = staged.paths.len(),
            enrollments = staged.ids.len(),
            "recording a destruction of store state the operator confirmed"
        ),
        Recording::Defer => {
            if !staged.is_empty() {
                tracing::warn!(
                    files = staged.paths.len(),
                    enrollments = staged.ids.len(),
                    "store state is gone from this worktree and the commit that would record it is \
                     skipped; history still holds it, so a restore can put it back"
                );
                return Ok(None);
            }
        }
        Recording::Refuse => {
            if !staged.paths.is_empty() {
                return Err(step_failure(
                    GitOp::Commit,
                    GitErr::CommitWouldDeleteStoreFiles {
                        paths: staged.paths,
                    },
                ));
            }
            if !staged.ids.is_empty() {
                return Err(step_failure(
                    GitOp::Commit,
                    GitErr::CommitWouldDropEnrollments { ids: staged.ids },
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

/// Make `<store>` a repository on `main`, with the exclude and the pinned identity everything else
/// depends on. Idempotent, and a precondition of every path that stages, cleans or checks out:
/// `add -A` without the exclude rule tracks another writer's in-flight `*.hctmp` permanently, after
/// which every stage, push and pull fails on it for good, and `clean -ffd` without it deletes one.
///
/// `--template=` is not decoration: an `init.templateDir` in the operator's `~/.gitconfig`
/// would install that directory's hooks here, and a `pre-commit` from it runs inside our commit
/// — arbitrary code in the process holding the store lock, on every mutation. It also leaves no
/// `.git/info` at all, and a clone's default exclude carries no `*.hctmp` rule, which is why
/// both the directory and the rule are written here on every open rather than once at creation.
/// The emptied `info/attributes` is the same surface: repository-local attributes can select
/// arbitrary clean, smudge or diff drivers, and the store format has no attributes to keep. So is
/// `.git/config`, which [`pin_repo_config`] replaces outright: it is the one config channel
/// `--git-dir` cannot be told to ignore.
fn harden_repo(store: &Path) -> Result<(), GitErr> {
    std::fs::create_dir_all(store)?;
    store_dir(store)?;
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
    std::fs::set_permissions(&dot_git, std::fs::Permissions::from_mode(0o700))?;
    let info = dot_git.join("info");
    match std::fs::symlink_metadata(&info) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&info)?;
        }
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(GitErr::UnsafeGitDirectory { path: info }),
        Err(error) => return Err(error.into()),
    }
    std::fs::set_permissions(&info, std::fs::Permissions::from_mode(0o700))?;
    for (name, body) in [("exclude", EXCLUDE.as_bytes()), ("attributes", b"".as_slice())] {
        let path = info.join(name);
        clear_repo_entry(&path)?;
        hc_core::crypto::envelope::atomic_write(&path, body)?;
    }
    pin_repo_config(store)?;
    let on = git(Some(store), GitOp::Commit, &["symbolic-ref", "-q", "HEAD"])?;
    if String::from_utf8_lossy(&on).trim() != HEAD_REF {
        return Err(GitErr::HeadNotOnBranch);
    }
    Ok(())
}

/// Take whatever occupies a repository path out of the way so the write that follows lands on a
/// file this code owns. A directory there defeats the rename an atomic write ends in, a symlink
/// aims that rename's replacement at a path nobody chose, and both are one `mkdir` or one `ln -s`
/// away for anyone who can write into `.git`.
fn clear_repo_entry(path: &Path) -> Result<(), GitErr> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.file_type().is_dir() => Ok(std::fs::remove_dir_all(path)?),
        Ok(_) => Ok(std::fs::remove_file(path)?),
    }
}

/// Replace `.git/config` wholesale instead of auditing it key by key.
///
/// [`scrubbed`] closes the environment and the system and global files, but every store-addressed
/// git runs with `--git-dir <store>/.git`, so the repository's own config is still read, and one
/// line of it owns every transfer: `url.<anything>.insteadOf` rewrites the URL [`GitStore::push_one`]
/// and [`GitStore::pull_preview`] hand to git, while `config.toml`, the status panel and the CLI
/// all still name the host the operator chose. That makes a same-uid writer into the hostile backup
/// host the whole [`Rewind`] design is written against, with no network position at all.
///
/// Auditing for `insteadOf` and `pushInsteadOf` would patch the two that were found. The list of
/// keys that redirect a transport or run a command only grows — `core.sshCommand`,
/// `credential.helper`, `remote.<name>.uploadpack`, `include.path`, `core.hooksPath`,
/// `filter.<n>.clean`, `alias.<n>` — so nothing the file holds is kept: it is deleted, `git init`
/// rewrites the one it no longer finds, and the effective local config is then required to be
/// exactly [`PINNED_CONFIG`]. `git init` only measures [`PROBED_CONFIG`] when it creates a
/// repository, so those two are carried across as booleans rather than guessed back — and a value
/// that no longer reads as one is dropped rather than raised, because refusing here would let one
/// `git config core.ignorecase notabool` wedge the only code that can clean it back out.
fn pin_repo_config(store: &Path) -> Result<(), GitErr> {
    let mut probed = Vec::new();
    for key in PROBED_CONFIG {
        let ran = run(
            Some(store),
            GitOp::Commit,
            &["config", "--local", "--get", "--type=bool", key],
        )?;
        match (ran.code, String::from_utf8_lossy(&ran.stdout).trim()) {
            (0, "true") => probed.push((key, "true")),
            (0, "false") => probed.push((key, "false")),
            _ => {}
        }
    }
    clear_repo_entry(&store.join(GIT_DIR).join("config"))?;
    git(Some(store), GitOp::Commit, &["init", "-q", "--template="])?;
    for (key, value) in probed {
        git(Some(store), GitOp::Commit, &["config", key, value])?;
    }
    for (key, value) in LOCAL_CONFIG {
        git(Some(store), GitOp::Commit, &["config", key, value])?;
    }
    let listed = git(
        Some(store),
        GitOp::Commit,
        &["config", "--local", "--list", "--name-only", "-z"],
    )?;
    for name in listed.split(|byte| *byte == 0).filter(|n| !n.is_empty()) {
        let key = hc_core::safe_diagnostic(name);
        if !PINNED_CONFIG.contains(&key.as_str()) {
            return Err(GitErr::UnsafeRepoConfig { key });
        }
    }
    Ok(())
}

/// Harden the repository and commit whatever is already there, then answer with the tip it left —
/// which is the existing one when nothing was committed, so a caller publishing this as the store's
/// head does not report a store with history as one without. Idempotent; the first run on a
/// pre-existing rsync store makes commit #1 out of everything already there.
///
/// `consent` is `Some` only where the operator has just confirmed destroying the store's key
/// material. Every other caller, including every `open`, passes `None` and gets
/// `Recording::Defer`: a store file that vanished leaves the tip alone rather than failing, so
/// the loss stays out of the backups and the restore paths stay open.
pub fn ensure_repo(store: &Path, consent: Option<Consent>) -> Result<Option<CommitId>, GitErr> {
    harden_repo(store)?;
    validate_local_store_tree(store)?;
    if local_vault(store)? != LocalVault::Absent {
        let recording = match consent {
            Some(consent) => Recording::Confirmed(consent),
            None => Recording::Defer,
        };
        commit(store, &store_vault(store)?, recording)?;
    }
    Ok(rev(store, "HEAD")?)
}

/// Create one vault's bare repository on a backup host, idempotently, and leave it refusing every
/// push that would cost it what it holds.
///
/// [`BARE_REPO_SETTINGS`] is applied on every call rather than only at creation, so a repository an
/// older version of this program left unguarded becomes guarded the next time a push has to create
/// or repair it. The settings are then read back off the host, because a remote whose git accepted
/// the write and did not keep it — a read-only config, a `core.bare` repository someone else owns —
/// would otherwise look protected here while refusing nothing.
fn ensure_remote(remote: &BackupRemote, vault: &VaultId) -> Result<ReceiveGuards, GitErr> {
    let repo = remote_repo(remote, vault);
    let git_dir = format!("--git-dir={repo}");
    ssh(
        remote,
        &["git", "init", "-q", "--bare", "--template=", "--", &repo],
    )?;
    for [verb, name, value] in BARE_REPO_SETTINGS {
        ssh(remote, &["git", &git_dir, verb, name, value])?;
    }
    let guards = receive_guards(remote, vault)?;
    warn_unguarded(remote, guards);
    Ok(guards)
}

/// One backup host's `receive.*` settings, read back off the host itself.
///
/// One extra ssh per fetch pass, deliberately not on the push path: a push runs after every
/// mutation and must not grow a network round trip, while a fetch already costs one and runs on a
/// timer. `config --list` rather than two `--get` calls, because an unset key exits non-zero and an
/// absent setting is the answer this is looking for.
///
/// `-z` is what makes the answer a measurement rather than a suggestion. Line-framed output puts a
/// config value and a config record in the same alphabet, so one value holding a newline printed a
/// second record of its own, and `receive.denyDeletes=true` inside `core.hostile` read back as the
/// one guard on this design a local process cannot switch off.
fn receive_guards(remote: &BackupRemote, vault: &VaultId) -> Result<ReceiveGuards, GitErr> {
    let git_dir = format!("--git-dir={}", remote_repo(remote, vault));
    Ok(parse_receive_guards(&ssh(
        remote,
        &["git", &git_dir, "config", "--list", "-z"],
    )?))
}

/// `--list -z` frames one entry as `key NEWLINE value NUL`, and a value-less entry — which is also
/// true — as `key NUL`. Git lowercases the section and the name it prints, takes `true`, `yes`,
/// `on` and `1` as true, and prints a repeated key once per occurrence, the last of which wins.
fn parse_receive_guards(stdout: &[u8]) -> ReceiveGuards {
    let mut guards = ReceiveGuards {
        deny_deletes: false,
        deny_non_fast_forwards: false,
    };
    for record in stdout.split(|byte| *byte == 0).filter(|r| !r.is_empty()) {
        let entry = String::from_utf8_lossy(record);
        let (key, value) = match entry.split_once('\n') {
            Some((key, value)) => (key, value),
            None => (entry.as_ref(), "true"),
        };
        let set = matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "yes" | "on" | "1"
        );
        if key.eq_ignore_ascii_case(DENY_DELETES) {
            guards.deny_deletes = set;
        }
        if key.eq_ignore_ascii_case(DENY_NON_FAST_FORWARDS) {
            guards.deny_non_fast_forwards = set;
        }
    }
    guards
}

/// Say, every single time it is seen, that a backup host does not refuse the push that would
/// destroy it. Nothing here fails on it: an unguarded backup is still a backup, and refusing to use
/// one would leave an operator with no off-machine copy at all.
fn warn_unguarded(remote: &BackupRemote, guards: ReceiveGuards) {
    if guards.enforced() {
        return;
    }
    tracing::warn!(
        host = %remote.host,
        folder = %remote.folder,
        deny_deletes = guards.deny_deletes,
        deny_non_fast_forwards = guards.deny_non_fast_forwards,
        "THIS BACKUP DOES NOT REFUSE DELETIONS: its repository is missing receive.denyDeletes or \
         receive.denyNonFastForwards, so one push from this machine can delete or rewrite the only \
         off-machine copy of the store, and no setting on this machine can stop it. A `backup push` \
         reapplies both settings when it has to create or repair the repository"
    );
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

/// One snapshot of the store, written whole under the digest of its own serialized bytes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    /// Container version.
    v: u32,
    /// The vault this store belongs to, as its `keyring.json` named it.
    vault: VaultId,
    /// Every store file, ordered by path.
    files: Vec<Archived>,
}

/// One store file inside a snapshot.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Archived {
    /// Store-relative path, e.g. `keyring.json` or `policies/TREASURY.toml`.
    path: String,
    /// The file's exact bytes.
    #[serde(with = "hex::serde")]
    bytes: Vec<u8>,
}

/// One snapshot as a listing found it.
#[derive(Debug)]
pub struct Archive {
    /// The vault whose subtree of the archive root holds it.
    pub vault: VaultId,
    /// The snapshot's content digest, which is also its file name.
    pub digest: String,
    /// Bytes the snapshot file occupies.
    pub bytes: u64,
    /// Unix seconds this snapshot was first written here.
    pub at: u64,
}

/// One walk of the archive root, which every install on the machine shares.
#[derive(Debug)]
pub struct Archives {
    /// The root walked, as `config.toml` named it.
    pub root: PathBuf,
    /// Snapshots a restore on this install would accept, oldest first.
    pub found: Vec<Archive>,
    /// Vault subtrees whose snapshots this listing did not walk.
    pub other_vaults: usize,
    /// Snapshot files still lying directly in the root, written before per-vault subtrees.
    pub flat: usize,
    /// Directory entries this listing counted rather than described, so a root someone filled
    /// shortens the listing instead of refusing it.
    pub skipped: usize,
}

/// What the archive root holds, without opening a snapshot.
struct ArchiveRoot {
    /// One subtree per vault archived here, in the order the filesystem named them.
    vaults: Vec<(VaultId, PathBuf)>,
    /// Snapshot files lying directly in the root, written before per-vault subtrees.
    flat: usize,
    /// Root entries this walk counted rather than described.
    skipped: usize,
}

/// One directory's entries as far as a listing describes them, and how many it did not.
struct Walked {
    found: Vec<(String, PathBuf, std::fs::Metadata)>,
    /// Entries past [`MAX_ARCHIVES`] this walk counted rather than held.
    skipped: usize,
}

/// What a restore did. It is add-only: it creates the store files the snapshot has and the store
/// does not, and never replaces or deletes one.
#[derive(Debug)]
pub struct Restored {
    /// The snapshot restored from.
    pub digest: String,
    /// The vault the snapshot belongs to.
    pub vault: VaultId,
    /// Store files this restore created.
    pub written: Vec<String>,
    /// Store files the snapshot holds and the store already had, left exactly as they were.
    pub kept: Vec<String>,
}

/// Snapshot the store into the configured archive, under a name derived from the snapshot's own
/// bytes so a new snapshot can never land on an older one.
///
/// This returns nothing, and that is the guarantee: a caller cannot propagate an archive failure
/// into the mutation it was archiving even by accident, because there is no error value to
/// propagate. A missing, unwritable, full, foreign-owned or junk-filled archive directory is a
/// warning and the mutation stands — a backup that blocks the thing it backs up is worse than no
/// backup, and four rounds of this design were spent on guards that turned into wedges. Nothing
/// here writes inside the store either, so a half-written snapshot cannot damage what it copied.
fn archive_store(cfg: &Config, store: &Path, vault: &VaultId) {
    let root = cfg.store_archive_path();
    match write_snapshot(&root, store, vault) {
        Ok(digest) => {
            tracing::debug!(archive = %root.display(), %vault, %digest, "archived the store")
        }
        Err(error) => tracing::warn!(
            archive = %root.display(),
            %vault,
            error = %error,
            "the store was not archived; the mutation itself stands and every snapshot already \
             written is untouched"
        ),
    }
}

fn write_snapshot(root: &Path, store: &Path, vault: &VaultId) -> Result<String, GitErr> {
    let snapshot = Snapshot {
        v: ARCHIVE_VERSION,
        vault: vault.clone(),
        files: read_store_files(store)?,
    };
    let bytes = serde_json::to_vec(&snapshot)?;
    let digest = digest_of(&bytes);
    archive_dir(root)?;
    let dir = root.join(vault.to_string());
    archive_dir(&dir)?;
    let path = dir.join(format!("{digest}{ARCHIVE_SUFFIX}"));
    if std::fs::symlink_metadata(&path).is_ok_and(|found| found.file_type().is_file()) {
        return Ok(digest);
    }
    link_new(&path, &bytes)?;
    Ok(digest)
}

/// Every file of the store grammar, sorted by path so the same store always serializes to the same
/// bytes and therefore to the same name. Anything the grammar does not admit — an in-flight
/// `*.hctmp`, `.git`, a stray document — is skipped rather than refused: those are not store state,
/// and a snapshot that failed on one would be a snapshot nobody got.
fn read_store_files(store: &Path) -> Result<Vec<Archived>, GitErr> {
    let mut files = Vec::new();
    let mut total = 0u64;
    for file in store_grammar_entries(store)? {
        if !file.regular {
            return Err(GitErr::UnsafeLocalStoreEntry { path: file.on_disk });
        }
        let bytes = hc_core::read_bounded(hc_core::open_regular_file(&file.on_disk)?, file.max)?;
        total = total.saturating_add(bytes.len() as u64);
        if files.len() >= MAX_STORE_FILES || total > MAX_STORE_BYTES {
            return Err(GitErr::LocalTreeTooLarge {
                files: files.len().saturating_add(1),
                bytes: total,
            });
        }
        files.push(Archived {
            path: file.path,
            bytes,
        });
    }
    Ok(files)
}

/// One store-grammar file the store directory holds.
struct StoreFile {
    /// Store-relative path, e.g. `keyring.json` or `policies/TREASURY.toml`.
    path: String,
    /// Where it lies, absolute because a git child resolves a relative path against its own cwd.
    on_disk: PathBuf,
    /// Whether it is a regular file, judged without following a symlink.
    regular: bool,
    /// The grammar's byte ceiling for this path.
    max: u64,
}

/// What the store directory holds of the store grammar, sorted, judged by reading the directory
/// and nothing else. Every entry the grammar does not admit is walked past rather than refused,
/// because this runs on the archive path after every mutation and on the preview path before every
/// restore, and both must answer for a store an operator has left something in.
fn store_grammar_entries(store: &Path) -> Result<Vec<StoreFile>, GitErr> {
    let mut inspected = 0usize;
    let mut held = Vec::new();
    let mut keep = |path: String, on_disk: PathBuf, kind: std::fs::FileType| {
        if let Some(max) = store_path_limit(&path) {
            held.push(StoreFile {
                path,
                on_disk,
                regular: kind.is_file(),
                max,
            });
        }
    };
    for entry in std::fs::read_dir(store)? {
        bound_entries(inspected)?;
        inspected = inspected.saturating_add(1);
        let entry = entry?;
        let name = hc_core::safe_diagnostic(entry.file_name().as_encoded_bytes());
        if name == GIT_DIR {
            continue;
        }
        let kind = entry.file_type()?;
        if name == "policies" && kind.is_dir() {
            for policy in std::fs::read_dir(entry.path())? {
                bound_entries(inspected)?;
                inspected = inspected.saturating_add(1);
                let policy = policy?;
                let file = hc_core::safe_diagnostic(policy.file_name().as_encoded_bytes());
                let below = policy.file_type()?;
                keep(format!("policies/{file}"), policy.path(), below);
            }
            continue;
        }
        keep(name, entry.path(), kind);
    }
    held.sort_by(|one, other| one.path.cmp(&other.path));
    Ok(held)
}

fn bound_entries(inspected: usize) -> Result<(), GitErr> {
    if inspected < hc_core::MAX_STORE_ENUM_ENTRIES {
        return Ok(());
    }
    Err(GitErr::TooManyLocalStoreEntries {
        found: inspected.saturating_add(1),
        max: hc_core::MAX_STORE_ENUM_ENTRIES,
    })
}

/// The archive root and each vault's subtree of it, both brought to the same bar `read_grant::create`
/// and `socket::bind_socket` hold their own directories to: created if absent, then required —
/// through `symlink_metadata`, which does not follow — to be a real directory this uid owns, so a
/// symlink planted in place of either cannot redirect a snapshot into another vault's subtree or out
/// of the archive entirely, and finally closed to group and other.
fn archive_dir(dir: &Path) -> Result<(), GitErr> {
    std::fs::create_dir_all(dir)?;
    let holding = std::fs::symlink_metadata(dir)?;
    // SAFETY: `geteuid` has no preconditions and changes no process state.
    let ours = unsafe { libc::geteuid() };
    if !holding.file_type().is_dir() || holding.uid() != ours {
        return Err(GitErr::UnsafeArchiveDirectory {
            path: dir.to_path_buf(),
        });
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(ARCHIVE_DIR_MODE))?;
    Ok(())
}

/// Write `bytes` and claim `path` for them, or fail leaving whatever is already at `path` exactly
/// as it was. `link(2)` is what makes that unconditional: it refuses an existing name outright, so
/// there is no window in which a snapshot replaces anything — not an older snapshot, not a file
/// planted under a name someone guessed. The content is complete on disk before the name exists,
/// so a crash leaves a temporary file rather than a truncated snapshot.
///
/// `sync_data` and not `sync_all`: on APFS the latter is `F_FULLFSYNC`, a device write barrier that
/// measures 34ms here against 6.7ms for an ordinary flush, and it would be spent on every mutation.
/// This copy exists to survive an `rm -rf`, not a power cut — the authoritative store file was
/// already written through `atomic_write`, which does take the barrier.
fn link_new(path: &Path, bytes: &[u8]) -> Result<(), GitErr> {
    let dir = path.parent().ok_or_else(|| GitErr::UnsafeArchiveDirectory {
        path: path.to_path_buf(),
    })?;
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    let temp = dir.join(format!("{}{ARCHIVE_TEMP_SUFFIX}", hex::encode(random)));
    let written = (|| -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(ARCHIVE_FILE_MODE)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_data()
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(error.into());
    }
    let linked = std::fs::hard_link(&temp, path);
    let removed = std::fs::remove_file(&temp);
    linked?;
    removed?;
    Ok(())
}

fn digest_of(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// The digest a snapshot's file name carries, or `None` for any other directory entry — which a
/// listing walks past rather than fails on, because the archive is a plain directory an operator
/// reads, copies out of and leaves notes in.
fn archive_digest(name: &str) -> Option<&str> {
    let digest = name.strip_suffix(ARCHIVE_SUFFIX).unwrap_or(name);
    let addressed = digest.len() == 64
        && digest
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    match addressed {
        true => Some(digest),
        false => None,
    }
}

/// The vault a store belongs to, from whichever record of it the store still has: the cleartext
/// keyring first, then the keyring in this machine's own `HEAD`, which a deleted worktree file does
/// not take with it. A record that cannot be read is warned about and skipped rather than raised,
/// because the store this runs against is already damaged and the file it names is the one most
/// likely to be the damage.
fn store_evidence_vault(store: &Path) -> (VaultSite, LocalVault) {
    match local_vault(store) {
        Ok(LocalVault::Absent) => {}
        Ok(found) => return (VaultSite::LocalStore, found),
        Err(error) => tracing::warn!(
            error = %error,
            "this store's cleartext keyring could not be read, so it is not what names its vault"
        ),
    }
    match committed_vault(store) {
        Ok(found) => (VaultSite::Committed, found),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "nor could the keyring in this machine's own history, so nothing names its vault"
            );
            (VaultSite::LocalStore, LocalVault::Absent)
        }
    }
}

/// One named snapshot, looked up rather than listed: this install's own subtree, then the flat
/// layout the version before subtrees wrote, and — only for a store that can name no vault at all —
/// every vault subtree, streamed and never collected.
///
/// The lookup is what keeps the recovery working. The archive root is shared by every install on
/// the machine and anything that can write into it can fill it, so a listing walk on this path
/// meant enough entries in the root turned a restore by exact digest into a refusal: the one thing
/// standing between an operator and a permanently lost owner key, switched off from outside.
fn find_archive(root: &Path, mine: Option<&VaultId>, named: &str) -> Result<Option<PathBuf>, GitErr> {
    let mut probes = Vec::new();
    if let Some(vault) = mine {
        probes.push(root.join(vault.to_string()).join(named));
    }
    probes.push(root.join(named));
    for path in probes {
        if std::fs::symlink_metadata(&path).is_ok_and(|found| found.file_type().is_file()) {
            return Ok(Some(path));
        }
    }
    if mine.is_some() {
        return Ok(None);
    }
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if hc_core::safe_diagnostic(entry.file_name().as_encoded_bytes())
            .parse::<VaultId>()
            .is_err()
        {
            continue;
        }
        let path = entry.path().join(named);
        if std::fs::symlink_metadata(&path).is_ok_and(|found| found.file_type().is_file()) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// One directory's entries, without following a symlink to judge what each one is. An absent
/// directory is no entries: nothing has been archived there yet, which is an answer and not a
/// failure. So is a directory with more entries than one listing describes — [`MAX_ARCHIVES`]
/// bounds what is held in memory and the rest is counted, because refusing to name a single
/// snapshot is the one answer that leaves an operator with nothing.
fn archive_entries(dir: &Path, max: usize) -> Result<Walked, GitErr> {
    let mut walked = Walked {
        found: Vec::new(),
        skipped: 0,
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(walked),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if walked.found.len() >= max {
            walked.skipped = walked.skipped.saturating_add(1);
            continue;
        }
        let name = hc_core::safe_diagnostic(entry.file_name().as_encoded_bytes());
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        walked.found.push((name, path, metadata));
    }
    Ok(walked)
}

/// Split the archive root into the vault subtrees this version writes and the flat snapshot files
/// the version before it wrote. Anything else an operator left there — a note, a copy, a directory
/// that is not a vault id — is walked past, because the archive is a plain directory they read.
fn read_archive_root(root: &Path, max: usize) -> Result<ArchiveRoot, GitErr> {
    let walked = archive_entries(root, max)?;
    let mut held = ArchiveRoot {
        vaults: Vec::new(),
        flat: 0,
        skipped: walked.skipped,
    };
    for (name, path, metadata) in walked.found {
        if metadata.file_type().is_file() {
            if archive_digest(&name).is_some() {
                held.flat = held.flat.saturating_add(1);
            }
            continue;
        }
        if !metadata.file_type().is_dir() {
            continue;
        }
        if let Ok(vault) = name.parse::<VaultId>() {
            held.vaults.push((vault, path));
        }
    }
    Ok(held)
}

/// Every snapshot this install could restore from, oldest first, without opening one.
///
/// That is exactly this vault's subtree while the store's keyring names a vault, and every vault's
/// subtree while it names none — a machine mid-recovery, whose keyring is the thing it is trying to
/// get back, has no vault to filter by and every subtree is a candidate. Another install's
/// snapshots are never listed as this one's either way: each row carries the vault it was found
/// under, and the subtrees this listing walked past are counted rather than shown, so the root is
/// never silently larger than the listing.
///
/// Snapshot files still lying directly in the root are counted the same way and left exactly where
/// they are. Adopting one would mean opening every file in a shared root on a path that runs after
/// every mutation, and the `vault` field inside a flat file is the only evidence of whose it is —
/// so a restore reads that field and refuses a foreign one, and nothing here moves a file whose
/// owner it has not read.
///
/// A keyring this cannot read is the unfiltered case and not a failure. This is the verb an
/// operator reaches for when the store is already damaged, and refusing to name a single snapshot
/// because the file they are trying to get back is unreadable would leave them with nothing.
pub fn archive_list(cfg: &Config) -> Result<Archives, GitErr> {
    let root = cfg.store_archive_path();
    let mine = store_evidence_vault(&cfg.store_path()).1.id().cloned();
    let held = read_archive_root(&root, MAX_ARCHIVES)?;
    let mut listed = Archives {
        root,
        found: Vec::new(),
        other_vaults: 0,
        flat: held.flat,
        skipped: held.skipped,
    };
    for (vault, dir) in held.vaults {
        if mine.as_ref().is_some_and(|mine| *mine != vault) {
            listed.other_vaults = listed.other_vaults.saturating_add(1);
            continue;
        }
        let walked = archive_entries(&dir, MAX_ARCHIVES)?;
        listed.skipped = listed.skipped.saturating_add(walked.skipped);
        for (name, _, metadata) in walked.found {
            let Some(digest) = archive_digest(&name) else {
                continue;
            };
            if !metadata.file_type().is_file() {
                continue;
            }
            listed.found.push(Archive {
                vault: vault.clone(),
                digest: digest.to_string(),
                bytes: metadata.len(),
                at: u64::try_from(metadata.mtime()).unwrap_or(0),
            });
        }
    }
    listed
        .found
        .sort_by(|one, other| (one.at, &one.digest).cmp(&(other.at, &other.digest)));
    Ok(listed)
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
        commit(&store, &vault, Recording::Refuse).expect("the edit commits");
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
        commit(&upstream, &vault, Recording::Refuse).expect("remote change commits");
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
            commit(&store, &vault, Recording::Refuse),
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
            git(Some(&store), GitOp::Commit, &["ls-files"])
                .expect("the index reads")
                .is_empty()
                && rev(&store, "HEAD").expect("head reads").is_none(),
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
            commit(&store, &vault, Recording::Refuse),
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
        commit(&store, &vault, Recording::Refuse).expect("our commit");
        git(
            Some(&store),
            GitOp::Push,
            &["push", "--quiet", &bare, REFSPEC],
        )
        .expect("our push");

        std::fs::write(other.join("OPS"), b"theirs").expect("their edit");
        commit(&other, &vault, Recording::Refuse).expect("their commit");
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

        assert!(commit(&store, &vault, Recording::Refuse)
            .expect("a no-op runs")
            .is_none());
        assert!(commit(&store, &vault, Recording::Refuse)
            .expect("a no-op runs")
            .is_none());
        assert_eq!(
            rev(&store, "HEAD").expect("head reads").expect("born"),
            first,
            "two no-op mutations must not move HEAD"
        );

        std::fs::write(store.join("TREASURY"), b"changed").expect("touch a keystore");
        let second = commit(&store, &vault, Recording::Refuse)
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
        let remote = commit(&store, &vault, Recording::Refuse)
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
            commit(&store, &vault, Recording::Refuse)
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
            "store_archive": dir.join("archive").to_string_lossy(),
            "backup_remotes": remotes.iter().map(|remote| serde_json::json!({
                "host": remote.host,
                "folder": remote.folder,
            })).collect::<Vec<_>>(),
        }))
        .expect("build the fixture config");
        // A sibling test's child that has forked and not yet reached its `exec` still owns a copy
        // of every descriptor this process held, a claim another thread has just dropped included.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let claim = loop {
            match flock::Claim::take(&dir.join("store.lock")) {
                Ok(claim) => break claim,
                Err(error) if std::time::Instant::now() >= deadline => {
                    panic!("claim the fixture store: {error:?}")
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        };
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
        match commit(&store, &vault, Recording::Refuse) {
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
        commit(&store, &vault, Recording::Refuse)
            .expect("enrolling commits")
            .expect("enrolling moves head");

        keyring["enrollments"]
            .as_array_mut()
            .expect("the keyring still has enrollments")
            .pop();
        std::fs::write(&path, serde_json::to_vec(&keyring).expect("serialize")).expect("un-enroll");
        match commit(&store, &vault, Recording::Refuse) {
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
        match commit(&store, &replaced, Recording::Refuse) {
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
        let replacing = commit(&store, &replaced, Recording::Confirmed(consent))
            .expect("a confirmed replacement commits")
            .expect("the replacement moves head");
        assert_ne!(replacing, before);
        assert!(
            commit(&store, &replaced, Recording::Refuse)
                .expect("the store still commits routinely")
                .is_none(),
            "spending the capability must leave an ordinary store behind, not a wedged one"
        );
    }

    /// A store file that disappears — a partial write, a future bug — must not be recordable by
    /// accident: every routine mutation is refused until the operator names the loss and accepts
    /// it. `open` is the exception, because `open` is what `serve`, `generate` and `backup pull`
    /// all run first, and failing it would take the recovery down with the store.
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
            git_store.open().expect("open must survive a lost store file");
            match git_store.after_mutation() {
                Err(GitErr::CommitWouldDeleteStoreFiles { paths }) => {
                    assert_eq!(paths, vec!["TREASURY".to_string()])
                }
                other => panic!("a routine mutation must never record a loss, got {other:?}"),
            }
        }
        assert_eq!(
            rev(&store, HEAD_REF).expect("head reads"),
            Some(before),
            "neither the opens nor the refused mutations may move history"
        );

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
        match commit(&store, &replaced, Recording::Refuse) {
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
    /// leave the DEK with no way back into it, and it has to say so by name — and keep saying so
    /// after the rollback itself is accepted, because agreeing to older content is not agreeing to
    /// lose every way in.
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
        match git_store.pull_apply(&doomed) {
            Err(GitErr::PullWouldLoseEveryEnrollment { ids }) => {
                assert_eq!(ids, vec![FIRST_ENROLLMENT.to_string()])
            }
            other => panic!("the rollback phrase must not waive this one, got {other:?}"),
        }
        assert_eq!(rev(&store, HEAD_REF).expect("head reads"), Some(mine));

        doomed.accept_lost_enrollments();
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

        let mut doomed = git_store
            .pull_preview(&remote, &vault)
            .expect("preview the addition");
        assert_eq!(doomed.added, vec!["OPS".to_string()]);
        doomed.accept_rewind();
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
        let newer = commit(&store, &vault, Recording::Refuse)
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

    /// A keystore that vanished must never block the paths that put it back. `open` is what every
    /// later command runs first, so failing it made the documented answer to a lost file "record
    /// the loss on every backup, then hope" — recovery through replicating the loss.
    #[test]
    fn a_locally_missing_keystore_is_restorable_without_recording_its_loss() {
        let dir = scratch("restore_missing");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let (remote, _bare) = local_remote(&dir, &vault);
        let git_store = cli_store(&dir, &store, vec![remote.clone()]);
        git_store.open().expect("the store becomes a repo");
        git_store
            .push_every(&git_store.config)
            .expect("the backup takes the commit");
        let before = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the store has a head");

        std::fs::remove_file(store.join("TREASURY")).expect("a keystore vanishes");
        git_store.open().expect("open must survive a lost store file");
        assert_eq!(
            rev(&store, HEAD_REF).expect("head reads"),
            Some(before),
            "open must not record the loss it was asked to tolerate"
        );

        let after = git_store
            .restore_missing()
            .expect("local history still holds it");
        assert!(after.is_empty(), "the loss is undone, not recorded");
        assert_eq!(
            std::fs::read(store.join("TREASURY")).expect("the keystore reads"),
            b"keystore-one"
        );
        assert_eq!(mode(&store.join("TREASURY")), 0o600);
        assert_eq!(
            rev(&store, HEAD_REF).expect("head reads"),
            Some(before),
            "recovering out of history must move no ref and tell no backup"
        );

        std::fs::remove_file(store.join("TREASURY")).expect("it vanishes again");
        let doomed = git_store
            .pull_preview(&remote, &vault)
            .expect("the remote restore path is reachable while a file is missing");
        assert!(
            doomed.tracked.iter().any(|path| path == "TREASURY"),
            "the pull must name the file it is about to replace"
        );
        git_store.pull_apply(&doomed).expect("the restore applies");
        assert_eq!(
            std::fs::read(store.join("TREASURY")).expect("the keystore reads"),
            b"keystore-one"
        );
        assert_eq!(rev(&store, HEAD_REF).expect("head reads"), Some(before));
        drop(doomed);
        drop(git_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A [`Consent`] is spent against one staged tree. Re-deriving the tree after the operator
    /// answered let a same-uid `rm` in the gap land a second deletion inside an answer nobody gave,
    /// while the summary still reported the one file that was shown.
    #[test]
    fn the_previewed_loss_set_is_the_committed_one_under_a_concurrent_rm() {
        let dir = scratch("loss_set");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        std::fs::write(store.join("OPS"), b"a second keystore").expect("write a second keystore");
        ensure_repo(&store, None).expect("the store becomes a repo");
        let before = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the store has a head");

        std::fs::remove_file(store.join("TREASURY")).expect("one keystore vanishes");
        let approved = stage(&store, &vault).expect("name what is gone");
        assert_eq!(approved.paths, vec!["TREASURY".to_string()]);

        std::fs::remove_file(store.join("OPS")).expect("a same-uid rm lands in the gap");
        let consent = Consent::confirmed(Destruction::Deletion, Destruction::Deletion.phrase())
            .expect("the exact phrase mints");
        let recorded = commit_staged(&store, &vault, approved, Recording::Confirmed(consent))
            .expect("the approved loss records")
            .expect("it moves head");
        let deleted = git(
            Some(&store),
            GitOp::Commit,
            &[
                "diff",
                "--no-ext-diff",
                "--name-only",
                "--diff-filter=D",
                "-z",
                &before.to_string(),
                &recorded.to_string(),
                "--",
            ],
        )
        .expect("read what the commit recorded");
        assert_eq!(
            nul_paths(&deleted),
            vec!["TREASURY".to_string()],
            "the commit recorded a deletion the operator was never shown"
        );

        match commit(&store, &vault, Recording::Refuse) {
            Err(Failed {
                cause: GitErr::CommitWouldDeleteStoreFiles { paths },
                ..
            }) => assert_eq!(
                paths,
                vec!["OPS".to_string()],
                "the second loss must still need its own question"
            ),
            other => panic!("the spent consent must not cover the next loss, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Additive is not a synonym for safe. A missing policy is deny-by-default, so an incoming tip
    /// that adds one where none existed converts deny into allow with nothing deleted, nothing
    /// replaced and ancestry that checks out — and a keystore a recorded loss retired comes back
    /// the same way, under the same vault and the same DEK.
    #[test]
    fn an_incoming_addition_needs_the_rollback_confirmation_too() {
        let dir = scratch("additive_widening");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let (remote, _bare) = local_remote(&dir, &vault);
        let git_store = cli_store(&dir, &store, vec![remote.clone()]);
        git_store.open().expect("the store becomes a repo");
        let mine = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the store has a head");

        let granted = store.join("policies").join("TREASURY.toml");
        std::fs::write(&granted, b"safe = \"0x0\"\n").expect("the policy this machine never had");
        git(Some(&store), GitOp::Commit, &["add", "-A"]).expect("stage the remote's addition");
        let tree = String::from_utf8_lossy(
            &git(Some(&store), GitOp::Commit, &["write-tree"]).expect("write the remote tree"),
        )
        .trim()
        .to_string();
        let widened = parse_id(
            &git(
                Some(&store),
                GitOp::Commit,
                &["commit-tree", &tree, "-p", &mine.to_string(), "-m", "grant"],
            )
            .expect("build the widening child"),
            GitOp::Commit,
        )
        .expect("the widening child parses");
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
                &format!("{widened}:{HEAD_REF}"),
            ],
        )
        .expect("the hostile host serves the widening child");

        let mut doomed = git_store
            .pull_preview(&remote, &vault)
            .expect("preview the addition");
        assert_eq!(
            doomed.relation,
            Relation::RemoteAhead,
            "the attack is that ancestry is clean; that is what makes it worth catching"
        );
        assert!(doomed.removed.is_empty() && doomed.changed.is_empty());
        assert_eq!(doomed.added, vec!["policies/TREASURY.toml".to_string()]);
        assert_eq!(doomed.rewind, Some(Rewind::Widens));

        match git_store.pull_apply(&doomed) {
            Err(GitErr::PullRewindNotAccepted {
                rewind: Rewind::Widens,
                added,
                ..
            }) => assert_eq!(added, vec!["policies/TREASURY.toml".to_string()]),
            other => panic!("an unaccepted widening must not apply, got {other:?}"),
        }
        assert!(!granted.exists(), "the refusal changed the store");

        doomed.accept_rewind();
        git_store
            .pull_apply(&doomed)
            .expect("an accepted widening applies");
        assert!(
            granted.exists(),
            "this is the state the confirmation exists to make an operator agree to"
        );
        drop(doomed);
        drop(git_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `git init --template=` leaves no `.git/info` at all, so `add -A` in an unhardened repository
    /// tracks another writer's in-flight `*.hctmp` permanently — after which every stage, push and
    /// pull fails on a path nothing can now remove. Naming a loss stages, so it hardens first.
    #[test]
    fn a_destructive_verb_hardens_the_repository_before_it_stages() {
        let dir = scratch("unhardened");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let git_store = cli_store(&dir, &store, Vec::new());
        git_store.open().expect("the store becomes a repo");
        let exclude = store.join(GIT_DIR).join("info").join("exclude");
        std::fs::remove_file(&exclude).expect("an unhardened repository");
        std::fs::write(store.join("TREASURY.hctmp"), b"half written")
            .expect("another writer is mid-write");
        std::fs::remove_file(store.join("TREASURY")).expect("and a keystore vanished");

        let missing = git_store
            .missing()
            .expect("naming a loss must not depend on someone having opened the store first");
        assert_eq!(missing.paths, vec!["TREASURY".to_string()]);
        assert!(exclude.exists(), "the verb ran without hardening the repo");
        let indexed = nul_paths(
            &git(Some(&store), GitOp::Commit, &["ls-files", "-z"]).expect("the index reads"),
        );
        assert!(
            !indexed.iter().any(|path| path.ends_with(".hctmp")),
            "the stage tracked another writer's temporary, which nothing can now untrack: {indexed:?}"
        );
        drop(git_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Hardening runs before every stage, clean and checkout, so anything that can make it fail
    /// wedges all three. An atomic write ends in a rename, which a directory at the target defeats
    /// and a symlink at the target redirects, and both are one command away for whoever could
    /// remove the exclude rule in the first place.
    #[test]
    fn a_hostile_git_directory_cannot_wedge_or_redirect_the_hardening() {
        let dir = scratch("hostile_git_dir");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let git_store = cli_store(&dir, &store, Vec::new());
        git_store.open().expect("the store becomes a repo");
        let info = store.join(GIT_DIR).join("info");

        std::fs::remove_file(info.join("exclude")).expect("clear the exclude rule");
        std::fs::create_dir(info.join("exclude")).expect("a directory where the file belongs");
        std::fs::write(info.join("exclude").join("decoy"), b"decoy").expect("and not an empty one");
        let elsewhere = dir.join("elsewhere");
        std::fs::write(&elsewhere, b"someone else's file").expect("write the symlink's target");
        std::fs::remove_file(info.join("attributes")).expect("clear the attributes");
        std::os::unix::fs::symlink(&elsewhere, info.join("attributes"))
            .expect("aim the next write out of the repository");
        std::fs::set_permissions(&info, std::fs::Permissions::from_mode(0o500))
            .expect("and take away the write bit");

        git_store
            .open()
            .expect("hardening must survive a repository someone else has written into");
        assert_eq!(
            std::fs::read(info.join("exclude")).expect("the exclude rule is a file again"),
            EXCLUDE.as_bytes()
        );
        assert_eq!(
            std::fs::read(&elsewhere).expect("the symlink target still reads"),
            b"someone else's file",
            "the hardening wrote through a symlink out of the repository"
        );
        assert!(git_store
            .missing()
            .expect("the store still answers")
            .is_empty());

        git(
            Some(&store),
            GitOp::Commit,
            &["config", "core.ignorecase", "notabool"],
        )
        .expect("a same-uid writer poisons a value every later git parses");
        assert!(
            run(Some(&store), GitOp::Commit, &["rev-parse", "HEAD"])
                .expect("git still runs")
                .code
                != 0,
            "the fixture must reach the state it is about to recover from"
        );
        drop(git_store);
        let reopened = cli_store(&dir, &store, Vec::new());
        reopened
            .open()
            .expect("hardening must clean out a config it cannot itself read past");
        assert!(reopened
            .missing()
            .expect("the recovered store answers")
            .is_empty());
        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--git-dir` still reads the repository's own config, so a same-uid writer needed one line
    /// of it to become the hostile backup host this whole design is written against: an
    /// `insteadOf` re-aims the URL every transfer is handed while `config.toml`, the status panel
    /// and the CLI all still name the host the operator chose. The property is that the file
    /// cannot carry anything this code did not put there — auditing the two keys that were found
    /// leaves `pushInsteadOf`, `core.sshCommand`, `credential.helper`, `include.path` and every
    /// key git grows next.
    #[test]
    fn a_repository_local_config_cannot_re_aim_a_transfer() {
        let dir = scratch("repo_config");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let (remote, bare) = local_remote(&dir, &vault);
        let git_store = cli_store(&dir, &store, vec![remote.clone()]);
        git_store.open().expect("the store becomes a repo");
        git_store
            .push_every(&git_store.config)
            .expect("the backup takes the first commit");

        let hijack = dir.join("hijack");
        std::fs::create_dir_all(&hijack).expect("make the attacker's folder");
        let stolen = hijack
            .join(format!("{vault}{BARE_SUFFIX}"))
            .to_string_lossy()
            .into_owned();
        git(
            None,
            GitOp::EnsureRemote,
            &["init", "-q", "--bare", "--template=", "--", &stolen],
        )
        .expect("the attacker's repository is created");
        let folder = format!("{}:vaults/", dir.join("remote").to_string_lossy());
        let rewrite = format!("url.{}/.insteadOf", hijack.to_string_lossy());
        for (key, value) in [
            (rewrite.as_str(), folder.as_str()),
            ("core.sshCommand", "/nonexistent/ssh"),
            ("credential.helper", "!/nonexistent/helper"),
            ("core.hooksPath", "/nonexistent/hooks"),
            ("include.path", "/nonexistent/more"),
            ("remote.origin.url", "/nonexistent/repo"),
            ("alias.push", "!/nonexistent/run"),
        ] {
            git(Some(&store), GitOp::Commit, &["config", key, value])
                .expect("a same-uid writer owns .git/config");
        }

        std::fs::write(store.join("TREASURY"), b"rotated").expect("rotate a keystore");
        git_store
            .after_mutation()
            .expect("the rotation commits and publishes");

        let head = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the rotation moved head");
        assert_eq!(
            String::from_utf8_lossy(&bare_head(&bare)).trim(),
            head.to_string(),
            "the push must land on the host config.toml names"
        );
        let taken = run(
            None,
            GitOp::Fetch,
            &[
                &format!("--git-dir={stolen}"),
                "rev-parse",
                "--verify",
                "--quiet",
                HEAD_REF,
            ],
        )
        .expect("the attacker's repository answers");
        assert_ne!(
            taken.code, 0,
            "the repository config re-aimed the transfer at {stolen}"
        );
        let listed = nul_paths(
            &git(
                Some(&store),
                GitOp::Commit,
                &["config", "--local", "--list", "--name-only", "-z"],
            )
            .expect("the repository config reads"),
        );
        for key in &listed {
            assert!(
                PINNED_CONFIG.contains(&key.as_str()),
                "a key this code never wrote survived in .git/config: {key}",
            );
        }
        drop(git_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The safe recovery has to cover every way store state goes missing, because every one of
    /// them wedges the same commit. Walking staged removals alone covered deletions and nothing
    /// else: a `keyring.json` edited in place to drop an enrollment is a modification, and one
    /// removed outright leaves nothing able to name the vault — both stayed wedged while the
    /// recovery reported success and sent the operator to a rewinding remote pull.
    #[test]
    fn the_safe_recovery_covers_every_loss_this_machine_s_own_tip_still_holds() {
        let dir = scratch("restore_halves");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let second = "enr_11111111111111111111111111111111";
        write_keyring(&store, &vault, &[FIRST_ENROLLMENT, second]);
        let git_store = cli_store(&dir, &store, Vec::new());
        git_store.open().expect("the store becomes a repo");
        let before = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("the store has a head");

        let recover = |what: &str| {
            assert_eq!(
                committed_vault(&store).expect("the committed keyring reads"),
                LocalVault::Id(vault.clone()),
                "{what}: the tip's own keyring is the evidence a deleted worktree file cannot erase"
            );
            let restored = git_store
                .restore_missing()
                .unwrap_or_else(|e| panic!("{what} must be recoverable from local history: {e:?}"));
            assert!(
                restored.is_empty(),
                "{what} was reported restored while the store stayed wedged: {restored:?}"
            );
            assert!(
                git_store
                    .missing()
                    .unwrap_or_else(|e| panic!("{what}: {e:?}"))
                    .is_empty(),
                "{what} still wedges the store"
            );
            git_store
                .after_mutation()
                .unwrap_or_else(|e| panic!("{what} still refuses every routine mutation: {e:?}"));
            assert_eq!(
                rev(&store, HEAD_REF).expect("head reads"),
                Some(before),
                "{what}: recovering out of history must move no ref"
            );
        };

        std::fs::remove_file(store.join("TREASURY")).expect("a keystore vanishes");
        recover("a deleted keystore");
        write_keyring(&store, &vault, &[FIRST_ENROLLMENT]);
        recover("an edited keyring");
        std::fs::remove_file(store.join(KEYRING_FILE)).expect("the keyring vanishes");
        recover("a deleted keyring");
        drop(git_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// "Nothing here to lose" has to be read off evidence a local writer cannot manufacture.
    /// `.git` and `keyring.json` are cleartext and non-secret, and removing both left every check
    /// here seeing a fresh install while the keys were still on disk — so a whole remote tree,
    /// including a `policies/<key>.toml` this machine never had, applied on one flag. What a store
    /// still holds is the evidence that survives, and only a store holding nothing may take the
    /// single-confirmation path.
    #[test]
    fn a_store_whose_history_was_removed_is_not_a_fresh_install() {
        let dir = scratch("history_removed");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let (remote, _bare) = local_remote(&dir, &vault);
        let git_store = cli_store(&dir, &store, vec![remote.clone()]);
        git_store.open().expect("the store becomes a repo");
        let granted = store.join("policies").join("TREASURY.toml");
        std::fs::write(&granted, b"safe = \"0x0\"\n").expect("the remote grows a policy");
        git_store
            .after_mutation()
            .expect("the widened store commits and publishes");
        git(
            Some(&store),
            GitOp::ForcedPull,
            &[
                "reset",
                "--hard",
                "--quiet",
                &rev(&store, HEAD_REF)
                    .expect("head reads")
                    .expect("the store has a head")
                    .to_string(),
            ],
        )
        .expect("stay where we are");
        std::fs::remove_file(&granted).expect("this machine does not have the policy");

        std::fs::remove_dir_all(store.join(GIT_DIR)).expect("local history is removed");
        std::fs::remove_file(store.join(KEYRING_FILE)).expect("and the cleartext keyring with it");
        git_store
            .open()
            .expect("the next command opens a store that looks brand new");
        assert_eq!(
            rev(&store, "HEAD").expect("head reads"),
            None,
            "the fixture must reach the state the attack creates: no commit at all"
        );

        let mut doomed = git_store
            .pull_preview(&remote, &vault)
            .expect("the restore path is still reachable");
        assert!(
            doomed.rewind.is_some(),
            "a store that still holds {:?} took the one-confirmation path",
            doomed.unrecorded
        );
        assert_eq!(doomed.rewind, Some(Rewind::Unrecorded));
        assert!(doomed.unrecorded.iter().any(|path| path == "TREASURY"));
        match git_store.pull_apply(&doomed) {
            Err(GitErr::PullRewindNotAccepted { rewind, .. }) => {
                assert_eq!(rewind, Rewind::Unrecorded)
            }
            other => panic!("an unaccepted rollback must not apply, got {other:?}"),
        }
        assert!(!granted.exists(), "the refusal still changed the store");
        doomed.accept_rewind();
        git_store.pull_apply(&doomed).expect("an accepted pull applies");
        assert!(granted.exists());
        drop(doomed);
        drop(git_store);

        let bare = dir.join("empty");
        std::fs::create_dir_all(&bare).expect("make a genuinely fresh install");
        let fresh = cli_store(&bare, &bare.join("store"), vec![remote.clone()]);
        fresh.open().expect("a fresh store opens");
        let first = fresh
            .pull_preview(&remote, &vault)
            .expect("a first restore previews");
        assert_eq!(
            first.rewind, None,
            "a machine that holds nothing must still restore on one confirmation"
        );
        drop(first);
        drop(fresh);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// "This machine has nothing to lose" is the whole of the single-confirmation path, and every
    /// answer to it so far was read off a git surface a local writer owns — the index, the
    /// untracked list, a branch ref — so each round's fix was walked around by erasing a different
    /// one. Every way of making local history look absent is driven here against a store that
    /// still holds an owner key, and none of them may reach that path.
    #[test]
    fn no_erasure_of_local_history_lets_a_store_holding_keys_pull_on_one_confirmation() {
        const OWNER_KEY: &[u8] = b"the second safe owner key";
        type Erase = fn(&Path, CommitId, &str);
        let erasures: [(&str, Erase, bool); 8] = [
            ("the whole repository", |store, _, _| {
                std::fs::remove_dir_all(store.join(GIT_DIR)).expect("remove local history");
            }, false),
            ("the branch ref, leaving the index", |store, _, _| {
                std::fs::remove_file(store.join(GIT_DIR).join("refs").join("heads").join("main"))
                    .expect("remove the branch ref");
                let _ = std::fs::remove_file(store.join(GIT_DIR).join("packed-refs"));
            }, false),
            ("the branch ref through git", |store, _, _| {
                git(Some(store), GitOp::Commit, &["update-ref", "-d", HEAD_REF])
                    .expect("delete the branch ref");
            }, false),
            ("a repository re-initialised around a full index", |store, _, _| {
                std::fs::remove_dir_all(store.join(GIT_DIR)).expect("remove local history");
                git(Some(store), GitOp::Commit, &["init", "-q", "--template="])
                    .expect("re-initialise");
                git(Some(store), GitOp::Commit, &["symbolic-ref", "HEAD", HEAD_REF])
                    .expect("on main");
                git(Some(store), GitOp::Commit, &["add", "-A"]).expect("stage without committing");
            }, false),
            ("the reflog and the ref", |store, _, _| {
                std::fs::remove_dir_all(store.join(GIT_DIR).join("logs"))
                    .expect("truncate the reflog");
                git(Some(store), GitOp::Commit, &["update-ref", "-d", HEAD_REF])
                    .expect("delete the branch ref");
            }, false),
            ("the ref rewound to the tip the backup serves", |store, older, _| {
                git(
                    Some(store),
                    GitOp::Commit,
                    &["update-ref", HEAD_REF, &older.to_string()],
                )
                .expect("rewind the branch ref");
            }, false),
            ("the keystore rewritten with bytes no commit carries", |store, _, url| {
                std::fs::write(store.join("OPS"), b"a key this machine rotated away from")
                    .expect("commit something else at that path");
                git(Some(store), GitOp::Commit, &["add", "-A"]).expect("stage it");
                git(Some(store), GitOp::Commit, &["commit", "-q", "-m", "rotate"])
                    .expect("commit it");
                let head = rev(store, HEAD_REF)
                    .expect("head reads")
                    .expect("the store committed");
                git(
                    Some(store),
                    GitOp::Push,
                    &["push", "--quiet", "--force", url, &format!("{head}:{HEAD_REF}")],
                )
                .expect("the backup serves exactly this machine's own tip");
                std::fs::write(store.join("OPS"), OWNER_KEY).expect("and the disk moves past it");
            }, false),
            ("HEAD moved to a branch that does not exist", |store, _, _| {
                git(
                    Some(store),
                    GitOp::Commit,
                    &["symbolic-ref", "HEAD", "refs/heads/scratch"],
                )
                .expect("move HEAD off main");
            }, true),
        ];

        for (at, (how, erase, refuses)) in erasures.iter().enumerate() {
            let dir = scratch(&format!("erasure_{at}"));
            let vault = VaultId::random();
            let store = store_at(&dir, &vault);
            let (remote, _bare) = local_remote(&dir, &vault);
            let git_store = cli_store(&dir, &store, vec![remote.clone()]);
            git_store.open().expect("the store becomes a repo");
            let older = rev(&store, HEAD_REF)
                .expect("head reads")
                .expect("a populated store commits once");
            let owner = store.join("OPS");
            std::fs::write(&owner, OWNER_KEY).expect("a second owner key");
            git_store.after_mutation().expect("the second key commits");
            let url = url(&remote, &vault);
            git(
                Some(&store),
                GitOp::Push,
                &[
                    "push",
                    "--quiet",
                    "--force",
                    &url,
                    &format!("{older}:{HEAD_REF}"),
                ],
            )
            .expect("the backup host serves the tip from before that key");

            erase(&store, older, &url);
            let held = || std::fs::read(&owner).ok();
            assert_eq!(
                held().as_deref(),
                Some(OWNER_KEY),
                "{how}: the fixture lost the key it protects"
            );

            match (git_store.pull_preview(&remote, &vault), refuses) {
                (Ok(mut doomed), false) => {
                    assert!(
                        doomed.rewind.is_some(),
                        "{how}: a store still holding {:?} took the one-confirmation path",
                        doomed.unrecorded
                    );
                    match git_store.pull_apply(&doomed) {
                        Err(GitErr::PullRewindNotAccepted { .. }) => {}
                        other => panic!("{how}: an unaccepted rollback applied, got {other:?}"),
                    }
                    assert_eq!(
                        held().as_deref(),
                        Some(OWNER_KEY),
                        "{how}: the refusal took the key anyway"
                    );
                    doomed.accept_rewind();
                    doomed.accept_lost_enrollments();
                    git_store
                        .pull_apply(&doomed)
                        .expect("an accepted rollback applies");
                    assert_ne!(
                        held().as_deref(),
                        Some(OWNER_KEY),
                        "{how}: the fixture never reached the loss the confirmation is about"
                    );
                }
                (Err(_), true) => assert_eq!(
                    held().as_deref(),
                    Some(OWNER_KEY),
                    "{how}: the refusal took the key"
                ),
                (found, _) => panic!("{how}: expected refuses={refuses}, got {found:?}"),
            }
            drop(git_store);
            let _ = std::fs::remove_dir_all(&dir);
        }

        let dir = scratch("erasure_nothing_to_lose");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let (remote, _bare) = local_remote(&dir, &vault);
        let git_store = cli_store(&dir, &store, vec![remote.clone()]);
        git_store.open().expect("the store becomes a repo");
        let head = rev(&store, HEAD_REF)
            .expect("head reads")
            .expect("a populated store commits once");
        git(
            Some(&store),
            GitOp::Push,
            &[
                "push",
                "--quiet",
                &url(&remote, &vault),
                &format!("{head}:{HEAD_REF}"),
            ],
        )
        .expect("the backup holds exactly this");
        std::fs::remove_file(store.join(GIT_DIR).join("index")).expect("and the index goes");
        let doomed = git_store
            .pull_preview(&remote, &vault)
            .expect("the preview runs");
        assert_eq!(
            doomed.rewind, None,
            "every file here is already in this machine's own commit, so a measurement that asks \
             for a confirmation is a wedge, not a guard: {:?}",
            doomed.unrecorded
        );
        drop(doomed);
        drop(git_store);
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


    /// A config whose store and archive both live under one scratch directory.
    fn config_at(store: &Path, archive: &Path) -> Arc<Config> {
        let mut config = (*Config::for_test(&store.to_string_lossy())).clone();
        config.store_archive = Some(archive.to_string_lossy().into_owned());
        Arc::new(config)
    }

    /// A snapshot is named after its own bytes, so an unchanged store re-archives to the name it
    /// already has, a changed one takes a new name, and a name already taken — by an older
    /// snapshot or by junk that guessed it — is left exactly as it was found.
    #[test]
    fn a_snapshot_never_lands_on_a_name_that_is_already_taken() {
        let dir = scratch("archive_add_only");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let archive = dir.join("archive");

        let first = write_snapshot(&archive, &store, &vault).expect("the first snapshot lands");
        let mine = archive.join(vault.to_string());
        let path = mine.join(format!("{first}{ARCHIVE_SUFFIX}"));
        let written = std::fs::read(&path).expect("the snapshot reads back");
        assert_eq!(
            digest_of(&written),
            first,
            "a snapshot is named after its own bytes"
        );
        assert_eq!(mode(&path), ARCHIVE_FILE_MODE);
        assert_eq!(mode(&archive), ARCHIVE_DIR_MODE);
        assert_eq!(mode(&mine), ARCHIVE_DIR_MODE);

        let again =
            write_snapshot(&archive, &store, &vault).expect("an unchanged store re-archives");
        assert_eq!(again, first, "the same store is the same name");

        std::fs::write(store.join("TREASURY"), b"keystore-two").expect("change a keystore");
        let second = write_snapshot(&archive, &store, &vault).expect("the changed store archives");
        assert_ne!(second, first, "a changed store takes a name of its own");
        assert_eq!(
            std::fs::read(&path).expect("the first snapshot is still there"),
            written,
            "an older snapshot must survive every later one"
        );

        let planted = mine.join(format!("{}{ARCHIVE_SUFFIX}", "0".repeat(64)));
        std::fs::write(&planted, b"not a snapshot").expect("plant a file under a snapshot name");
        assert!(matches!(
            link_new(&planted, b"replacement"),
            Err(GitErr::StdIo(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(
            std::fs::read(&planted).expect("the planted file is still there"),
            b"not a snapshot",
            "a name this code did not create is not a name it may replace"
        );

        let listed = archive_list(&config_at(&store, &archive)).expect("the archive lists");
        let digests: Vec<&str> = listed.found.iter().map(|f| f.digest.as_str()).collect();
        assert!(digests.contains(&first.as_str()) && digests.contains(&second.as_str()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A backup that can block the thing it backs up is worse than no backup, so an archive that
    /// cannot be written is a warning and the mutation lands anyway. The three ways it fails are
    /// a symlink standing in for the directory, a parent that refuses the directory, and a
    /// directory that is not there at all — which is the one this creates rather than refuses.
    #[test]
    fn a_mutation_lands_even_when_its_archive_cannot_be_written() {
        let dir = scratch("archive_never_blocks");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);

        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("make the directory a symlink can aim at");
        let symlinked = dir.join("symlinked");
        std::os::unix::fs::symlink(&elsewhere, &symlinked).expect("plant the symlink");
        assert!(matches!(
            write_snapshot(&symlinked, &store, &vault),
            Err(GitErr::UnsafeArchiveDirectory { .. })
        ));
        assert!(
            std::fs::read_dir(&elsewhere)
                .expect("the aimed-at directory reads")
                .next()
                .is_none(),
            "a snapshot must not be redirected out of the archive by a planted symlink"
        );

        let sealed = dir.join("sealed");
        std::fs::create_dir_all(&sealed).expect("make the parent that will refuse the archive");
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o500))
            .expect("seal the parent");
        assert!(write_snapshot(&sealed.join("archive"), &store, &vault).is_err());

        let missing = dir.join("missing").join("deeper");
        write_snapshot(&missing, &store, &vault).expect("an absent archive directory is created");

        let claim = flock::Claim::take(&dir.join("claim.lock")).expect("take the store claim");
        let git = GitStore::cli(config_at(&store, &symlinked), claim).expect("open the store");
        git.open().expect("the store becomes a repository");
        let was = rev(&store, "HEAD").expect("head reads");
        std::fs::write(store.join("SECOND"), b"keystore-two").expect("add a keystore");
        git.after_mutation()
            .expect("a mutation lands with an archive it cannot write");
        assert_ne!(
            rev(&store, "HEAD").expect("head reads"),
            was,
            "the mutation the archive could not record was still committed"
        );
        assert_eq!(
            std::fs::read(store.join("SECOND")).expect("the keystore is there"),
            b"keystore-two"
        );
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700))
            .expect("unseal the parent");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A snapshot reproduces the store it was taken of, byte for byte, and adds only: a file the
    /// store still has is left exactly as it is rather than replaced by the archived copy, because
    /// a restore that could overwrite is one more way a wrong answer destroys the right one.
    #[test]
    fn a_restore_reproduces_the_store_and_replaces_nothing() {
        let dir = scratch("archive_restore");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let archive = dir.join("archive");
        let before = read_store_files(&store).expect("the store reads");
        let digest = write_snapshot(&archive, &store, &vault).expect("the snapshot lands");

        std::fs::remove_file(store.join("TREASURY")).expect("lose a keystore");
        std::fs::remove_file(store.join("policies").join("x.toml")).expect("lose a policy");
        let claim = flock::Claim::take(&dir.join("claim.lock")).expect("take the store claim");
        let git = GitStore::cli(config_at(&store, &archive), claim).expect("open the store");
        let restored = git.archive_restore(&digest).expect("the snapshot restores");
        assert_eq!(restored.written, vec!["TREASURY", "policies/x.toml"]);
        assert_eq!(restored.kept, vec![KEYRING_FILE]);
        let after = read_store_files(&store).expect("the store reads again");
        assert_eq!(after.len(), before.len());
        for (was, is) in before.iter().zip(after.iter()) {
            assert_eq!(was.path, is.path);
            assert_eq!(
                was.bytes, is.bytes,
                "{} did not come back byte for byte",
                was.path
            );
        }
        assert_eq!(mode(&store.join("TREASURY")), 0o600);

        std::fs::write(store.join("TREASURY"), b"a newer keystore").expect("move the store on");
        let again = git.archive_restore(&digest).expect("the snapshot restores again");
        assert!(again.written.is_empty());
        assert_eq!(
            std::fs::read(store.join("TREASURY")).expect("the keystore reads"),
            b"a newer keystore",
            "a restore must never replace a store file the store already has"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A snapshot of another vault is sealed under another DEK, so dropping its keystores in
    /// beside these would leave files nothing on this machine can open. A file lands in a subtree
    /// by its name, and any same-uid writer can choose a name, so being found under this vault is
    /// not evidence of being this vault's: the `vault` field inside is read and required too.
    #[test]
    fn a_restore_refuses_a_snapshot_of_another_vault() {
        let dir = scratch("archive_vault");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let archive = dir.join("archive");
        let foreign = VaultId::random();
        let digest = write_snapshot(&archive, &store, &foreign)
            .expect("a snapshot naming another vault lands");
        let named = format!("{digest}{ARCHIVE_SUFFIX}");
        let mine = archive.join(vault.to_string());
        archive_dir(&mine).expect("this vault's subtree");
        std::fs::rename(archive.join(foreign.to_string()).join(&named), mine.join(&named))
            .expect("plant it under this vault's own subtree");
        let claim = flock::Claim::take(&dir.join("claim.lock")).expect("take the store claim");
        let git = GitStore::cli(config_at(&store, &archive), claim).expect("open the store");
        assert!(matches!(
            git.archive_restore(&digest),
            Err(GitErr::VaultMismatch { .. })
        ));
        assert!(matches!(
            git.archive_restore("not-a-digest"),
            Err(GitErr::ArchiveNameIsNotADigest { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The archive root is outside every `HOT_CHEESE_HOME`, so every install on the machine shares
    /// one and nothing prunes it: a throwaway home's snapshots must land in a subtree of their own,
    /// and must be neither listed nor reachable as this install's.
    #[test]
    fn two_installs_sharing_one_archive_root_never_read_each_others_snapshots() {
        let dir = scratch("archive_two_vaults");
        let archive = dir.join("archive");
        let mine = VaultId::random();
        let theirs = VaultId::random();
        let store = store_at(&dir.join("mine"), &mine);
        let other = store_at(&dir.join("theirs"), &theirs);

        let ours = write_snapshot(&archive, &store, &mine).expect("this install's snapshot lands");
        let junk = write_snapshot(&archive, &other, &theirs).expect("the throwaway's snapshot lands");
        assert!(archive
            .join(mine.to_string())
            .join(format!("{ours}{ARCHIVE_SUFFIX}"))
            .is_file());
        assert!(archive
            .join(theirs.to_string())
            .join(format!("{junk}{ARCHIVE_SUFFIX}"))
            .is_file());
        assert!(
            !archive
                .join(mine.to_string())
                .join(format!("{junk}{ARCHIVE_SUFFIX}"))
                .exists(),
            "a snapshot of one vault must never land in another vault's subtree"
        );

        let listed = archive_list(&config_at(&store, &archive)).expect("the archive lists");
        assert_eq!(listed.found.len(), 1);
        assert_eq!(listed.found[0].digest, ours);
        assert_eq!(listed.found[0].vault, mine);
        assert_eq!(listed.other_vaults, 1, "the other subtree is counted, not shown");
        assert_eq!(listed.flat, 0);

        let claim = flock::Claim::take(&dir.join("claim.lock")).expect("take the store claim");
        let git = GitStore::cli(config_at(&store, &archive), claim).expect("open the store");
        assert!(
            matches!(git.archive_restore(&junk), Err(GitErr::ArchiveNotFound { .. })),
            "another install's snapshot is not found, not merely refused after being read"
        );
        git.archive_restore(&ours).expect("this vault's snapshot restores");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A symlink standing in for a vault's subtree would aim a snapshot into another vault's
    /// subtree, or out of the archive entirely, and the root being sound says nothing about it.
    #[test]
    fn a_symlink_where_a_vault_subtree_belongs_refuses_the_snapshot() {
        let dir = scratch("archive_vault_symlink");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let archive = dir.join("archive");
        let elsewhere = dir.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("make the directory the symlink aims at");
        archive_dir(&archive).expect("the root is sound");
        std::os::unix::fs::symlink(&elsewhere, archive.join(vault.to_string()))
            .expect("plant the symlink where the subtree belongs");

        assert!(matches!(
            write_snapshot(&archive, &store, &vault),
            Err(GitErr::UnsafeArchiveDirectory { .. })
        ));
        assert!(
            std::fs::read_dir(&elsewhere)
                .expect("the aimed-at directory reads")
                .next()
                .is_none(),
            "a snapshot must not be redirected out of its own subtree by a planted symlink"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A root written before it held per-vault subtrees keeps its flat snapshots exactly where they
    /// are: whose they are is only in the `vault` field inside, so a restore reads that and refuses
    /// a foreign one, and nothing moves a file whose owner it has not read.
    #[test]
    fn a_flat_snapshot_is_reported_where_it_lies_and_restores_only_into_its_own_vault() {
        let dir = scratch("archive_flat");
        let archive = dir.join("archive");
        let mine = VaultId::random();
        let theirs = VaultId::random();
        let store = store_at(&dir.join("mine"), &mine);
        let other = store_at(&dir.join("theirs"), &theirs);

        let digest = write_snapshot(&archive, &store, &mine).expect("the snapshot lands");
        let named = format!("{digest}{ARCHIVE_SUFFIX}");
        let flat = archive.join(&named);
        std::fs::rename(archive.join(mine.to_string()).join(&named), &flat)
            .expect("put the snapshot back where the flat layout kept it");
        std::fs::remove_dir_all(archive.join(mine.to_string())).expect("drop the subtree");

        let listed = archive_list(&config_at(&store, &archive)).expect("the archive lists");
        assert!(
            listed.found.is_empty(),
            "a flat file's vault is unread, so it is never listed as this install's"
        );
        assert_eq!(listed.flat, 1, "and it is reported rather than left invisible");

        std::fs::remove_file(store.join("TREASURY")).expect("lose a keystore");
        let claim = flock::Claim::take(&dir.join("mine.lock")).expect("take the store claim");
        let git = GitStore::cli(config_at(&store, &archive), claim).expect("open the store");
        let restored = git.archive_restore(&digest).expect("its own vault restores it");
        assert_eq!(restored.written, vec!["TREASURY"]);
        assert!(flat.is_file(), "a restore reads a flat snapshot and never moves it");

        let claim = flock::Claim::take(&dir.join("theirs.lock")).expect("take the other claim");
        let git = GitStore::cli(config_at(&other, &archive), claim).expect("open the other store");
        assert!(matches!(
            git.archive_restore(&digest),
            Err(GitErr::VaultMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A snapshot of another vault is sealed under a DEK nothing here has, and the refusal that says
    /// so was gated on the store having a `keyring.json` — so it was inert on exactly the machine
    /// this verb exists for, one whose keyring is the file it is trying to get back. The keyring in
    /// this machine's own history is the second record of the same fact and it survives the first.
    #[test]
    fn a_restore_refuses_a_foreign_vault_with_the_worktree_keyring_gone() {
        let dir = scratch("archive_midrecovery");
        let archive = dir.join("archive");
        let mine = VaultId::random();
        let theirs = VaultId::random();
        let store = store_at(&dir.join("mine"), &mine);
        let other = store_at(&dir.join("theirs"), &theirs);
        let ours = write_snapshot(&archive, &store, &mine).expect("this install's snapshot lands");
        let junk = write_snapshot(&archive, &other, &theirs).expect("another install's lands");
        ensure_repo(&store, None).expect("the store becomes a repo");

        std::fs::remove_file(store.join(KEYRING_FILE)).expect("mid-recovery: the keyring is gone");
        std::fs::remove_file(store.join("TREASURY")).expect("and a keystore with it");
        std::fs::rename(
            archive
                .join(theirs.to_string())
                .join(format!("{junk}{ARCHIVE_SUFFIX}")),
            archive
                .join(mine.to_string())
                .join(format!("{junk}{ARCHIVE_SUFFIX}")),
        )
        .expect("plant the foreign snapshot under this vault's own subtree");

        let claim = flock::Claim::take(&dir.join("claim.lock")).expect("take the store claim");
        let git = GitStore::cli(config_at(&store, &archive), claim).expect("open the store");
        assert!(
            matches!(git.archive_restore(&junk), Err(GitErr::VaultMismatch { .. })),
            "a foreign vault's keystores were restorable into a store that still names its own"
        );
        let restored = git.archive_restore(&ours).expect("its own snapshot restores");
        assert_eq!(restored.vault, mine);
        assert_eq!(restored.written, vec!["TREASURY", KEYRING_FILE]);
        drop(git);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The archive root is shared by every install on the machine, so anything that can write into
    /// it can fill it and anything that owns it can close it — and a lookup that listed the root
    /// first let either turn a restore by exact digest, the last thing between an operator and a
    /// permanently lost owner key, into a refusal. A named snapshot is opened by name, and a walk
    /// that cannot describe everything it finds shortens its listing instead of refusing one.
    #[test]
    fn a_named_snapshot_restores_out_of_a_root_no_listing_can_read() {
        let dir = scratch("archive_unlistable_root");
        let archive = dir.join("archive");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let digest = write_snapshot(&archive, &store, &vault).expect("the snapshot lands");
        std::fs::remove_file(store.join("TREASURY")).expect("lose a keystore");
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o300))
            .expect("close the shared root to listing while leaving it traversable");

        let claim = flock::Claim::take(&dir.join("claim.lock")).expect("take the store claim");
        let git = GitStore::cli(config_at(&store, &archive), claim).expect("open the store");
        let restored = git
            .archive_restore(&digest)
            .expect("a named digest must not be reachable only by walking the whole root");
        assert_eq!(restored.written, vec!["TREASURY"]);
        drop(git);

        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o700))
            .expect("open it again");
        for at in 0..4 {
            std::fs::write(archive.join(format!("filler_{at}")), b"").expect("fill the root");
        }
        let held = read_archive_root(&archive, 2).expect("a filled root is walked, not refused");
        assert_eq!(held.skipped, 3);
        let walked = archive_entries(&archive.join(vault.to_string()), 0)
            .expect("nor is a filled vault subtree");
        assert!(walked.found.is_empty() && walked.skipped > 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The two `receive.deny*` settings are the one guard on losing ciphertext that a same-uid
    /// process on this machine cannot switch off, because the receiving git enforces them. A bare
    /// repository this code set up really does refuse the deletion; one created before these
    /// settings existed refuses nothing, and reads back as refusing nothing.
    #[test]
    fn a_backup_repository_refuses_deletions_and_an_unguarded_one_reads_back_as_unguarded() {
        let dir = scratch("receive_guards");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        ensure_repo(&store, None).expect("the store becomes a repo");
        let bare = bare_at(&dir, &vault);
        let git_dir = format!("--git-dir={bare}");
        let listed = |git_dir: &str| {
            git(
                None,
                GitOp::EnsureRemote,
                &[git_dir, "config", "--list", "-z"],
            )
            .expect("the bare repository lists its config")
        };

        assert_eq!(
            parse_receive_guards(&listed(&git_dir)),
            ReceiveGuards {
                deny_deletes: false,
                deny_non_fast_forwards: false,
            },
            "a repository created before these settings existed refuses nothing"
        );

        git(
            None,
            GitOp::EnsureRemote,
            &[
                &git_dir,
                "config",
                "backup.note",
                "harmless\nreceive.denyDeletes=true\nreceive.denyNonFastForwards=true",
            ],
        )
        .expect("a config value carrying newlines is set");
        assert_eq!(
            parse_receive_guards(&listed(&git_dir)),
            ReceiveGuards {
                deny_deletes: false,
                deny_non_fast_forwards: false,
            },
            "one config value forged the settings that decide whether this backup is protected"
        );

        for [verb, name, value] in BARE_REPO_SETTINGS {
            git(
                None,
                GitOp::EnsureRemote,
                &[&git_dir, verb, name, value],
            )
            .expect("the bare repository takes the settings");
        }
        assert!(
            parse_receive_guards(&listed(&git_dir)).enforced(),
            "the settings this code applies must read back as both guards on"
        );

        git(
            Some(&store),
            GitOp::Push,
            &["push", "--quiet", &bare, REFSPEC],
        )
        .expect("the first push creates main");
        let head = bare_head(&bare);
        let deleted = run(
            Some(&store),
            GitOp::Push,
            &["push", "--quiet", &bare, &format!(":{HEAD_REF}")],
        )
        .expect("the deleting push runs");
        assert_ne!(
            deleted.code, 0,
            "a backup that accepts a deletion of the store is not a backup"
        );
        assert_eq!(
            bare_head(&bare),
            head,
            "the refused deletion left the branch where it was"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `git config --list -z` frames an entry as `key NEWLINE value NUL` and a value-less one as a
    /// bare key, lowercases what it prints and takes four spellings of true — and a value is the
    /// one field whoever set it chose, so no arrangement of bytes inside one may become a second
    /// entry of its own.
    #[test]
    fn receive_settings_are_read_the_way_git_prints_them() {
        assert_eq!(
            parse_receive_guards(
                b"core.hostile\nx\nreceive.denydeletes=true\nreceive.denynonfastforwards=true\0"
            ),
            ReceiveGuards {
                deny_deletes: false,
                deny_non_fast_forwards: false,
            },
            "a value became the entries that decide whether a backup refuses its own deletion"
        );
        assert_eq!(
            parse_receive_guards(b"receive.denydeletes\ntrue\nreceive.denynonfastforwards\ntrue\0"),
            ReceiveGuards {
                deny_deletes: false,
                deny_non_fast_forwards: false,
            },
            "everything after the first newline is one value, however many newlines it holds"
        );
        assert!(parse_receive_guards(
            b"core.bare\ntrue\0receive.denydeletes\n1\0receive.denynonfastforwards\0"
        )
        .enforced());
        assert!(parse_receive_guards(
            b"receive.denyDeletes\nYES\0receive.denyNonFastForwards\nOn\0"
        )
        .enforced());
        assert!(!parse_receive_guards(
            b"receive.denydeletes\ntrue\0receive.denynonfastforwards\nfalse\0"
        )
        .enforced());
        assert!(!parse_receive_guards(
            b"receive.denydeletes\ntrue\0receive.denydeletes\nfalse\0receive.denynonfastforwards\ntrue\0"
        )
        .enforced());
    }

    /// A snapshot must cost the store it copies and not the archive it lands in: an archive fills
    /// up over months, and a snapshot that read it would make every mutation slower than the last
    /// one. The flush that follows is a fixed cost, measured once and recorded on [`link_new`], and
    /// is deliberately outside this: a busy disk must not be able to fail a correctness test.
    #[test]
    fn a_snapshot_costs_the_store_and_not_the_archive() {
        let dir = scratch("archive_cost");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        for at in 0..8 {
            std::fs::write(store.join(format!("KEY_{at}")), vec![b'k'; 2048])
                .expect("write a keystore");
            std::fs::write(
                store.join("policies").join(format!("KEY_{at}.toml")),
                vec![b'p'; 512],
            )
            .expect("write a policy");
        }
        let archive = dir.join("archive");
        let piled = 200;
        for at in 0..piled {
            std::fs::write(store.join("TREASURY"), format!("keystore-{at}"))
                .expect("change a keystore");
            write_snapshot(&archive, &store, &vault).expect("the snapshot lands");
        }
        assert_eq!(
            archive_list(&config_at(&store, &archive))
                .expect("the archive lists")
                .found
                .len(),
            piled,
            "every changed store took a name of its own and none replaced another"
        );

        let rounds = 50u32;
        let started = std::time::Instant::now();
        for _ in 0..rounds {
            let files = read_store_files(&store).expect("the store reads");
            let snapshot = Snapshot {
                v: ARCHIVE_VERSION,
                vault: vault.clone(),
                files,
            };
            digest_of(&serde_json::to_vec(&snapshot).expect("the snapshot serializes"));
        }
        let each = started.elapsed() / rounds;
        assert!(
            each < Duration::from_millis(5),
            "naming a snapshot of a nine-key store, with {piled} already archived, took {each:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
