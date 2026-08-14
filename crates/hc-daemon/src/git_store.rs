//! The store as a git repository: every mutation auto-commits, a backup is a push, the
//! freshness probe is a fetch, and a merge is applied only when it is a fast-forward.
//!
//! Divergence is a surfaced state, never a silent overwrite: the background task can move the
//! worktree forward but never past a fork, and only an explicit operator action — which names
//! the keystores it will destroy first — can discard local history.
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
use hc_core::crypto::envelope::{enforce_store_modes, GIT_DIR};
use hc_core::keyring::{Keyring, KeyringErr, VaultId, KEYRING_FILE};
use hc_sign::grant::{now_secs, GrantErr};
use parking_lot::Mutex;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::watch;

/// The one branch this design has. Both ends of every transfer name it explicitly, so no `HEAD`
/// on either side has to be guessed at.
const BRANCH: &str = "main";

/// What `symbolic-ref HEAD` must answer, and half of every refspec.
const HEAD_REF: &str = "refs/heads/main";

/// Pushed and fetched explicitly, because this repository has no named remotes: `config.toml`
/// is the single source of truth for where a backup goes, and a `.git/config` remote list would
/// be a second copy of it that could drift.
const REFSPEC: &str = "refs/heads/main:refs/heads/main";

/// Suffix of a vault's bare repository on a backup host. Deliberately not [`GIT_DIR`]: that one
/// is a working tree's own directory, and the two only look alike.
const BARE_SUFFIX: &str = ".git";

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

/// Git plumbing variables removed from every child. `GIT_DIR` is the sharp one — it overrides
/// `-C <store>` outright — and the rest can redirect the index, the object store or the ref
/// namespace just as completely.
const SCRUBBED: [&str; 8] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES",
];

/// Seconds ssh waits for a backup host's TCP connect.
const CONNECT_TIMEOUT_SECS: u64 = 5;

/// A host that accepts and then stalls is bounded by these instead: `ConnectTimeout` covers only
/// the connect, and a background task must not hang on a half-dead session forever.
const ALIVE_INTERVAL_SECS: u64 = 5;
const ALIVE_COUNT_MAX: u64 = 3;

create_err_with_impls!(
    #[derive(Debug)]
    pub GitErr,
    NoBackupRemote,
    HeadNotOnBranch,
    FetchTaskGone,
    StdIo(std::io::Error),
    Keyring(KeyringErr),
    Grant(GrantErr),
    Hex(hex::FromHexError),
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
    NoVaultOnRemote { host: String },
    StoreNotEmpty { store: PathBuf, entries: Vec<String> },
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
                value: s.to_string(),
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
    /// The remote has commits local does not; a fast-forward is due.
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
    Merge,
    Push,
    Clone,
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
    /// What the last completed fetch found, as it found it, before any merge.
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
    /// Unix seconds this process last moved local `HEAD` — a commit, a fast-forward, or a
    /// forced pull.
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
        let head = match store.join(GIT_DIR).exists() {
            true => head(&store)?,
            false => None,
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

/// What a forced pull is about to destroy, so a confirmation can name it rather than say
/// "discards local history".
#[derive(Debug)]
pub struct Doomed {
    /// The commit the worktree will be reset to. Pinned here rather than re-read from
    /// `FETCH_HEAD` at apply time, so a background fetch between the question and the answer
    /// cannot change what the operator agreed to.
    pub remote_head: CommitId,
    /// Committed-here-only files the reset deletes — every one of them a keystore this machine
    /// generated and never pushed.
    pub tracked: Vec<String>,
    /// Untracked, non-excluded files `clean -fd` deletes.
    pub untracked: Vec<String>,
}

/// One session's git store: the claim it serialises on, the state it publishes, and how its
/// pushes get done.
pub struct GitStore {
    config: Arc<Config>,
    /// Held for the whole session. `flock(2)` excludes other processes; the mutex inside it
    /// excludes this process's own threads. Both are required and neither substitutes.
    claim: flock::Claim,
    status: GitStatus,
    background: Background,
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

    /// Bring the repository into the shape everything below assumes, and record what it found.
    /// Idempotent; the first run on a pre-existing rsync store makes commit #1 out of
    /// everything already there.
    pub fn open(&self) -> Result<(), GitErr> {
        let store = self.config.store_path();
        let _mutating = self.claim.mutate();
        let head = ensure_repo(&store)?;
        self.status.opened(local_vault(&store)?.id().cloned(), head);
        Ok(())
    }

    /// Record the mutation, then replicate it. The commit is the caller's problem when it
    /// fails; the push is not, because a store that really was written must not be reported as
    /// a failure because a remote was asleep.
    pub fn after_mutation(&self) -> Result<(), GitErr> {
        let store = self.config.store_path();
        let committed = {
            let _mutating = self.claim.mutate();
            let vault = store_vault(&store)?;
            commit(&store, &vault)?
        };
        let Some(head) = committed else {
            return Ok(());
        };
        self.status.moved(Some(head), now_secs()?);
        match &self.background {
            Background::None => {
                if let Err(e) = self.push_every(&self.config) {
                    tracing::warn!(error = %e, "the backup push after a store mutation failed");
                }
            }
            Background::Task { push, .. } => push.send_modify(|n| *n += 1),
        }
        Ok(())
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
        if head(&store)?.is_none() {
            return Ok(());
        }
        self.status.align(&cfg.backup_remotes);
        let mut failures = Vec::new();
        for remote in &cfg.backup_remotes {
            match self.push_one(&store, remote, &vault) {
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

    /// Fetch every remote and fast-forward where that is what the ancestry says. A fork is
    /// recorded and left alone: nothing merged, nothing pushed, nothing deleted.
    pub fn fetch_every(&self, cfg: &Config) -> Result<(), GitErr> {
        if cfg.backup_remotes.is_empty() {
            return Ok(());
        }
        let store = self.config.store_path();
        let vault = self.vault(&store)?;
        self.status.align(&cfg.backup_remotes);
        let mut failures = Vec::new();
        for remote in &cfg.backup_remotes {
            match self.fetch_one(&store, remote, &vault) {
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

    /// Fetch, and say what a forced pull would destroy. Nothing is written: the remote keyring
    /// is read out of the object database, so a wrong-vault remote is refused before the
    /// worktree has been touched at all.
    pub fn pull_preview(&self, remote: &BackupRemote, vault: &VaultId) -> Result<Doomed, GitErr> {
        let store = self.config.store_path();
        let url = url(remote, vault);
        let _mutating = self.claim.mutate();
        let mine = local_vault(&store)?;
        if mine != LocalVault::Absent {
            require_vault(VaultSite::LocalStore, Some(vault), mine.id())?;
        }
        git(
            Some(&store),
            GitOp::ForcedPull,
            &["fetch", "--quiet", &url, HEAD_REF],
        )?;
        let remote_head = fetch_head(&store)?;
        let blob = git(
            Some(&store),
            GitOp::ForcedPull,
            &["show", &format!("{remote_head}:{KEYRING_FILE}")],
        )?;
        let theirs: Keyring = serde_json::from_slice(&blob)?;
        require_vault(VaultSite::Pulled, Some(vault), theirs.vault_id.as_ref())?;
        let tracked = match head(&store)? {
            None => Vec::new(),
            Some(local) => lines(&git(
                Some(&store),
                GitOp::ForcedPull,
                &[
                    "diff",
                    "--name-only",
                    "--diff-filter=D",
                    &local.to_string(),
                    &remote_head.to_string(),
                ],
            )?),
        };
        let untracked = lines(&git(
            Some(&store),
            GitOp::ForcedPull,
            &["ls-files", "--others", "--exclude-standard"],
        )?);
        Ok(Doomed {
            remote_head,
            tracked,
            untracked,
        })
    }

    /// Discard local history and take the remote's, then re-tighten every mode the checkout
    /// recreated at the umask. The one operation here that can destroy key material.
    pub fn pull_apply(&self, doomed: &Doomed) -> Result<(), GitErr> {
        let store = self.config.store_path();
        let _mutating = self.claim.mutate();
        let target = doomed.remote_head.to_string();
        git(
            Some(&store),
            GitOp::ForcedPull,
            &["reset", "--hard", "--quiet", &target],
        )?;
        git(Some(&store), GitOp::ForcedPull, &["clean", "-fdq"])?;
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
    fn push_one(&self, store: &Path, remote: &BackupRemote, vault: &VaultId) -> Step<()> {
        let url = url(remote, vault);
        let argv = ["push", "--quiet", &url, REFSPEC];
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

    /// One remote's ancestry as the fetch found it, and the fast-forward when that is what it
    /// says. The fetch writes only into `.git` and holds no lock; the merge rewrites the
    /// worktree and holds one.
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
            &["fetch", "--quiet", &url, HEAD_REF],
        )?;
        let remote_head = fetch_head(store)?;
        let local = head(store)?;
        let relation = match local {
            None => Relation::RemoteAhead,
            Some(local) if local == remote_head => Relation::InSync,
            Some(local) => ancestry(store, local, remote_head)?,
        };
        if relation == Relation::RemoteAhead {
            let _mutating = self.claim.mutate();
            git(
                Some(store),
                GitOp::Merge,
                &["merge", "--ff-only", "--quiet", &remote_head.to_string()],
            )?;
            enforce_store_modes(store).map_err(|e| Failed {
                op: GitOp::Merge,
                cause: e.into(),
                stderr: String::new(),
            })?;
            let at = now_secs().map_err(|cause| Failed {
                op: GitOp::Merge,
                cause: cause.into(),
                stderr: String::new(),
            })?;
            self.status.moved(Some(remote_head), at);
        }
        Ok(Found {
            relation,
            local,
            remote: Some(remote_head),
        })
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

/// What one completed fetch learned, before the fast-forward it may then have applied.
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

/// One finished git child: what it printed and how it left.
struct Ran {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

/// The one `Command` constructor here. `store` is `Some` for anything addressing the store's
/// repository and `None` for a clone or a bare URL probe, which have no repository to be inside
/// yet.
fn scrubbed(store: Option<&Path>) -> Command {
    let mut cmd = Command::new("git");
    for name in SCRUBBED {
        cmd.env_remove(name);
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .env(
            "GIT_SSH_COMMAND",
            format!(
                "ssh -o BatchMode=yes -o ConnectTimeout={CONNECT_TIMEOUT_SECS} \
                 -o ServerAliveInterval={ALIVE_INTERVAL_SECS} \
                 -o ServerAliveCountMax={ALIVE_COUNT_MAX}"
            ),
        )
        .stdin(Stdio::null());
    if let Some(store) = store {
        cmd.arg("-C").arg(store);
    }
    cmd.arg("-c")
        .arg("commit.gpgsign=false")
        .arg("-c")
        .arg("core.hooksPath=/dev/null");
    cmd
}

fn owned(argv: &[&str]) -> Vec<String> {
    argv.iter().map(|a| (*a).to_string()).collect()
}

/// Non-empty trimmed lines of a child's stdout.
fn lines(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Run one git and hand back its exit code, for the commands whose non-zero exits are answers
/// rather than failures. Both streams are captured: a console owns the terminal and library
/// code may not draw into it.
fn run(store: Option<&Path>, op: GitOp, argv: &[&str]) -> Step<Ran> {
    let out = match scrubbed(store).args(argv).output() {
        Ok(out) => out,
        Err(e) => {
            return Err(Failed {
                op,
                cause: e.into(),
                stderr: String::new(),
            })
        }
    };
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
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

/// Run one command on a backup host. `BatchMode=yes` is load-bearing: a background task must
/// never stop on a password prompt.
fn ssh(remote: &BackupRemote, argv: &[&str]) -> Result<Vec<u8>, GitErr> {
    let out = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg(format!("ConnectTimeout={CONNECT_TIMEOUT_SECS}"))
        .arg(&remote.host)
        .args(argv)
        .stdin(Stdio::null())
        .output()?;
    if out.status.success() {
        return Ok(out.stdout);
    }
    tracing::warn!(
        host = %remote.host,
        stderr = %String::from_utf8_lossy(&out.stderr).trim(),
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

/// Local `HEAD`. `None` is the unborn branch of a store with nothing to commit yet, which is a
/// correct answer and not a failure.
fn head(store: &Path) -> Step<Option<CommitId>> {
    let argv = ["rev-parse", "--verify", "--quiet", "HEAD"];
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

/// Tighten every mode, stage everything, and commit only when something was staged. The staged
/// check is what stops a no-op mutation pushing an empty commit to every remote forever.
///
/// The message is `hot_cheese <vault> <unix secs>` and nothing else: the diff already reveals
/// which files changed, but naming the operation would put a signing history on a remote that
/// has never held one.
fn commit(store: &Path, vault: &VaultId) -> Step<Option<CommitId>> {
    enforce_store_modes(store).map_err(|e| Failed {
        op: GitOp::Commit,
        cause: e.into(),
        stderr: String::new(),
    })?;
    git(Some(store), GitOp::Commit, &["add", "-A"])?;
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
    head(store)
}

/// Make `<store>` a repository on `main`, with the exclude and the pinned identity everything
/// else depends on, and commit whatever is already there. Idempotent.
///
/// `--template=` is not decoration: an `init.templateDir` in the operator's `~/.gitconfig`
/// would install that directory's hooks here, and a `pre-commit` from it runs inside our commit
/// — arbitrary code in the process holding the store lock, on every mutation. It also leaves no
/// `.git/info` at all, and a clone's default exclude carries no `*.hctmp` rule, which is why
/// both the directory and the rule are written here on every open rather than once at creation.
pub fn ensure_repo(store: &Path) -> Result<Option<CommitId>, GitErr> {
    std::fs::create_dir_all(store)?;
    let dot_git = store.join(GIT_DIR);
    if !dot_git.exists() {
        git(Some(store), GitOp::Commit, &["init", "-q", "--template="])?;
        git(
            Some(store),
            GitOp::Commit,
            &["symbolic-ref", "HEAD", HEAD_REF],
        )?;
    }
    let info = dot_git.join("info");
    std::fs::create_dir_all(&info)?;
    std::fs::write(info.join("exclude"), EXCLUDE)?;
    for (key, value) in LOCAL_CONFIG {
        git(Some(store), GitOp::Commit, &["config", key, value])?;
    }
    let on = git(Some(store), GitOp::Commit, &["symbolic-ref", "-q", "HEAD"])?;
    if String::from_utf8_lossy(&on).trim() != HEAD_REF {
        return Err(GitErr::HeadNotOnBranch);
    }
    match local_vault(store)? {
        LocalVault::Absent => Ok(None),
        _ => Ok(commit(store, &store_vault(store)?)?),
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

/// Vaults present in one remote's folder, in both layouts. A plain `<id>` directory beside our
/// `<id>.git` means a machine that has not been upgraded is still rsyncing into the same folder,
/// so the two have silently stopped converging.
pub fn list_vaults(remote: &BackupRemote) -> Result<RemoteVaults, GitErr> {
    let stdout = ssh(remote, &["ls", "-1", "--", remote.folder.as_str()])?;
    let mut found = RemoteVaults::default();
    for line in lines(&stdout) {
        match line.strip_suffix(BARE_SUFFIX) {
            Some(name) => {
                if let Ok(v) = name.parse::<VaultId>() {
                    found.git.push(v);
                }
            }
            None => {
                if let Ok(v) = line.parse::<VaultId>() {
                    found.legacy.push(v);
                }
            }
        }
    }
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

/// Clone one vault into an empty store dir.
///
/// `--branch main` is mandatory, not tidiness: a bare repository whose HEAD was never set points
/// at `master`, and a plain clone of it checks out nothing while exiting 0. The emptiness check
/// is equally load-bearing — git refuses a non-empty destination with a bare 128, and proceeding
/// to `ensure_repo` instead would `git init` a second, unrelated history over real keystores.
pub fn clone(remote: &BackupRemote, vault: &VaultId, store: &Path) -> Result<(), GitErr> {
    let mut entries = Vec::new();
    if let Ok(read) = std::fs::read_dir(store) {
        for entry in read.flatten() {
            entries.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    if !entries.is_empty() {
        entries.sort();
        return Err(GitErr::StoreNotEmpty {
            store: store.to_path_buf(),
            entries,
        });
    }
    std::fs::create_dir_all(store)?;
    git(
        None,
        GitOp::Clone,
        &[
            "-c",
            "core.fileMode=false",
            "clone",
            "--quiet",
            "--branch",
            BRANCH,
            "--",
            &url(remote, vault),
            &store.to_string_lossy(),
        ],
    )?;
    for (key, value) in LOCAL_CONFIG {
        git(Some(store), GitOp::Clone, &["config", key, value])?;
    }
    let info = store.join(GIT_DIR).join("info");
    std::fs::create_dir_all(&info)?;
    std::fs::write(info.join("exclude"), EXCLUDE)?;
    enforce_store_modes(store)?;
    require_vault(VaultSite::Pulled, Some(vault), local_vault(store)?.id())
}

/// Bring a store that has no keyring back from a backup remote. The trigger is `keyring.json`
/// being absent rather than the dir being empty: the backend creates the store dir before
/// anything else runs, and a `.git` in it would break an emptiness test.
///
/// This must run before anything reads `keyring.json` and before [`ensure_repo`] creates a
/// `.git`, because git refuses to clone into a dir that holds any file at all.
pub fn clone_if_absent(cfg: &Config) -> Result<(), GitErr> {
    let store = cfg.store_path();
    if local_vault(&store)? != LocalVault::Absent {
        return Ok(());
    }
    let Some(remote) = cfg.backup_remotes.first() else {
        return Ok(());
    };
    let vault = pull_vault(cfg, remote, None)?;
    tracing::info!(host = %remote.host, %vault, "the store has no keyring; cloning it from the backup remote");
    clone(remote, &vault, &store)
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

    /// A store with a keyring, a keystore and a policy: what every one of these tests commits.
    fn store_at(dir: &Path, vault: &VaultId) -> PathBuf {
        let store = dir.join("store");
        std::fs::create_dir_all(store.join("policies")).expect("make the store");
        std::fs::write(
            store.join(KEYRING_FILE),
            format!("{{\"v\":1,\"vault_id\":\"{vault}\",\"enrollments\":[]}}"),
        )
        .expect("write the keyring");
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
            GitOp::Clone,
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
            git(Some(into), GitOp::Clone, &["config", key, value]).expect("the clone configures");
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

        ensure_repo(&store).expect("the store becomes a repo");
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
        commit(&store, &vault).expect("the edit commits");
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
            GitOp::Merge,
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

    /// Two histories that both moved must be refused rather than merged, and the refusal must
    /// leave both sides untouched: this is the whole of "divergence is a surfaced state, never a
    /// silent overwrite".
    #[test]
    fn divergence_is_refused_not_merged() {
        let dir = scratch("diverge");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        let bare = bare_at(&dir, &vault);
        ensure_repo(&store).expect("the store becomes a repo");
        git(
            Some(&store),
            GitOp::Push,
            &["push", "--quiet", &bare, REFSPEC],
        )
        .expect("the first push creates main");

        let other = dir.join("other");
        clone_at(&bare, &other);

        std::fs::write(store.join("TREASURY"), b"ours").expect("our edit");
        commit(&store, &vault).expect("our commit");
        git(
            Some(&store),
            GitOp::Push,
            &["push", "--quiet", &bare, REFSPEC],
        )
        .expect("our push");

        std::fs::write(other.join("OPS"), b"theirs").expect("their edit");
        commit(&other, &vault).expect("their commit");
        let before = std::fs::read(other.join("OPS")).expect("their file exists");

        git(
            Some(&other),
            GitOp::Fetch,
            &["fetch", "--quiet", &bare, HEAD_REF],
        )
        .expect("they fetch");
        let local = head(&other)
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
                GitOp::Merge,
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
        let first = ensure_repo(&store)
            .expect("the store becomes a repo")
            .expect("a populated store commits once");

        assert!(commit(&store, &vault).expect("a no-op runs").is_none());
        assert!(commit(&store, &vault).expect("a no-op runs").is_none());
        assert_eq!(
            head(&store).expect("head reads").expect("born"),
            first,
            "two no-op mutations must not move HEAD"
        );

        std::fs::write(store.join("TREASURY"), b"changed").expect("touch a keystore");
        let second = commit(&store, &vault)
            .expect("a real change commits")
            .expect("a real change moves HEAD");
        assert_ne!(second, first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An in-flight `*.hctmp` from another writer must survive both the commit and the forced
    /// pull, which is only true because the exclude rule is written on every open — a clone's
    /// default exclude has no such rule and `clean -fd` would delete it.
    #[test]
    fn a_half_written_keystore_is_never_committed_or_cleaned() {
        let dir = scratch("hctmp");
        let vault = VaultId::random();
        let store = store_at(&dir, &vault);
        ensure_repo(&store).expect("the store becomes a repo");
        std::fs::write(store.join("TREASURY.hctmp"), b"half").expect("a half-written keystore");
        std::fs::write(store.join("policies").join("x.hctmp"), b"half").expect("and one nested");

        assert!(
            commit(&store, &vault).expect("a commit runs").is_none(),
            "a store whose only new files are temporary has nothing to commit"
        );
        git(Some(&store), GitOp::ForcedPull, &["clean", "-fdq"]).expect("clean runs");
        assert!(store.join("TREASURY.hctmp").exists());
        assert!(store.join("policies").join("x.hctmp").exists());
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
}
