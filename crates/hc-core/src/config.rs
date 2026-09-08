//! Runtime configuration + on-disk locations.
//!
//! Replaces the old compile-time `include_bytes!("conf/cheese_config.json")` so the
//! store path, port, certs, and backup remotes can change without a rebuild.
use crate::{is_valid_key_name, is_valid_string_name, resolve_path};
use alloy_primitives::{Address, U256};
use err_mac::create_err_with_impls;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Legacy Keychain service name (used only by `migrate` to read the old master).
    pub service: String,
    /// Legacy Keychain account name (migration only).
    pub account: String,
    /// Directory holding the encrypted keystores + `keyring.json`.
    pub store: String,
    /// Root of the add-only store snapshots, one subtree per vault; absent uses [`store_archive_dir`].
    #[serde(default)]
    pub store_archive: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    /// Uncompressed SEC1 hex (65 bytes) of the Secure Enclave grant key `serve` must find.
    #[serde(default)]
    pub grant_public_key: Option<String>,
    /// Seconds the background bundle poller waits between ticks.
    #[serde(default)]
    pub bundle_watch_secs: Option<u64>,
    /// Seconds the runtime waits between backup fetches; 0 disables the periodic fetch.
    #[serde(default)]
    pub backup_fetch_secs: Option<u64>,
    /// Seconds one approval prompt waits for an answer before it denies itself.
    #[serde(default)]
    pub approval_timeout_secs: Option<u64>,
    /// What an agent proposing over MCP may name, accumulate and spend.
    #[serde(default)]
    pub mcp: Option<Mcp>,
    #[serde(default)]
    pub backup_remotes: Vec<BackupRemote>,
    /// Out-of-process signing adapters this machine trusts.
    #[serde(default)]
    pub adapters: Vec<AdapterPin>,
    /// Tailnet machines this install syncs `bundles/` with.
    #[serde(default)]
    pub bundle_peers: Vec<BundlePeer>,
    /// Contracts whose base units an approval summary may also render scaled and named.
    #[serde(default)]
    pub token: Vec<TokenAnnotation>,
    /// Operator-chosen names an approval summary may show beside an address.
    #[serde(default)]
    pub label: Vec<LabelAnnotation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRemote {
    /// SSH target, optionally followed by `-i` and one identity-file path.
    pub host: String,
    /// Remote folder under the home dir, e.g. "hot_cheese_store".
    pub folder: String,
}

impl BackupRemote {
    pub fn ssh_parts(&self) -> (&str, Option<&str>) {
        backup_ssh_parts(&self.host)
    }
}

/// Where a peer keeps its bundles when `config.toml` does not say otherwise.
const DEFAULT_PEER_BUNDLES_DIR: &str = ".config/hot_cheese/bundles";

/// Unsigned bundles an agent may leave waiting before the proposal server refuses to file
/// another. The queue is read by a human, so it is bounded by what a human will read.
const DEFAULT_MCP_MAX_PENDING: usize = 16;
const MAX_MCP_PENDING: usize = 64;

/// Keystore names, Safes or nonce anchors one `[mcp]` table may carry.
const MAX_MCP_ENTRIES: usize = 256;

/// Nonces above the anchor a proposal may claim when `[mcp]` does not say otherwise. A Safe
/// executes nonces in order, so this is how many transactions an operator can be holding at once
/// and still have every approval they give execute in the order they gave it.
const DEFAULT_NONCE_WINDOW: u64 = 8;
const MAX_NONCE_WINDOW: u64 = 1024;

/// Minutes an unsigned proposal keeps its place by default. Long enough that a human working
/// across a day never loses a row, short enough that a wedged queue heals without anyone.
const DEFAULT_PROPOSAL_TTL_MINS: u64 = 1440;
const MAX_PROPOSAL_TTL_MINS: u64 = 43_200;

/// Proposals one agent session may file per hour by default; the same number the queue holds, so
/// an agent can refill a queue the operator has just emptied and no faster.
const DEFAULT_PROPOSALS_PER_HOUR: u32 = 16;
const MAX_PROPOSALS_PER_HOUR: u32 = 1024;

/// Milliseconds between one session's tool calls that take the exclusive bundle claim. The
/// operator's CLI takes the same claim and fails outright when it loses, so this is what decides
/// whether a human can run a command while an agent is working.
const DEFAULT_LOCK_COOLDOWN_MS: u64 = 100;
const MAX_LOCK_COOLDOWN_MS: u64 = 60_000;
const MAX_BACKUP_REMOTES: usize = 64;
const MAX_ADAPTERS: usize = 64;
const MAX_BUNDLE_PEERS: usize = 64;
const MAX_ANNOTATIONS: usize = 1024;
const MAX_LEGACY_KEYCHAIN_FIELD_BYTES: usize = 256;

/// Seconds between inspection-only backup fetches when `config.toml` does not say otherwise. A
/// fetch is one `ls-remote` plus at most one transfer per remote; it never changes the worktree.
const DEFAULT_BACKUP_FETCH_SECS: u64 = 300;

/// Seconds between bundle polls when `config.toml` does not say otherwise. The poller is
/// continuous and unattended rather than a screen someone is staring at, so halving the ssh
/// handshakes is worth more than five seconds of latency.
const DEFAULT_BUNDLE_POLL_SECS: u64 = 30;

/// The floor under that. `bundle_watch_secs = 0` would otherwise spin rsync subprocesses as fast
/// as ssh can connect; 5 is one peer's own connect timeout.
const MIN_BUNDLE_POLL_SECS: u64 = 5;

/// Seconds one approval prompt waits for an answer when `config.toml` does not say otherwise.
pub const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 60;

/// The floor an operator may set that to. A prompt the operator cannot read, reach and answer
/// denies every request on a busy machine, and an unanswered prompt is what makes every later one
/// challenged, so a deadline below this turns the whole approval surface into noise.
const MIN_APPROVAL_TIMEOUT_SECS: u64 = 5;

/// The ceiling. One prompt holds the single approval thread for its whole deadline, and every
/// caller behind it waits twice that for a place in the line before it is told to come back.
const MAX_APPROVAL_TIMEOUT_SECS: u64 = 600;

/// What an agent proposing over MCP is allowed to accumulate, to name, and to spend. The queue
/// bounds are read by the CLI and the daemon too; the rest bound the agent alone — which keys and
/// Safes it may name at all, how far ahead of the operator's own queue it may reserve a Safe
/// nonce, how often it may write, how long what it wrote keeps holding a slot, and how often it
/// may take the exclusive claim the operator's CLI needs to run at all. Every field defaults, so
/// an install whose `[mcp]` table predates them is bounded exactly as it was.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Mcp {
    /// Bundle directories that must already exist before a proposal is refused.
    #[serde(default)]
    pub max_pending: Option<usize>,
    /// Keystore names the agent may propose with; empty is every key the store holds.
    #[serde(default)]
    pub keys: Vec<String>,
    /// Safes the agent may propose against; empty is every Safe `safes.toml` describes.
    #[serde(default)]
    pub safes: Vec<Address>,
    /// Nonces above the anchor a proposal may claim.
    #[serde(default)]
    pub nonce_window: Option<u64>,
    /// Minutes an unsigned proposal keeps holding its slot and its place in the queue.
    #[serde(default)]
    pub proposal_ttl_mins: Option<u64>,
    /// Proposals one agent session may file per hour.
    #[serde(default)]
    pub proposals_per_hour: Option<u32>,
    /// Milliseconds one session must leave between tool calls that lock the bundle tree.
    #[serde(default)]
    pub lock_cooldown_ms: Option<u64>,
    /// Safe nonces the operator read off-chain, each anchoring its Safe's window absolutely.
    #[serde(default)]
    pub anchor: Vec<NonceAnchor>,
}

impl Mcp {
    pub fn max_pending(&self) -> usize {
        self.max_pending.unwrap_or(DEFAULT_MCP_MAX_PENDING)
    }
    pub fn nonce_window(&self) -> u64 {
        self.nonce_window.unwrap_or(DEFAULT_NONCE_WINDOW)
    }
    pub fn proposal_ttl_ms(&self) -> u64 {
        self.proposal_ttl_mins
            .unwrap_or(DEFAULT_PROPOSAL_TTL_MINS)
            .saturating_mul(60_000)
    }
    pub fn proposals_per_hour(&self) -> usize {
        self.proposals_per_hour
            .unwrap_or(DEFAULT_PROPOSALS_PER_HOUR) as usize
    }
    pub fn lock_cooldown_ms(&self) -> u64 {
        self.lock_cooldown_ms.unwrap_or(DEFAULT_LOCK_COOLDOWN_MS)
    }
}

/// One Safe's next nonce as the operator last read it on chain. This machine has no RPC client,
/// so a Safe's real nonce is not knowable here: this entry is the operator stating it, and
/// without one the window is anchored on the local queue instead.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonceAnchor {
    /// The Safe whose window this anchors.
    pub safe: Address,
    /// Chain the Safe is deployed on.
    #[serde(with = "crate::wire::u256")]
    pub chain_id: U256,
    /// The Safe's next nonce.
    #[serde(with = "crate::wire::u256")]
    pub nonce: U256,
}

/// One tailnet machine this install exchanges Safe bundles with over rsync-on-ssh.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundlePeer {
    /// SSH target: the peer's MagicDNS name, optionally `user@`-prefixed.
    pub host: String,
    /// The peer's bundles dir; a relative path resolves against its home dir.
    #[serde(default)]
    pub dir: Option<String>,
}

impl BundlePeer {
    pub fn dir(&self) -> &str {
        self.dir.as_deref().unwrap_or(DEFAULT_PEER_BUNDLES_DIR)
    }
    /// The ssh target without any `user@` prefix, which is what the tailnet knows it as.
    pub fn name(&self) -> &str {
        match self.host.split_once('@') {
            Some((_, host)) => host,
            None => &self.host,
        }
    }
}

/// One trusted adapter: which manifest, and the exact bytes that manifest must be.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterPin {
    /// Adapter id: names its manifest, its socket, and the provenance on the approval prompt.
    pub id: String,
    /// Manifest path; a relative one resolves under the home dir.
    pub manifest: String,
    /// SHA-256 hex the manifest bytes must hash to before they are parsed.
    pub sha256: String,
}

impl AdapterPin {
    pub fn manifest_path(&self) -> PathBuf {
        let path = resolve_path(&self.manifest);
        if path.is_absolute() {
            return path;
        }
        home_dir().join(path)
    }
}

/// The token interface a contract implements, which is what decides whether its integer
/// argument is a quantity at all: scaling a `tokenId` by a fungible token's decimals would
/// render token #42 as `0.000042`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenStandard {
    Erc20,
    Erc721,
    Erc1155,
}

/// One contract an approval summary may name and scale amounts for.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenAnnotation {
    /// The contract the Safe calls; `0x0` annotates the chain's native asset.
    pub address: Address,
    /// Chain the contract is deployed on.
    #[serde(with = "crate::wire::u256")]
    pub chain_id: U256,
    /// Ticker shown beside the scaled amount.
    pub symbol: String,
    /// Base-unit exponent; must be 0 unless the standard is fungible.
    pub decimals: u8,
    pub standard: TokenStandard,
}

/// One address an approval summary may name.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabelAnnotation {
    /// The address being named.
    pub address: Address,
    /// Chain the name applies on.
    #[serde(with = "crate::wire::u256")]
    pub chain_id: U256,
    /// The name, appended to the address and never substituted for it.
    pub name: String,
}

/// What sits at a config path that is not the regular file hot_cheese will read.
#[derive(Debug)]
pub enum ConfigFileKind {
    Symlink,
    Directory,
    Other,
}

/// Why operator-authored annotation text may not reach an approval sheet.
#[derive(Debug)]
pub enum TextRefusal {
    Empty,
    TooLong,
    NotPrintableAscii,
    Parenthesis,
    AddressPrefix,
}

create_err_with_impls!(
    #[derive(Debug)]
    pub SshTargetErr,
    ;
    Invalid { target: String }
);

impl std::error::Error for SshTargetErr {}

create_err_with_impls!(
    #[derive(Debug)]
    pub RemotePathErr,
    ;
    Invalid { path: String }
);

impl std::error::Error for RemotePathErr {}

create_err_with_impls!(
    #[derive(Debug)]
    pub ConfigErr,
    StdIo(std::io::Error),
    SerdeJson(serde_json::Error),
    Toml(toml::de::Error),
    TomlSer(toml::ser::Error),
    Envelope(crate::crypto::envelope::EnvErr),
    SshTarget(SshTargetErr),
    RemotePath(RemotePathErr),
    InvalidGrantPublicKey
    ;
    ConfigLocked { path: PathBuf },
    UnsafeConfigLock { path: PathBuf },
    ReplaceConfigWithARegularFile { path: PathBuf, found: ConfigFileKind },
    ChownConfigToYourUser { path: PathBuf, owner: u32, ours: u32 },
    AnnotationTextRefused {
        address: Address,
        text: String,
        refusal: TextRefusal,
    },
    DecimalsOnNonFungible {
        address: Address,
        standard: TokenStandard,
        decimals: u8,
    },
    DuplicateToken {
        address: Address,
        chain_id: U256,
    },
    DuplicateLabel {
        address: Address,
        chain_id: U256,
    },
    StorePathNotAbsolute { path: PathBuf },
    StorePathHasUnsafeComponent { path: PathBuf },
    StorePathIsDangerous { path: PathBuf },
    StorePathNotDirectory { path: PathBuf },
    StoreArchiveNotAbsolute { path: PathBuf },
    StoreArchiveHasUnsafeComponent { path: PathBuf },
    StoreArchiveNotDirectory { path: PathBuf },
    StoreArchiveSharesTheStore { archive: PathBuf, store: PathBuf },
    StoreArchiveSharesTheHome { archive: PathBuf, home: PathBuf },
    TooManyEntries { field: String, found: usize, max: usize },
    InvalidMcpLimit { field: &'static str, found: u64, min: u64, max: u64 },
    InvalidApprovalTimeout { found: u64, min: u64, max: u64 },
    InvalidPort { found: u16 },
    InvalidMcpKey { key: String },
    DuplicateAnchor { safe: Address, chain_id: U256 },
    InvalidAdapterId { id: String },
    InvalidAdapterPin { id: String },
    DuplicateAdapter { id: String },
    DuplicateBackupRemote { host: String, folder: String },
    DuplicateBundlePeer { host: String },
    InvalidLegacyKeychainField { field: String }
);

/// Characters of annotation text an approval sheet has room for.
const MAX_ANNOTATION_CHARS: usize = 32;

const MAX_SSH_TARGET_BYTES: usize = 255;
const MAX_REMOTE_PATH_BYTES: usize = 1024;
/// Config is operator-authored and normally a few KiB; this bounds both TOML and legacy JSON.
pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const CONFIG_LOCK_FILE: &str = ".config.lock";

/// Held across the complete load/edit/save cycle so concurrent commands cannot overwrite each
/// other's unrelated configuration changes. The lock lives beside `config.toml`, is never
/// followed through a symlink, and is accepted only when it is an owner-owned regular file.
struct ConfigWriteLock {
    _file: std::fs::File,
}

impl ConfigWriteLock {
    fn take() -> Result<Self, ConfigErr> {
        std::fs::create_dir_all(home_dir())?;
        Self::take_at(&home_dir().join(CONFIG_LOCK_FILE))
    }

    fn take_at(path: &Path) -> Result<Self, ConfigErr> {
        let file = std::fs::File::options()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        // SAFETY: `geteuid` has no preconditions and changes no process state.
        let ours = unsafe { libc::geteuid() };
        if !metadata.file_type().is_file() || metadata.uid() != ours {
            return Err(ConfigErr::UnsafeConfigLock {
                path: path.to_path_buf(),
            });
        }
        if metadata.mode() & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(ConfigErr::ConfigLocked {
                path: path.to_path_buf(),
            }),
            Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

/// Read a config only this account can rewrite: it pins the grant key every signature is verified
/// against and names the backup remotes, and a running daemon re-reads it every cycle. The config
/// holds no secret, so a mode open to other accounts is tightened to 0600 before the bytes are
/// taken rather than refused, the same way [`ConfigWriteLock::take_at`] and
/// [`crate::crypto::envelope::enforce_store_modes`] treat a loose mode they find. A path this
/// account cannot own the contents of is what stays a refusal.
fn owner_only_config_bytes(path: &Path) -> Result<Vec<u8>, ConfigErr> {
    let kind = std::fs::symlink_metadata(path)?.file_type();
    if !kind.is_file() {
        return Err(ConfigErr::ReplaceConfigWithARegularFile {
            path: path.to_path_buf(),
            found: if kind.is_symlink() {
                ConfigFileKind::Symlink
            } else if kind.is_dir() {
                ConfigFileKind::Directory
            } else {
                ConfigFileKind::Other
            },
        });
    }
    let file = crate::open_regular_file(path)?;
    let metadata = file.metadata()?;
    // SAFETY: `geteuid` has no preconditions and changes no process state.
    let ours = unsafe { libc::geteuid() };
    if metadata.uid() != ours {
        return Err(ConfigErr::ChownConfigToYourUser {
            path: path.to_path_buf(),
            owner: metadata.uid(),
            ours,
        });
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        tracing::warn!(
            path = %path.display(),
            was = %format!("{mode:04o}"),
            "config.toml was open to other accounts; tightened to 0600 before reading it"
        );
    }
    Ok(crate::read_bounded(file, MAX_CONFIG_BYTES)?)
}

fn canonical_with_missing(path: &Path) -> std::io::Result<PathBuf> {
    let mut cursor = path;
    let mut missing: Vec<OsString> = Vec::new();
    loop {
        match std::fs::canonicalize(cursor) {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = cursor.file_name() else {
                    return Err(error);
                };
                missing.push(name.to_os_string());
                let Some(parent) = cursor.parent() else {
                    return Err(error);
                };
                cursor = parent;
            }
            Err(error) => return Err(error),
        }
    }
}

fn validate_store_path(configured: &str) -> Result<(), ConfigErr> {
    let path = resolve_path(configured);
    if !path.is_absolute() {
        return Err(ConfigErr::StorePathNotAbsolute { path });
    }
    if configured
        .split('/')
        .any(|component| component == "." || component == "..")
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(ConfigErr::StorePathHasUnsafeComponent { path });
    }
    if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(ConfigErr::StorePathNotDirectory { path });
    }
    let resolved = canonical_with_missing(&path)?;
    if resolved.parent().is_none() {
        return Err(ConfigErr::StorePathIsDangerous { path: resolved });
    }
    let mut protected = vec![home_dir()];
    if let Ok(home) = std::env::var("HOME") {
        protected.push(PathBuf::from(home));
    }
    for anchor in protected {
        let anchor = canonical_with_missing(&anchor)?;
        if resolved == anchor || anchor.starts_with(&resolved) {
            return Err(ConfigErr::StorePathIsDangerous { path: resolved });
        }
    }
    if path.exists() && !path.is_dir() {
        return Err(ConfigErr::StorePathNotDirectory { path });
    }
    Ok(())
}

/// Judge an operator-chosen `store_archive`. The archive exists to survive the destruction of the
/// store and of the home dir, so an archive that lives inside either — or that contains either —
/// shares exactly the fate it was added to escape, and is refused here rather than discovered after
/// the `rm -rf`. An archive inside the store would also be a directory the store grammar refuses,
/// which would wedge every commit.
fn validate_store_archive_path(configured: &str, store: &str) -> Result<(), ConfigErr> {
    let path = resolve_path(configured);
    if !path.is_absolute() {
        return Err(ConfigErr::StoreArchiveNotAbsolute { path });
    }
    if configured
        .split('/')
        .any(|component| component == "." || component == "..")
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(ConfigErr::StoreArchiveHasUnsafeComponent { path });
    }
    if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_symlink())
        || (path.exists() && !path.is_dir())
    {
        return Err(ConfigErr::StoreArchiveNotDirectory { path });
    }
    let archive = canonical_with_missing(&path)?;
    if archive.parent().is_none() {
        return Err(ConfigErr::StoreArchiveHasUnsafeComponent { path: archive });
    }
    let store = canonical_with_missing(&resolve_path(store))?;
    if archive.starts_with(&store) || store.starts_with(&archive) {
        return Err(ConfigErr::StoreArchiveSharesTheStore { archive, store });
    }
    let home = canonical_with_missing(&home_dir())?;
    if archive.starts_with(&home) || home.starts_with(&archive) {
        return Err(ConfigErr::StoreArchiveSharesTheHome { archive, home });
    }
    Ok(())
}

fn check_count(field: &str, found: usize, max: usize) -> Result<(), ConfigErr> {
    if found > max {
        return Err(ConfigErr::TooManyEntries {
            field: field.to_string(),
            found,
            max,
        });
    }
    Ok(())
}

fn ssh_word(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with('-')
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

pub fn validate_ssh_target(target: &str) -> Result<(), SshTargetErr> {
    let valid = !target.is_empty()
        && target.len() <= MAX_SSH_TARGET_BYTES
        && match target.split_once('@') {
            Some((user, host)) => !host.contains('@') && ssh_word(user) && ssh_word(host),
            None => ssh_word(target),
        };
    if valid {
        return Ok(());
    }
    Err(SshTargetErr::Invalid {
        target: target.to_string(),
    })
}

fn backup_ssh_parts(target: &str) -> (&str, Option<&str>) {
    match target.split_once(" -i ") {
        Some((host, identity_file)) => (host, Some(identity_file)),
        None => (target, None),
    }
}

pub fn validate_backup_ssh_target(target: &str) -> Result<(), SshTargetErr> {
    let (host, identity_file) = backup_ssh_parts(target);
    let valid_identity = identity_file.is_none_or(|path| {
        !path.is_empty()
            && !path.starts_with('-')
            && path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '~'))
    });
    if target.len() <= MAX_SSH_TARGET_BYTES && validate_ssh_target(host).is_ok() && valid_identity {
        return Ok(());
    }
    Err(SshTargetErr::Invalid {
        target: target.to_string(),
    })
}

pub fn validate_remote_path(path: &str) -> Result<(), RemotePathErr> {
    let trimmed = path.trim_end_matches('/');
    let valid = !trimmed.is_empty()
        && path.len() <= MAX_REMOTE_PATH_BYTES
        && !path
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/')))
        && !path
            .split('/')
            .any(|component| component == ".." || component.starts_with('-'));
    if valid {
        return Ok(());
    }
    Err(RemotePathErr::Invalid {
        path: path.to_string(),
    })
}

/// Judge one piece of operator-authored text that an approval summary will print. It is
/// operator-authored but frequently pasted from whoever asked to be paid, so it is untrusted
/// text in a security-critical string: a newline could forge a `⚠` line or push the real
/// content off the three lines a Touch ID sheet shows, a parenthesis could close the one the
/// renderer opened and open a second, and a `0x` prefix could pass for an address.
fn annotation_text(text: &str) -> Result<(), TextRefusal> {
    if text.is_empty() {
        return Err(TextRefusal::Empty);
    }
    if text.chars().count() > MAX_ANNOTATION_CHARS {
        return Err(TextRefusal::TooLong);
    }
    if !text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return Err(TextRefusal::NotPrintableAscii);
    }
    if text.contains('(') || text.contains(')') {
        return Err(TextRefusal::Parenthesis);
    }
    if text.starts_with("0x") || text.starts_with("0X") {
        return Err(TextRefusal::AddressPrefix);
    }
    Ok(())
}

/// `$HOT_CHEESE_HOME`, else `~/.config/hot_cheese`.
pub fn home_dir() -> PathBuf {
    if let Ok(h) = std::env::var("HOT_CHEESE_HOME") {
        return PathBuf::from(h);
    }
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h).join(".config").join("hot_cheese");
    }
    PathBuf::from(".hot_cheese")
}

pub fn config_path() -> PathBuf {
    home_dir().join("config.toml")
}

/// Root of the store's add-only snapshots when `config.toml` names no `store_archive`.
///
/// Deliberately outside [`home_dir`] and outside the store: an `rm -rf` of either — a mistake, a
/// stale uninstall script, an agent told to clean up — must not be able to take the copies with it,
/// which is the whole reason this archive exists. A snapshot is written on every mutation that adds
/// or changes a keystore or `keyring.json`, is named after the digest of its own bytes so a new one
/// can never land on an older one, and is never removed by anything in this program: pruning is the
/// operator's own `rm`, on files they can read and name first.
///
/// Being outside every `HOT_CHEESE_HOME` means every install on the machine shares this one root,
/// and nothing prunes it, so a throwaway home's snapshots would otherwise pile up here forever and
/// be indistinguishable from real ones at exactly the moment they matter. A snapshot therefore
/// lands under `<root>/<vault_id>/`, the same namespace a backup push targets, and an install lists
/// and restores only its own subtree.
///
/// Three consequences the operator has to know, because they are properties of add-only storage
/// and not of this implementation:
///
/// - Old ciphertext lives here forever. If the DEK is ever compromised, every snapshot ever
///   written is decryptable, and deleting a keystore afterwards buys nothing back. Rotation means
///   generating a NEW key and moving the funds to it, never deleting the old one.
/// - Every snapshot is another copy of the same ciphertext, and the recovery passphrase is the only
///   thing between a stolen copy and the keys. More copies is more surface for an offline attack on
///   that passphrase, so the passphrase has to be worth that.
/// - The archive holds exactly what the store holds: ciphertext, plus cleartext key names and
///   policies. That is safe to leave on a disk only you can read. It is not safe to publish, and
///   the cleartext half names every key you hold and what each one is allowed to sign.
pub fn store_archive_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("hot_cheese")
            .join("store-archive");
    }
    PathBuf::from(".hot_cheese_store_archive")
}

/// `<home>/adapters`: adapter manifests and their sockets. Deliberately outside the store, so
/// adapter trust is per-machine and never travels with a backup or an SSH bootstrap.
pub fn adapters_dir() -> PathBuf {
    home_dir().join("adapters")
}

/// `<home>/adapters/<id>.sock`, the one socket that carries adapter `id`'s provenance.
pub fn adapter_socket(id: &str) -> PathBuf {
    adapters_dir().join(format!("{id}.sock"))
}

/// `<home>/bundles`: `safes.toml` and one directory per SafeTx being collected. Deliberately
/// outside the store, which backup replicates per vault: two machines hold deliberately
/// different signer keys, and a bundle — public fields plus signatures over a public digest —
/// must never ride the path that carries key material.
pub fn bundles_dir() -> PathBuf {
    home_dir().join("bundles")
}

/// `<home>/read-grants`: one sealed grant per key an agent may pull without Touch ID.
/// Deliberately outside the store, whose git tree replicates to every backup remote: a live
/// credential must never reach a backup, and the store grammar would refuse the directory anyway.
pub fn read_grants_dir() -> PathBuf {
    home_dir().join("read-grants")
}

/// `<home>/bundle-quarantine`: where a file a peer pushed goes when it fails verification.
/// Outside `bundles/` on purpose, so nothing quarantined is ever synced back out.
pub fn bundle_quarantine_dir() -> PathBuf {
    home_dir().join("bundle-quarantine")
}

/// (cert.pem, key.pem) under the home dir.
pub fn cert_paths() -> (PathBuf, PathBuf) {
    let h = home_dir();
    (h.join("ssl-cert.pem"), h.join("ssl-key.pem"))
}

/// Max tracing level from `RUST_LOG` (case-insensitive level word), defaulting to INFO.
pub fn env_log_level() -> tracing::Level {
    match std::env::var("RUST_LOG").ok().as_deref() {
        Some(v) if v.eq_ignore_ascii_case("trace") => tracing::Level::TRACE,
        Some(v) if v.eq_ignore_ascii_case("debug") => tracing::Level::DEBUG,
        Some(v) if v.eq_ignore_ascii_case("warn") => tracing::Level::WARN,
        Some(v) if v.eq_ignore_ascii_case("error") => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    }
}

impl Config {
    pub fn store_path(&self) -> PathBuf {
        resolve_path(&self.store)
    }
    pub fn store_archive_path(&self) -> PathBuf {
        match &self.store_archive {
            Some(configured) => resolve_path(configured),
            None => store_archive_dir(),
        }
    }
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(5555)
    }
    pub fn bundle_watch_secs(&self) -> u64 {
        self.bundle_watch_secs
            .unwrap_or(DEFAULT_BUNDLE_POLL_SECS)
            .max(MIN_BUNDLE_POLL_SECS)
    }
    pub fn backup_fetch_secs(&self) -> u64 {
        self.backup_fetch_secs.unwrap_or(DEFAULT_BACKUP_FETCH_SECS)
    }
    /// How long one approval prompt waits for an answer before it denies itself. Bounded by
    /// [`Config::validate`], so a nonsensical value stops the command instead of the daemon.
    pub fn approval_timeout(&self) -> Duration {
        Duration::from_secs(
            self.approval_timeout_secs
                .unwrap_or(DEFAULT_APPROVAL_TIMEOUT_SECS),
        )
    }
    /// The `[mcp]` table, or every bound at its default when the config carries no such table.
    pub fn mcp(&self) -> &Mcp {
        static ABSENT: Mcp = Mcp {
            max_pending: None,
            keys: Vec::new(),
            safes: Vec::new(),
            nonce_window: None,
            proposal_ttl_mins: None,
            proposals_per_hour: None,
            lock_cooldown_ms: None,
            anchor: Vec::new(),
        };
        self.mcp.as_ref().unwrap_or(&ABSENT)
    }
    /// Validate an in-memory configuration before it is persisted or trusted.
    pub fn validate(&self) -> Result<(), ConfigErr> {
        validate_store_path(&self.store)?;
        if let Some(archive) = &self.store_archive {
            validate_store_archive_path(archive, &self.store)?;
        }
        if self.port == Some(0) {
            return Err(ConfigErr::InvalidPort { found: 0 });
        }
        for (field, value) in [("service", &self.service), ("account", &self.account)] {
            if value.len() > MAX_LEGACY_KEYCHAIN_FIELD_BYTES || value.contains('\0') {
                return Err(ConfigErr::InvalidLegacyKeychainField {
                    field: field.to_string(),
                });
            }
        }
        if let Some(pinned) = &self.grant_public_key {
            let point = hex::decode(pinned).map_err(|_| ConfigErr::InvalidGrantPublicKey)?;
            if point.len() != 65
                || point.first() != Some(&4)
                || p256::PublicKey::from_sec1_bytes(&point).is_err()
            {
                return Err(ConfigErr::InvalidGrantPublicKey);
            }
        }
        if let Some(found) = self.approval_timeout_secs {
            if !(MIN_APPROVAL_TIMEOUT_SECS..=MAX_APPROVAL_TIMEOUT_SECS).contains(&found) {
                return Err(ConfigErr::InvalidApprovalTimeout {
                    found,
                    min: MIN_APPROVAL_TIMEOUT_SECS,
                    max: MAX_APPROVAL_TIMEOUT_SECS,
                });
            }
        }
        let mcp = self.mcp();
        check_count("mcp.keys", mcp.keys.len(), MAX_MCP_ENTRIES)?;
        check_count("mcp.safes", mcp.safes.len(), MAX_MCP_ENTRIES)?;
        check_count("mcp.anchor", mcp.anchor.len(), MAX_MCP_ENTRIES)?;
        for key in &mcp.keys {
            if !is_valid_key_name(key) {
                return Err(ConfigErr::InvalidMcpKey { key: key.clone() });
            }
        }
        for (at, anchor) in mcp.anchor.iter().enumerate() {
            if mcp.anchor[at + 1..]
                .iter()
                .any(|other| other.safe == anchor.safe && other.chain_id == anchor.chain_id)
            {
                return Err(ConfigErr::DuplicateAnchor {
                    safe: anchor.safe,
                    chain_id: anchor.chain_id,
                });
            }
        }
        for (field, stated, min, max) in [
            (
                "max_pending",
                mcp.max_pending.map(|found| found as u64),
                1,
                MAX_MCP_PENDING as u64,
            ),
            ("nonce_window", mcp.nonce_window, 0, MAX_NONCE_WINDOW),
            (
                "proposal_ttl_mins",
                mcp.proposal_ttl_mins,
                1,
                MAX_PROPOSAL_TTL_MINS,
            ),
            (
                "proposals_per_hour",
                mcp.proposals_per_hour.map(u64::from),
                1,
                u64::from(MAX_PROPOSALS_PER_HOUR),
            ),
            (
                "lock_cooldown_ms",
                mcp.lock_cooldown_ms,
                0,
                MAX_LOCK_COOLDOWN_MS,
            ),
        ] {
            let Some(found) = stated else {
                continue;
            };
            if found < min || found > max {
                return Err(ConfigErr::InvalidMcpLimit {
                    field,
                    found,
                    min,
                    max,
                });
            }
        }
        check_count(
            "backup_remotes",
            self.backup_remotes.len(),
            MAX_BACKUP_REMOTES,
        )?;
        check_count("adapters", self.adapters.len(), MAX_ADAPTERS)?;
        check_count("bundle_peers", self.bundle_peers.len(), MAX_BUNDLE_PEERS)?;
        check_count("token", self.token.len(), MAX_ANNOTATIONS)?;
        check_count("label", self.label.len(), MAX_ANNOTATIONS)?;

        for (at, remote) in self.backup_remotes.iter().enumerate() {
            validate_backup_ssh_target(&remote.host)?;
            validate_remote_path(&remote.folder)?;
            if self.backup_remotes[at + 1..].iter().any(|other| {
                other
                    .ssh_parts()
                    .0
                    .eq_ignore_ascii_case(remote.ssh_parts().0)
                    && other.folder == remote.folder
            }) {
                return Err(ConfigErr::DuplicateBackupRemote {
                    host: remote.host.clone(),
                    folder: remote.folder.clone(),
                });
            }
        }
        for (at, peer) in self.bundle_peers.iter().enumerate() {
            validate_ssh_target(&peer.host)?;
            validate_remote_path(peer.dir())?;
            if self.bundle_peers[at + 1..]
                .iter()
                .any(|other| other.host.eq_ignore_ascii_case(&peer.host))
            {
                return Err(ConfigErr::DuplicateBundlePeer {
                    host: peer.host.clone(),
                });
            }
        }
        for (at, adapter) in self.adapters.iter().enumerate() {
            if !is_valid_string_name(&adapter.id) {
                return Err(ConfigErr::InvalidAdapterId {
                    id: adapter.id.clone(),
                });
            }
            let pin = hex::decode(&adapter.sha256).map_err(|_| ConfigErr::InvalidAdapterPin {
                id: adapter.id.clone(),
            })?;
            if pin.len() != 32 {
                return Err(ConfigErr::InvalidAdapterPin {
                    id: adapter.id.clone(),
                });
            }
            if self.adapters[at + 1..]
                .iter()
                .any(|other| other.id == adapter.id)
            {
                return Err(ConfigErr::DuplicateAdapter {
                    id: adapter.id.clone(),
                });
            }
        }
        for (i, token) in self.token.iter().enumerate() {
            if let Err(refusal) = annotation_text(&token.symbol) {
                return Err(ConfigErr::AnnotationTextRefused {
                    address: token.address,
                    text: token.symbol.clone(),
                    refusal,
                });
            }
            let fungible = match token.standard {
                TokenStandard::Erc20 => true,
                TokenStandard::Erc721 | TokenStandard::Erc1155 => false,
            };
            if !fungible && token.decimals != 0 {
                return Err(ConfigErr::DecimalsOnNonFungible {
                    address: token.address,
                    standard: token.standard,
                    decimals: token.decimals,
                });
            }
            for other in &self.token[i + 1..] {
                if other.address == token.address && other.chain_id == token.chain_id {
                    return Err(ConfigErr::DuplicateToken {
                        address: token.address,
                        chain_id: token.chain_id,
                    });
                }
            }
        }
        for (i, label) in self.label.iter().enumerate() {
            if let Err(refusal) = annotation_text(&label.name) {
                return Err(ConfigErr::AnnotationTextRefused {
                    address: label.address,
                    text: label.name.clone(),
                    refusal,
                });
            }
            for other in &self.label[i + 1..] {
                if other.address == label.address && other.chain_id == label.chain_id {
                    return Err(ConfigErr::DuplicateLabel {
                        address: label.address,
                        chain_id: label.chain_id,
                    });
                }
            }
        }
        Ok(())
    }
    pub fn load() -> Result<Self, ConfigErr> {
        let path = config_path();
        if !path.exists() {
            let legacy = home_dir().join("config.json");
            if legacy.exists() {
                let bytes = owner_only_config_bytes(&legacy)?;
                let cfg: Config = crate::wire::strict_json_from_slice(&bytes)?;
                cfg.validate()?;
                cfg.save()?;
                std::fs::remove_file(&legacy)?;
                return Ok(cfg);
            }
        }
        let bytes = owner_only_config_bytes(&path)?;
        let cfg: Config = toml::from_str(
            std::str::from_utf8(&bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        )?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Atomically serialize an existing-config read/modify/write transaction against every
    /// other hot_cheese command using this API. The closure may return its caller's richer error
    /// type; configuration and lock failures convert into it.
    pub fn update<T, E>(edit: impl FnOnce(&mut Self) -> Result<T, E>) -> Result<T, E>
    where
        E: From<ConfigErr>,
    {
        let _lock = ConfigWriteLock::take().map_err(E::from)?;
        let mut config = Self::load().map_err(E::from)?;
        let result = edit(&mut config)?;
        config.save().map_err(E::from)?;
        Ok(result)
    }
    /// A config for tests that build a `HotApi` directly: the store, plus the P-256 base
    /// point standing in for a pinned grant key so the sign path reaches its approver (no
    /// test owns an enclave, so none of them reaches the mint that key would answer).
    #[cfg(any(test, feature = "test-util"))]
    pub fn for_test(store: &str) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            service: String::new(),
            account: String::new(),
            store: store.to_string(),
            store_archive: Some(format!("{store}.archive")),
            port: None,
            grant_public_key: Some(
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
                    .to_string(),
            ),
            bundle_watch_secs: None,
            backup_fetch_secs: None,
            approval_timeout_secs: None,
            mcp: None,
            backup_remotes: Vec::new(),
            adapters: Vec::new(),
            bundle_peers: Vec::new(),
            token: Vec::new(),
            label: Vec::new(),
        })
    }
    pub fn save(&self) -> Result<(), ConfigErr> {
        self.validate()?;
        let text = toml::to_string_pretty(self)?;
        let p = config_path();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::crypto::envelope::atomic_write(&p, text.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "service = \"\"\naccount = \"\"\nstore = \"/nonexistent\"\n";

    fn loaded(tables: &str) -> Result<Config, ConfigErr> {
        let cfg: Config = toml::from_str(&format!("{HEAD}{tables}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn label(name: &str) -> Result<Config, ConfigErr> {
        loaded(&format!(
            "[[label]]\naddress = \"0x2222222222222222222222222222222222222222\"\n\
             chain_id = 1\nname = \"{name}\"\n"
        ))
    }

    fn with_store(path: &str) -> Result<Config, ConfigErr> {
        let cfg: Config = toml::from_str(&format!(
            "service = \"\"\naccount = \"\"\nstore = {path:?}\n"
        ))?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn config_update_lock_serializes_the_whole_transaction() {
        let path = std::env::temp_dir().join(format!(
            "hot-cheese-config-lock-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = ConfigWriteLock::take_at(&path).expect("first writer claims the lock");
        assert!(matches!(
            ConfigWriteLock::take_at(&path),
            Err(ConfigErr::ConfigLocked { .. })
        ));
        drop(first);
        ConfigWriteLock::take_at(&path).expect("released lock is reusable");
        std::fs::remove_file(path).unwrap();
    }

    /// A daemon re-reads `config.toml` and obeys the grant key it pins, so a mode another account
    /// can rewrite is closed before the bytes are taken instead of refused — refusing wedges every
    /// command over a file that holds no secret — while a path whose contents this account cannot
    /// own stays a refusal that names what to do about it.
    #[test]
    fn a_config_open_to_other_accounts_is_tightened_rather_than_wedging_every_command() {
        let dir = std::env::temp_dir().join(format!(
            "hot-cheese-config-mode-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("make the test dir");
        let path = dir.join("config.toml");
        crate::crypto::envelope::atomic_write(&path, HEAD.as_bytes()).expect("write it 0600");
        assert_eq!(
            owner_only_config_bytes(&path).expect("an owner-only config loads"),
            HEAD.as_bytes()
        );
        assert_eq!(
            std::fs::metadata(&path).expect("stat it").mode() & 0o7777,
            0o600
        );

        for loose in [0o644, 0o664, 0o606] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(loose))
                .expect("loosen the mode");
            assert_eq!(
                owner_only_config_bytes(&path).expect("a loose config still loads"),
                HEAD.as_bytes()
            );
            assert_eq!(
                std::fs::metadata(&path).expect("stat it").mode() & 0o7777,
                0o600,
                "{loose:o} reached the read"
            );
        }

        let link = dir.join("link.toml");
        std::os::unix::fs::symlink(&path, &link).expect("make a final-component symlink");
        assert!(matches!(
            owner_only_config_bytes(&link),
            Err(ConfigErr::ReplaceConfigWithARegularFile {
                found: ConfigFileKind::Symlink,
                ..
            })
        ));

        // SAFETY: `geteuid` has no preconditions and changes no process state.
        if unsafe { libc::geteuid() } != 0 {
            assert!(matches!(
                owner_only_config_bytes(Path::new("/etc/hosts")),
                Err(ConfigErr::ChownConfigToYourUser { owner: 0, .. })
            ));
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A label is pasted text that a summary prints inside `address (name)`, so the shapes that
    /// could forge structure there — a newline that fakes a ⚠ line or pushes the real content off
    /// a three-line sheet, a paren that closes the renderer's and opens its own, an address-like
    /// prefix, and anything too long for the sheet — must all die before an approval ever runs.
    #[test]
    fn label_text_that_could_forge_an_approval_line_dies_at_load() {
        assert!(label("Vendor payouts").is_ok());
        for forged in [
            r"Vendor\npayouts",
            "Vendor (payouts",
            "Vendor payouts)",
            "0xdeadbeef",
            "",
            &"a".repeat(33),
        ] {
            assert!(
                matches!(label(forged), Err(ConfigErr::AnnotationTextRefused { .. })),
                "{forged:?} must not reach an approval sheet"
            );
        }
        assert!(label(&"a".repeat(32)).is_ok());
    }

    /// A second entry for a `(address, chain_id)` the first already answers can never fire, and a
    /// `decimals` on a standard whose integer is an id and not a quantity would render token #42
    /// as `0.000042`. Both are operator beliefs the renderer would not honour, so neither loads.
    #[test]
    fn annotation_tables_refuse_entries_that_could_never_be_honoured() {
        let two = concat!(
            "[[label]]\naddress = \"0x2222222222222222222222222222222222222222\"\n",
            "chain_id = 1\nname = \"Vendor payouts\"\n\n",
            "[[label]]\naddress = \"0x2222222222222222222222222222222222222222\"\n",
            "chain_id = 1\nname = \"Attacker\"\n",
        );
        assert!(matches!(loaded(two), Err(ConfigErr::DuplicateLabel { .. })));

        let other_chain = two.replace(
            "chain_id = 1\nname = \"Attacker\"",
            "chain_id = 10\nname = \"Attacker\"",
        );
        assert!(loaded(&other_chain).is_ok());

        let token = |standard: &str, decimals: u8| {
            loaded(&format!(
                "[[token]]\naddress = \"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48\"\n\
                 chain_id = 1\nsymbol = \"USDC\"\ndecimals = {decimals}\nstandard = \"{standard}\"\n"
            ))
        };
        assert!(token("erc20", 6).is_ok());
        assert!(token("erc721", 0).is_ok());
        assert!(matches!(
            token("erc721", 6),
            Err(ConfigErr::DecimalsOnNonFungible { .. })
        ));
        assert!(matches!(
            token("erc1155", 6),
            Err(ConfigErr::DecimalsOnNonFungible { .. })
        ));
    }

    /// An archive inside the store, or inside the home, shares exactly the `rm -rf` it exists to
    /// survive — and an archive containing either is the same mistake written the other way round.
    #[test]
    fn a_store_archive_that_shares_what_it_protects_is_refused_at_config_load() {
        let dir = std::env::temp_dir().join(format!(
            "hot-cheese-config-archive-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = dir.join("store");
        std::fs::create_dir_all(&store).expect("make the store");
        let archived = |at: PathBuf| -> Result<Config, ConfigErr> {
            let cfg: Config = toml::from_str(&format!(
                "service = \"\"\naccount = \"\"\nstore = {:?}\nstore_archive = {:?}\n",
                store.display().to_string(),
                at.display().to_string()
            ))?;
            cfg.validate()?;
            Ok(cfg)
        };
        assert!(matches!(
            archived(store.join("snapshots")),
            Err(ConfigErr::StoreArchiveSharesTheStore { .. })
        ));
        assert!(matches!(
            archived(dir.clone()),
            Err(ConfigErr::StoreArchiveSharesTheStore { .. })
        ));
        assert!(matches!(
            archived(home_dir().join("snapshots")),
            Err(ConfigErr::StoreArchiveSharesTheHome { .. })
        ));
        assert!(matches!(
            archived(PathBuf::from("relative/snapshots")),
            Err(ConfigErr::StoreArchiveNotAbsolute { .. })
        ));
        archived(dir.join("snapshots"))
            .expect("an archive beside the store and outside the home is what this is for");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn destructive_store_targets_are_refused_at_config_load() {
        assert!(matches!(
            with_store("relative/store"),
            Err(ConfigErr::StorePathNotAbsolute { .. })
        ));
        assert!(matches!(
            with_store("/"),
            Err(ConfigErr::StorePathIsDangerous { .. })
        ));
        assert!(matches!(
            with_store("/tmp/../etc"),
            Err(ConfigErr::StorePathHasUnsafeComponent { .. })
        ));
        assert!(matches!(
            with_store(&home_dir().display().to_string()),
            Err(ConfigErr::StorePathIsDangerous { .. })
        ));
        assert!(with_store("/nonexistent/hot-cheese-dedicated-store").is_ok());

        let file = std::env::temp_dir().join(format!(
            "hot-cheese-config-store-file-{}",
            std::process::id()
        ));
        std::fs::write(&file, b"not a directory").expect("make a file-shaped store target");
        assert!(matches!(
            with_store(&file.display().to_string()),
            Err(ConfigErr::StorePathNotDirectory { .. })
        ));
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn ssh_words_remote_paths_and_config_multiplicity_are_bounded() {
        for target in ["host", "user@host.tailnet.ts.net", "user_name@10.0.0.1"] {
            assert!(validate_ssh_target(target).is_ok(), "{target}");
        }
        for target in ["", "-oProxyCommand=x", "user@@host", "host;touch", "user@"] {
            assert!(validate_ssh_target(target).is_err(), "{target}");
        }
        for path in ["vault.git", "folder/under_home", "/absolute/safe-dir/"] {
            assert!(validate_remote_path(path).is_ok(), "{path}");
        }
        for path in [
            "",
            "../escape",
            "folder/../escape",
            "folder;touch",
            "-option",
        ] {
            assert!(validate_remote_path(path).is_err(), "{path}");
        }

        let too_many = (0..=MAX_BUNDLE_PEERS)
            .map(|at| BundlePeer {
                host: format!("peer{at}"),
                dir: None,
            })
            .collect();
        let mut cfg = loaded("").expect("base config");
        cfg.bundle_peers = too_many;
        assert!(matches!(
            cfg.validate(),
            Err(ConfigErr::TooManyEntries { ref field, .. }) if field == "bundle_peers"
        ));

        let mut cfg = loaded("").expect("base config");
        cfg.mcp = Some(Mcp {
            max_pending: Some(MAX_MCP_PENDING + 1),
            ..Mcp::default()
        });
        assert!(matches!(
            cfg.validate(),
            Err(ConfigErr::InvalidMcpLimit {
                field: "max_pending",
                ..
            })
        ));

        assert!(matches!(
            loaded("[mcp]\nnonce_window = 4096\n"),
            Err(ConfigErr::InvalidMcpLimit {
                field: "nonce_window",
                ..
            })
        ));
    }

    #[test]
    fn an_ephemeral_listener_port_is_refused() {
        assert!(matches!(
            loaded("port = 0\n"),
            Err(ConfigErr::InvalidPort { found: 0 })
        ));
    }

    #[test]
    fn backup_targets_allow_one_safe_identity_file_only() {
        for target in [
            "host",
            "nixos@tprime2 -i ~/.ssh/copium2",
            "backup.example -i /Users/operator/.ssh/id_ed25519",
        ] {
            assert!(validate_backup_ssh_target(target).is_ok(), "{target}");
        }
        for target in [
            "host -p 2222",
            "host -o ProxyCommand=x",
            "host -i",
            "host -i ",
            "host -i -key",
            "host -i ~/.ssh/key other",
            "host -i ~/.ssh/key;touch",
            "host -i ~/.ssh/key -i ~/.ssh/other",
        ] {
            assert!(validate_backup_ssh_target(target).is_err(), "{target}");
        }

        let mut cfg = loaded("").expect("base config");
        cfg.backup_remotes.push(BackupRemote {
            host: "nixos@tprime2 -i ~/.ssh/copium2".to_string(),
            folder: "backups".to_string(),
        });
        assert!(cfg.validate().is_ok());

        let mut duplicate = loaded("").expect("base config");
        duplicate.backup_remotes.extend([
            BackupRemote {
                host: "nixos@tprime2".to_string(),
                folder: "backups".to_string(),
            },
            BackupRemote {
                host: "NIXOS@TPRIME2 -i ~/.ssh/copium2".to_string(),
                folder: "backups".to_string(),
            },
        ]);
        assert!(matches!(
            duplicate.validate(),
            Err(ConfigErr::DuplicateBackupRemote { .. })
        ));

        cfg.bundle_peers.push(BundlePeer {
            host: "nixos@tprime2 -i ~/.ssh/copium2".to_string(),
            dir: None,
        });
        assert!(matches!(
            cfg.validate(),
            Err(ConfigErr::SshTarget(SshTargetErr::Invalid { .. }))
        ));
    }

    /// Every `[mcp]` bound the agent is held to has a default, and folding the agent limits into
    /// this one file must not move any of them: a config that names none of the new keys — the
    /// only thing an install predating them has — is bounded by exactly the values the standalone
    /// limits file used, and an empty allow-list still means every key and every Safe.
    #[test]
    fn an_mcp_table_naming_none_of_the_agent_limits_keeps_every_previous_default() {
        for tables in ["", "[mcp]\n", "[mcp]\nmax_pending = 4\n"] {
            let cfg = loaded(tables).expect("a config predating the agent limits still loads");
            let mcp = cfg.mcp();
            assert!(mcp.keys.is_empty(), "an empty allow-list is every key");
            assert!(mcp.safes.is_empty(), "and every Safe");
            assert!(mcp.anchor.is_empty());
            assert_eq!(mcp.nonce_window(), 8);
            assert_eq!(mcp.proposal_ttl_ms(), 1_440 * 60_000);
            assert_eq!(mcp.proposals_per_hour(), 16);
            assert_eq!(mcp.lock_cooldown_ms(), 100);
        }
        assert_eq!(loaded("").expect("no table").mcp().max_pending(), 16);
        assert_eq!(
            loaded("[mcp]\nmax_pending = 4\n")
                .expect("a stated cap")
                .mcp()
                .max_pending(),
            4
        );
    }

    #[test]
    fn adapter_and_grant_pins_are_validated_before_use() {
        let mut cfg = loaded("").expect("base config");
        cfg.grant_public_key = Some("04".to_string());
        assert!(matches!(
            cfg.validate(),
            Err(ConfigErr::InvalidGrantPublicKey)
        ));

        let mut cfg = loaded("").expect("base config");
        cfg.adapters.push(AdapterPin {
            id: "../socket".to_string(),
            manifest: "adapter.toml".to_string(),
            sha256: "00".repeat(32),
        });
        assert!(matches!(
            cfg.validate(),
            Err(ConfigErr::InvalidAdapterId { .. })
        ));

        let mut cfg = loaded("").expect("base config");
        cfg.adapters.push(AdapterPin {
            id: "adapter".to_string(),
            manifest: "adapter.toml".to_string(),
            sha256: "00".repeat(31),
        });
        assert!(matches!(
            cfg.validate(),
            Err(ConfigErr::InvalidAdapterPin { .. })
        ));
    }
}
