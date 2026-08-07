//! Automated rsync backups, namespaced per vault.
//!
//! Because the store is now an envelope (the DEK never appears in plaintext), the
//! whole store dir is safe to replicate to untrusted remotes. We replicate ONLY the
//! store directory — certs/keys live under the home dir (see `config::cert_paths`)
//! and are deliberately never synced.
//!
//! Every install owns a [`VaultId`] (cleartext in `keyring.json`) and replicates into
//! `<folder>/<vault_id>/`, so several installs with DIFFERENT DEKs can share one host
//! and folder without overwriting each other. A keyring written before vault ids has
//! none and keeps using the un-namespaced `<folder>/` exactly as before.
//!
//! Ports the old `examples/simple_backup.rs` (push) and `regenerate_from_backup.sh`
//! (pull), minus the `conf/` handling, since certs are no longer kept in the store.
use err_mac::create_err_with_impls;
use hc_core::config::{BackupRemote, Config};
use hc_core::keyring::{Keyring, KeyringErr, VaultId};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

create_err_with_impls!(
    #[derive(Debug)]
    pub BackupErr,
    // rsync exited with a non-zero status code.
    RsyncFailed(i32),
    // rsync was terminated by a signal (no exit code available).
    RsyncSignal,
    // ssh (remote listing / mkdir) was terminated by a signal.
    SshSignal,
    StdIo(std::io::Error),
    Keyring(KeyringErr)
    ;
    SshFailed { code: i32 },
    VaultMismatch { site: VaultSite, requested: Option<VaultId>, found: Option<VaultId> },
    AmbiguousRemoteTryPullVault { vaults: Vec<VaultId> },
    LocalKeyringMissing { store: PathBuf }
);

/// Which keyring disagreed about the vault a pull was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultSite {
    /// The keyring already in the local store dir (checked BEFORE rsync runs).
    LocalStore,
    /// The keyring the pull just wrote into the local store dir.
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

/// True if the store dir is missing or contains no entries yet.
pub fn store_absent(store: &Path) -> bool {
    match std::fs::read_dir(store) {
        Err(_) => true,
        Ok(mut it) => it.next().is_none(),
    }
}

/// Read the store's vault id from cleartext `keyring.json`. Unlocks nothing.
pub fn local_vault(store: &Path) -> Result<LocalVault, BackupErr> {
    let path = store.join(hc_core::keyring::KEYRING_FILE);
    if !path.exists() {
        return Ok(LocalVault::Absent);
    }
    match Keyring::load(&path)?.vault_id {
        Some(v) => Ok(LocalVault::Id(v)),
        None => Ok(LocalVault::Legacy),
    }
}

/// Refuse when a vault id is not the one that was asked for. `None` means "the
/// un-namespaced legacy vault", which is a DIFFERENT vault from any `v_…` id.
fn require_vault(
    site: VaultSite,
    requested: Option<&VaultId>,
    found: Option<&VaultId>,
) -> Result<(), BackupErr> {
    if requested == found {
        return Ok(());
    }
    Err(BackupErr::VaultMismatch {
        site,
        requested: requested.cloned(),
        found: found.cloned(),
    })
}

/// Render a directory path with exactly one trailing slash, regardless of whether the
/// input already had one — so rsync copies the dir's *contents* and we never emit `//`.
fn dir_with_trailing_slash(p: &Path) -> String {
    format!("{}/", p.display().to_string().trim_end_matches('/'))
}

/// `<host>:~/<folder>/<vault_id>/`, or `<host>:~/<folder>/` for a legacy keyring.
fn remote_dir(remote: &BackupRemote, vault: Option<&VaultId>) -> String {
    match vault {
        Some(v) => format!("{}:~/{}/{}/", remote.host, remote.folder, v),
        None => format!("{}:~/{}/", remote.host, remote.folder),
    }
}

/// Build the argv for a push (`rsync -az <local>/ <host>:~/<folder>/<vault_id>/`).
///
/// The trailing slash on the local source makes rsync copy the *contents* of the
/// store dir into the remote vault dir rather than nesting it one level deeper.
fn rsync_push_args(local: &Path, remote: &BackupRemote, vault: Option<&VaultId>) -> Vec<String> {
    vec![
        "-az".to_string(),
        dir_with_trailing_slash(local),
        remote_dir(remote, vault),
    ]
}

/// Build the argv for a pull (`rsync -az <host>:~/<folder>/<vault_id>/ <local>/`).
///
/// Trailing slashes on both ends copy the remote vault's contents straight into
/// the local store dir (bootstrap-from-backup).
fn rsync_pull_args(local: &Path, remote: &BackupRemote, vault: Option<&VaultId>) -> Vec<String> {
    vec![
        "-az".to_string(),
        remote_dir(remote, vault),
        dir_with_trailing_slash(local),
    ]
}

/// Run rsync with the given argv, mapping a non-zero/abnormal exit to `BackupErr`.
fn run_rsync(args: &[String]) -> Result<(), BackupErr> {
    let status = Command::new("rsync").args(args).status()?;
    if status.success() {
        return Ok(());
    }
    match status.code() {
        Some(code) => Err(BackupErr::RsyncFailed(code)),
        None => Err(BackupErr::RsyncSignal),
    }
}

/// Run a command on the remote over ssh and return its stdout. Remote stderr is
/// inherited so ssh's own diagnostics reach the operator's terminal.
fn ssh(remote: &BackupRemote, args: &[&str]) -> Result<Vec<u8>, BackupErr> {
    let out = Command::new("ssh")
        .arg(&remote.host)
        .args(args)
        .stderr(Stdio::inherit())
        .output()?;
    if out.status.success() {
        return Ok(out.stdout);
    }
    match out.status.code() {
        Some(code) => Err(BackupErr::SshFailed { code }),
        None => Err(BackupErr::SshSignal),
    }
}

/// Vault ids present in `<folder>` on the remote. Entries that are not `v_<32 hex>`
/// (a legacy un-namespaced backup's own files) are skipped. Unlocks nothing.
pub fn list_vaults(remote: &BackupRemote) -> Result<Vec<VaultId>, BackupErr> {
    let stdout = ssh(remote, &["ls", "-1", "--", remote.folder.as_str()])?;
    let mut vaults = Vec::new();
    for line in String::from_utf8_lossy(&stdout).lines() {
        if let Ok(v) = line.trim().parse::<VaultId>() {
            vaults.push(v);
        }
    }
    Ok(vaults)
}

/// The vault a pull should fetch: `explicit` when given, else this install's own id,
/// else — with no local keyring at all — the remote's single vault. More than one
/// candidate is never guessed at.
pub fn pull_vault(
    cfg: &Config,
    remote: &BackupRemote,
    explicit: Option<VaultId>,
) -> Result<Option<VaultId>, BackupErr> {
    if explicit.is_some() {
        return Ok(explicit);
    }
    match local_vault(&cfg.store_path())? {
        LocalVault::Id(v) => Ok(Some(v)),
        LocalVault::Legacy => Ok(None),
        LocalVault::Absent => {
            let mut vaults = list_vaults(remote)?;
            if vaults.len() > 1 {
                return Err(BackupErr::AmbiguousRemoteTryPullVault { vaults });
            }
            Ok(vaults.pop())
        }
    }
}

/// Push the local store into this install's vault dir on a single remote.
fn push(cfg: &Config, remote: &BackupRemote, vault: Option<&VaultId>) -> Result<(), BackupErr> {
    let local = cfg.store_path();
    if let Some(v) = vault {
        ssh(
            remote,
            &["mkdir", "-p", "--", &format!("{}/{}", remote.folder, v)],
        )?;
    }
    let args = rsync_push_args(&local, remote, vault);
    tracing::info!(host = %remote.host, folder = %remote.folder, vault = ?vault, "rsync push");
    run_rsync(&args)
}

/// Pull one vault from a remote into the local store dir (bootstrap-from-backup).
///
/// Refuses BEFORE rsync runs if the local store already belongs to another vault:
/// `rsync -az` has no `--delete`, so the pull would merge, leaving keystores this
/// install's DEK cannot open. Refusing is safer than deleting. After rsync it
/// re-reads the pulled keyring and refuses if it is not the vault that was asked for.
pub fn pull(cfg: &Config, remote: &BackupRemote, vault: Option<&VaultId>) -> Result<(), BackupErr> {
    let local = cfg.store_path();
    let existing = local_vault(&local)?;
    if existing != LocalVault::Absent {
        require_vault(VaultSite::LocalStore, vault, existing.id())?;
    }
    std::fs::create_dir_all(&local)?;
    let args = rsync_pull_args(&local, remote, vault);
    tracing::info!(host = %remote.host, folder = %remote.folder, vault = ?vault, "rsync pull");
    run_rsync(&args)?;
    require_vault(VaultSite::Pulled, vault, local_vault(&local)?.id())
}

/// Push the store to every configured remote.
///
/// Best-effort by design: a failure against one remote (unreachable host, rsync
/// error) must not block replication to the others, so each failure is logged via
/// `tracing::warn!` and we continue. With no remotes configured this is a no-op.
/// Returns `Ok(())` as long as every configured remote was attempted; the warnings
/// are the failure signal.
pub fn push_all(cfg: &Config) -> Result<(), BackupErr> {
    if cfg.backup_remotes.is_empty() {
        return Ok(());
    }
    let store = cfg.store_path();
    let vault = local_vault(&store)?;
    if vault == LocalVault::Absent {
        return Err(BackupErr::LocalKeyringMissing { store });
    }
    for remote in &cfg.backup_remotes {
        if let Err(e) = push(cfg, remote, vault.id()) {
            tracing::warn!(
                host = %remote.host,
                folder = %remote.folder,
                error = %e,
                "backup push to remote failed; continuing with other remotes",
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote() -> BackupRemote {
        BackupRemote {
            host: "user@1.2.3.4".to_string(),
            folder: "hot_cheese_store".to_string(),
        }
    }

    fn vault() -> VaultId {
        "v_0f1e2d3c4b5a69788796a5b4c3d2e1f0"
            .parse()
            .expect("fixed vault id parses")
    }

    #[test]
    fn push_args_land_in_the_vault_subtree() {
        let v = vault();
        let args = rsync_push_args(Path::new("/var/store"), &remote(), Some(&v));
        assert_eq!(
            args,
            vec![
                "-az".to_string(),
                "/var/store/".to_string(),
                "user@1.2.3.4:~/hot_cheese_store/v_0f1e2d3c4b5a69788796a5b4c3d2e1f0/".to_string(),
            ]
        );
    }

    #[test]
    fn pull_args_reverse_source_and_dest() {
        let v = vault();
        let args = rsync_pull_args(Path::new("/var/store"), &remote(), Some(&v));
        assert_eq!(
            args,
            vec![
                "-az".to_string(),
                "user@1.2.3.4:~/hot_cheese_store/v_0f1e2d3c4b5a69788796a5b4c3d2e1f0/".to_string(),
                "/var/store/".to_string(),
            ]
        );
    }

    /// A keyring with no vault id keeps the pre-vault layout: the folder root itself.
    #[test]
    fn legacy_keyring_keeps_the_unnamespaced_layout() {
        let push = rsync_push_args(Path::new("/var/store"), &remote(), None);
        let pull = rsync_pull_args(Path::new("/var/store"), &remote(), None);
        assert_eq!(push[2], "user@1.2.3.4:~/hot_cheese_store/");
        assert_eq!(pull[1], "user@1.2.3.4:~/hot_cheese_store/");
    }

    /// The remote spec must land under `~/` (home-relative), not absolute or bare.
    #[test]
    fn remote_dest_is_home_relative() {
        let v = vault();
        let dest = &rsync_push_args(Path::new("/s"), &remote(), Some(&v))[2];
        assert!(dest.starts_with("user@1.2.3.4:~/"));
        assert!(dest.ends_with("/hot_cheese_store/v_0f1e2d3c4b5a69788796a5b4c3d2e1f0/"));
    }

    /// Source must keep a single trailing slash even when the path already lacks one,
    /// so rsync copies contents rather than nesting the dir.
    #[test]
    fn source_trailing_slash_independent_of_input() {
        let v = vault();
        let with = rsync_push_args(Path::new("/store/"), &remote(), Some(&v));
        let without = rsync_push_args(Path::new("/store"), &remote(), Some(&v));
        assert_eq!(with[1], "/store/");
        assert_eq!(without[1], "/store/");
    }

    /// Sharing one folder is only safe if a pull that lands on the wrong vault is
    /// refused, in both directions: a store already holding another vault, and a
    /// remote that handed back another vault's keyring. Legacy (no id) is its own
    /// vault, so it must not silently absorb — or be absorbed by — a namespaced one.
    #[test]
    fn a_pull_refuses_every_vault_but_the_requested_one() {
        let mine = vault();
        let theirs: VaultId = "v_ffeeddccbbaa99887766554433221100"
            .parse()
            .expect("other vault id parses");

        require_vault(VaultSite::LocalStore, Some(&mine), Some(&mine)).expect("same vault passes");
        require_vault(VaultSite::Pulled, None, None).expect("legacy to legacy passes");

        match require_vault(VaultSite::Pulled, Some(&mine), Some(&theirs)) {
            Err(BackupErr::VaultMismatch {
                site,
                requested,
                found,
            }) => {
                assert_eq!(site, VaultSite::Pulled);
                assert_eq!(requested, Some(mine.clone()));
                assert_eq!(found, Some(theirs.clone()));
            }
            other => panic!("expected a mismatch, got {:?}", other),
        }

        assert!(require_vault(VaultSite::LocalStore, Some(&mine), Some(&theirs)).is_err());
        assert!(require_vault(VaultSite::LocalStore, Some(&mine), None).is_err());
        assert!(require_vault(VaultSite::LocalStore, None, Some(&theirs)).is_err());
    }

    #[test]
    fn store_absent_true_for_missing_dir() {
        let p = std::env::temp_dir().join("hot_cheese_nope_does_not_exist_xyz");
        let _ = std::fs::remove_dir_all(&p);
        assert!(store_absent(&p));
    }

    #[test]
    fn store_absent_false_when_populated() {
        let dir = std::env::temp_dir().join(format!("hc_backup_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk test dir");
        std::fs::write(dir.join("keyring.json"), b"{}").expect("write test file");
        assert!(!store_absent(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
