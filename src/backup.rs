//! Automated rsync backups.
//!
//! Because the store is now an envelope (the DEK never appears in plaintext), the
//! whole store dir is safe to replicate to untrusted remotes. We replicate ONLY the
//! store directory — certs/keys live under the home dir (see `config::cert_paths`)
//! and are deliberately never synced.
//!
//! Ports the old `examples/simple_backup.rs` (push) and `regenerate_from_backup.sh`
//! (pull), minus the `conf/` handling, since certs are no longer kept in the store.
use crate::config::{BackupRemote, Config};
use err_mac::create_err_with_impls;
use std::path::Path;
use std::process::Command;

create_err_with_impls!(
    #[derive(Debug)]
    pub BackupErr,
    NoRemotes,
    // rsync exited with a non-zero status code.
    RsyncFailed(i32),
    // rsync was terminated by a signal (no exit code available).
    RsyncSignal,
    StdIo(std::io::Error)
    ;
);

/// True if the store dir is missing or contains no entries yet.
pub fn store_absent(store: &Path) -> bool {
    match std::fs::read_dir(store) {
        Err(_) => true,
        Ok(mut it) => it.next().is_none(),
    }
}

/// Render a directory path with exactly one trailing slash, regardless of whether the
/// input already had one — so rsync copies the dir's *contents* and we never emit `//`.
fn dir_with_trailing_slash(p: &Path) -> String {
    format!("{}/", p.display().to_string().trim_end_matches('/'))
}

/// Build the argv for a push (`rsync -az <local>/ <host>:~/<folder>/`).
///
/// The trailing slash on the local source makes rsync copy the *contents* of the
/// store dir into the remote folder rather than nesting it one level deeper.
fn rsync_push_args(local: &Path, remote: &BackupRemote) -> Vec<String> {
    vec![
        "-az".to_string(),
        dir_with_trailing_slash(local),
        format!("{}:~/{}/", remote.host, remote.folder),
    ]
}

/// Build the argv for a pull (`rsync -az <host>:~/<folder>/ <local>/`).
///
/// Trailing slashes on both ends copy the remote folder's contents straight into
/// the local store dir (bootstrap-from-backup).
fn rsync_pull_args(local: &Path, remote: &BackupRemote) -> Vec<String> {
    vec![
        "-az".to_string(),
        format!("{}:~/{}/", remote.host, remote.folder),
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

/// Push the local store to a single remote.
pub fn push(cfg: &Config, remote: &BackupRemote) -> Result<(), BackupErr> {
    let local = cfg.store_path();
    let args = rsync_push_args(&local, remote);
    tracing::info!(host = %remote.host, folder = %remote.folder, "rsync push");
    run_rsync(&args)
}

/// Pull the store from a remote into the local store dir (bootstrap-from-backup).
pub fn pull(cfg: &Config, remote: &BackupRemote) -> Result<(), BackupErr> {
    let local = cfg.store_path();
    std::fs::create_dir_all(&local)?;
    let args = rsync_pull_args(&local, remote);
    tracing::info!(host = %remote.host, folder = %remote.folder, "rsync pull");
    run_rsync(&args)
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
    for remote in &cfg.backup_remotes {
        if let Err(e) = push(cfg, remote) {
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

    #[test]
    fn push_args_have_trailing_slash_source_and_host_dest() {
        let args = rsync_push_args(Path::new("/var/store"), &remote());
        assert_eq!(
            args,
            vec![
                "-az".to_string(),
                "/var/store/".to_string(),
                "user@1.2.3.4:~/hot_cheese_store/".to_string(),
            ]
        );
    }

    #[test]
    fn pull_args_reverse_source_and_dest() {
        let args = rsync_pull_args(Path::new("/var/store"), &remote());
        assert_eq!(
            args,
            vec![
                "-az".to_string(),
                "user@1.2.3.4:~/hot_cheese_store/".to_string(),
                "/var/store/".to_string(),
            ]
        );
    }

    /// The remote spec must land under `~/` (home-relative), not absolute or bare.
    #[test]
    fn remote_dest_is_home_relative() {
        let dest = &rsync_push_args(Path::new("/s"), &remote())[2];
        assert!(dest.starts_with("user@1.2.3.4:~/"));
        assert!(dest.ends_with("/hot_cheese_store/"));
    }

    /// Source must keep a single trailing slash even when the path already lacks one,
    /// so rsync copies contents rather than nesting the dir.
    #[test]
    fn source_trailing_slash_independent_of_input() {
        let with = rsync_push_args(Path::new("/store/"), &remote());
        let without = rsync_push_args(Path::new("/store"), &remote());
        // `dir_with_trailing_slash` strips any existing trailing slash, so both yield exactly one.
        assert_eq!(with[1], "/store/");
        assert_eq!(without[1], "/store/");
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
