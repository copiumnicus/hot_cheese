//! The one advisory lock every store mutator takes, and the in-process mutex layered under it.
//!
//! `flock(2)` lives on the open file description, so the kernel drops it when this process
//! leaves — `SIGKILL` included — and a leftover lock file never blocks a later start. It also
//! means a second `open` inside THIS process conflicts with the claim the process already holds,
//! which is why the claim is taken once at the entry point and handed down, and why a background
//! task that needs exclusion against another background task takes [`Claim::mutate`] instead.
use err_mac::create_err_with_impls;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The file under the home dir whose `flock` is this install's claim on its store. It sits
/// outside the store because a forced pull runs `clean -fd` across the store and would delete a
/// lock file kept inside it while the process holding it was still running.
const STORE_LOCK: &str = ".store.lock";

create_err_with_impls!(
    #[derive(Debug)]
    pub FlockErr,
    StdIo(std::io::Error)
    ;
    Held { path: PathBuf },
    UnsafeFile { path: PathBuf }
);

/// An exclusive claim on one install's store.
pub struct Claim {
    _file: std::fs::File,
    /// Excludes this process's own background tasks from each other; the flock excludes other
    /// processes. Both are required and neither substitutes.
    mutations: parking_lot::Mutex<()>,
}

impl Claim {
    pub fn take(path: &Path) -> Result<Self, FlockErr> {
        let file = std::fs::File::options()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        // SAFETY: `geteuid` has no preconditions and changes no process state.
        let ours = unsafe { libc::geteuid() };
        if !metadata.file_type().is_file() || metadata.uid() != ours {
            return Err(FlockErr::UnsafeFile {
                path: path.to_path_buf(),
            });
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        match file.try_lock() {
            Ok(()) => Ok(Self {
                _file: file,
                mutations: parking_lot::Mutex::new(()),
            }),
            Err(std::fs::TryLockError::WouldBlock) => Err(FlockErr::Held {
                path: path.to_path_buf(),
            }),
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }

    /// Serialise one store mutation against every other in this process. The guard must never
    /// straddle an `.await`.
    pub fn mutate(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.mutations.lock()
    }
}

/// Claim this install's store for as long as the returned value lives.
pub fn store_claim() -> Result<Claim, FlockErr> {
    Claim::take(&hc_core::config::home_dir().join(STORE_LOCK))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn claim_is_owner_only_and_never_follows_a_symlink() {
        let root =
            std::env::temp_dir().join(format!("hot-cheese-store-lock-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let victim = root.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let link = root.join("lock-link");
        symlink(&victim, &link).unwrap();
        assert!(Claim::take(&link).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");

        let lock = root.join("lock");
        std::fs::write(&lock, b"").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o666)).unwrap();
        let claim = Claim::take(&lock).unwrap();
        assert_eq!(
            std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(matches!(Claim::take(&lock), Err(FlockErr::Held { .. })));
        drop(claim);
        let _ = std::fs::remove_dir_all(root);
    }
}
