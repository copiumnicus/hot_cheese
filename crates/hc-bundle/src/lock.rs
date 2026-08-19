//! Cross-process exclusion for the local bundle tree.
use err_mac::create_err_with_impls;
use hc_core::config::home_dir;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const BUNDLE_LOCK: &str = ".bundles.lock";

/// How long a claim waits for the process that holds it. No transfer runs under this lock, so
/// every holder is doing bounded local filesystem work; waiting through that is what keeps a
/// second process from failing a `collect` the operator has already approved with a biometric.
const WAIT: Duration = Duration::from_secs(10);
const RETRY: Duration = Duration::from_millis(20);

create_err_with_impls!(
    #[derive(Debug)]
    pub LockErr,
    StdIo(std::io::Error)
    ;
    Held { path: PathBuf },
    UnsafeFile { path: PathBuf }
);

pub struct Lock {
    _file: std::fs::File,
}

impl Lock {
    pub fn take() -> Result<Self, LockErr> {
        std::fs::create_dir_all(home_dir())?;
        Self::take_at(&home_dir().join(BUNDLE_LOCK), WAIT)
    }

    fn take_at(path: &Path, wait: Duration) -> Result<Self, LockErr> {
        let file = std::fs::File::options()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let meta = file.metadata()?;
        // SAFETY: `geteuid` has no preconditions and changes no process state.
        let ours = unsafe { libc::geteuid() };
        if !meta.file_type().is_file() || meta.uid() != ours {
            return Err(LockErr::UnsafeFile {
                path: path.to_path_buf(),
            });
        }
        if meta.mode() & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let deadline = Instant::now() + wait;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(RETRY)
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(LockErr::Held {
                        path: path.to_path_buf(),
                    })
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_process_description_cannot_enter_the_bundle_mutation() {
        let path = std::env::temp_dir().join(format!(
            "hot-cheese-bundle-lock-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let first = Lock::take_at(&path, Duration::ZERO).expect("first claim");
        assert!(matches!(
            Lock::take_at(&path, Duration::from_millis(50)),
            Err(LockErr::Held { .. })
        ));
        drop(first);
        Lock::take_at(&path, Duration::ZERO).expect("released claim");
        let _ = std::fs::remove_file(path);
    }
}
