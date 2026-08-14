//! The one advisory lock every store mutator takes, and the in-process mutex layered under it.
//!
//! `flock(2)` lives on the open file description, so the kernel drops it when this process
//! leaves — `SIGKILL` included — and a leftover lock file never blocks a later start. It also
//! means a second `open` inside THIS process conflicts with the claim the process already holds,
//! which is why the claim is taken once at the entry point and handed down, and why a background
//! task that needs exclusion against another background task takes [`Claim::mutate`] instead.
use err_mac::create_err_with_impls;
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
    Held { path: PathBuf }
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
            .open(path)?;
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
