//! One 0600 unix socket per adapter, and the stale-socket protocol guarding its path.
//!
//! TCP loopback is open to every local uid; a 0600 socket in a 0700 directory is not. Nothing
//! here authenticates anybody: `ssh -R` forwards into a unix socket just as it does into a
//! loopback port, and pids recycle, so the peer credentials this logs narrow the caller to "a
//! process running as this uid" and nothing more. What an adapter socket DOES establish is
//! which adapter's manifest a request is evaluated against, because the daemon takes that from
//! the listener that accepted the connection and never from the request.
use err_mac::create_err_with_impls;
use hc_sign::manifest::LoadedManifest;
use std::fs::Permissions;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixListener;

/// Mode of `<home>/adapters`: only this uid may reach the paths inside it, which is what
/// closes the window between `bind` and the socket's own chmod.
const DIR_MODE: u32 = 0o700;

/// Mode of an adapter socket: connectable by this uid alone.
const SOCKET_MODE: u32 = 0o600;

/// The file in the adapters directory whose `flock` serialises the whole probe-and-bind.
const CLAIM_LOCK: &str = ".claim.lock";

create_err_with_impls!(
    #[derive(Debug)]
    pub SocketErr,
    StdIo(io::Error)
    ;
    DaemonAlreadyListening { path: PathBuf },
    ProbeFailed { path: PathBuf, kind: io::ErrorKind },
    ClaimHeld { path: PathBuf },
    NotInADirectory { path: PathBuf }
);

/// What connecting to an existing socket path revealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// Nothing is at the path.
    Absent,
    /// A connect succeeded: another daemon is live on it.
    Answered,
    /// The path exists and nothing is listening (`ECONNREFUSED`).
    Refused,
    /// The connect failed some other way, so the path is not ours to interpret.
    Failed(io::ErrorKind),
}

/// What to do with the path before binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bind {
    /// Bind straight away.
    Fresh,
    /// Unlink the socket a dead daemon left behind, then bind.
    Unlink,
}

/// The stale-socket decision, taken under the directory [`claim`] so that the probe it reads
/// cannot go out of date before the unlink and the bind that act on it. A path that answers
/// belongs to a live daemon, so this one refuses to start rather than stealing its adapters;
/// only a refused connect proves the file outlived its process. Nothing else unlinks anything.
pub fn decide(path: &Path, probe: Probe) -> Result<Bind, SocketErr> {
    match probe {
        Probe::Absent => Ok(Bind::Fresh),
        Probe::Refused => Ok(Bind::Unlink),
        Probe::Answered => Err(SocketErr::DaemonAlreadyListening {
            path: path.to_path_buf(),
        }),
        Probe::Failed(kind) => Err(SocketErr::ProbeFailed {
            path: path.to_path_buf(),
            kind,
        }),
    }
}

/// Ask the path whether a daemon is behind it. Startup only, so this is the blocking std
/// connect. A dangling symlink counts as present and then fails its connect, which lands in
/// [`Probe::Failed`] and refuses to start.
pub fn probe(path: &Path) -> Probe {
    if std::fs::symlink_metadata(path).is_err() {
        return Probe::Absent;
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Probe::Answered,
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Probe::Refused,
        Err(e) => Probe::Failed(e.kind()),
    }
}

/// Hold the adapters directory against every other daemon for as long as the returned file is
/// open. The lock lives on the descriptor and not on the name, so the kernel drops it when this
/// process leaves — `SIGKILL` included — and a leftover lock file never blocks a later start.
fn claim(dir: &Path) -> Result<std::fs::File, SocketErr> {
    let path = dir.join(CLAIM_LOCK);
    let file = std::fs::File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(SocketErr::ClaimHeld { path }),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// Claim `path` and bind it. The [`claim`] covers the probe, the unlink and the bind together:
/// once this returns, any other daemon's probe of the path reaches THIS listener and refuses,
/// so a live socket can never be unlinked by a second start reading it as stale.
fn bind_socket(path: &Path) -> Result<UnixListener, SocketErr> {
    let dir = path.parent().ok_or_else(|| SocketErr::NotInADirectory {
        path: path.to_path_buf(),
    })?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, Permissions::from_mode(DIR_MODE))?;
    let _claim = claim(dir)?;
    if decide(path, probe(path))? == Bind::Unlink {
        tracing::warn!(path = %path.display(), "unlinking an adapter socket left by a dead daemon");
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE))?;
    Ok(listener)
}

/// Every adapter socket this daemon bound. Dropping it unlinks them all, and every ending
/// `serve` can act on — a normal return, an error, SIGINT, SIGTERM, SIGHUP — reaches that drop.
/// `SIGKILL` cannot be caught by anything, so it is the one ending that strands a socket, and
/// the stale-socket protocol above is what covers it.
pub struct AdapterSockets {
    /// Bound listeners, drained into their accept loops at startup.
    pub bound: Vec<(Arc<LoadedManifest>, UnixListener)>,
    paths: Vec<PathBuf>,
}

impl AdapterSockets {
    /// Bind one socket per adapter. A failure part-way unlinks whatever was already bound,
    /// because the daemon is not starting.
    pub fn bind(adapters: Vec<LoadedManifest>) -> Result<Self, SocketErr> {
        let mut sockets = AdapterSockets {
            bound: Vec::with_capacity(adapters.len()),
            paths: Vec::with_capacity(adapters.len()),
        };
        for adapter in adapters {
            let path = adapter.socket();
            let listener = bind_socket(&path)?;
            tracing::info!(
                adapter = %adapter.manifest.id,
                manifest = %adapter.path.display(),
                sha256 = %hex::encode(adapter.digest),
                path = %path.display(),
                "adapter socket listening"
            );
            sockets.paths.push(path);
            sockets.bound.push((Arc::new(adapter), listener));
        }
        Ok(sockets)
    }
}

impl Drop for AdapterSockets {
    fn drop(&mut self) {
        for path in &self.paths {
            if let Err(e) = std::fs::remove_file(path) {
                tracing::warn!(path = %path.display(), error = %e, "could not unlink the adapter socket");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole protocol: a socket that answers is another daemon's, so this one refuses to
    /// start; only a refused connect licenses an unlink; anything else is left alone. Getting
    /// this backwards would let a second daemon silently steal a live adapter's socket.
    #[test]
    fn only_a_refused_connect_licenses_an_unlink() {
        let path = Path::new("/tmp/hot_cheese_never_bound.sock");
        assert_eq!(decide(path, Probe::Absent).expect("bind"), Bind::Fresh);
        assert_eq!(decide(path, Probe::Refused).expect("bind"), Bind::Unlink);
        assert!(matches!(
            decide(path, Probe::Answered),
            Err(SocketErr::DaemonAlreadyListening { .. })
        ));
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotFound,
            io::ErrorKind::ConnectionReset,
        ] {
            assert!(
                matches!(
                    decide(path, Probe::Failed(kind)),
                    Err(SocketErr::ProbeFailed { .. })
                ),
                "{kind:?} must never unlink"
            );
        }
    }

    /// A path nothing ever bound must read as absent rather than as a dead daemon's leftovers.
    #[test]
    fn an_unused_path_probes_absent() {
        let dir = std::env::temp_dir().join("hot_cheese_socket_probe_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make the probe dir");
        assert_eq!(probe(&dir.join("nothing.sock")), Probe::Absent);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Claiming a path is one step, so a second bind of a LIVE socket refuses instead of
    /// stealing it, and the first daemon is still the one reachable at that path afterwards.
    /// The file a dead daemon leaves behind stays rebindable, which is the only unlink there is.
    #[tokio::test]
    async fn a_second_bind_refuses_a_live_socket_and_leaves_it_reachable() {
        let dir = std::env::temp_dir().join("hot_cheese_socket_claim_test");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("adapter.sock");
        let first = bind_socket(&path).expect("the first bind claims the path");

        assert!(matches!(
            bind_socket(&path),
            Err(SocketErr::DaemonAlreadyListening { .. })
        ));

        let client = tokio::net::UnixStream::connect(&path)
            .await
            .expect("the path still leads somewhere");
        let (served, _) = first
            .accept()
            .await
            .expect("and it leads to the FIRST listener, not a replacement");
        drop((client, served));

        drop(first);
        assert!(path.exists(), "a dropped listener leaves its file behind");
        bind_socket(&path).expect("a socket no process is behind is rebindable");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
