//! One 0600 unix socket per adapter, and the stale-socket protocol guarding its path.
//!
//! TCP loopback is open to every local uid; a 0600 socket in a 0700 directory is not. Nothing
//! here authenticates anybody: `ssh -R` forwards into a unix socket just as it does into a
//! loopback port, and pids recycle, so the [`crate::PeerCred`] the accept loop reads and shows
//! the operator narrows the caller to "a process running as this uid" and nothing more, which
//! is why the prompt names it rather than trusting it. What an adapter socket DOES establish is
//! which adapter's manifest a request is evaluated against, because the daemon takes that from
//! the listener that accepted the connection and never from the request.
use err_mac::create_err_with_impls;
use hc_sign::manifest::LoadedManifest;
use std::fs::Permissions;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
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
    StdIo(io::Error),
    Flock(crate::flock::FlockErr)
    ;
    DaemonAlreadyListening { path: PathBuf },
    ProbeFailed { path: PathBuf, kind: io::ErrorKind },
    NotInADirectory { path: PathBuf },
    UnsafeDirectory { path: PathBuf },
    UnsafeSocket { path: PathBuf }
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

/// Ask a socket path whether a daemon is behind it. Startup only, so this is the blocking std
/// connect. A regular file, FIFO, directory or symlink is not a stale socket regardless of the
/// errno `connect` would return, and therefore fails before a connect is attempted.
pub fn probe(path: &Path) -> Probe {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Probe::Absent,
        Err(error) => return Probe::Failed(error.kind()),
        Ok(metadata) if !metadata.file_type().is_socket() => {
            return Probe::Failed(io::ErrorKind::InvalidInput)
        }
        Ok(_) => {}
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Probe::Answered,
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Probe::Refused,
        Err(e) => Probe::Failed(e.kind()),
    }
}

/// Claim `path` and bind it. The [`crate::flock::Claim`] covers the probe, the unlink and the
/// bind together: once this returns, any other daemon's probe of the path reaches THIS listener
/// and refuses, so a live socket can never be unlinked by a second start reading it as stale.
fn bind_socket(path: &Path) -> Result<(UnixListener, BoundPath), SocketErr> {
    let dir = path.parent().ok_or_else(|| SocketErr::NotInADirectory {
        path: path.to_path_buf(),
    })?;
    std::fs::create_dir_all(dir)?;
    let directory = std::fs::symlink_metadata(dir)?;
    // SAFETY: `geteuid` has no preconditions and changes no process state.
    let ours = unsafe { libc::geteuid() };
    if !directory.file_type().is_dir() || directory.uid() != ours {
        return Err(SocketErr::UnsafeDirectory {
            path: dir.to_path_buf(),
        });
    }
    std::fs::set_permissions(dir, Permissions::from_mode(DIR_MODE))?;
    let _claim = crate::flock::Claim::take(&dir.join(CLAIM_LOCK))?;
    let probed_identity = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if decide(path, probe(path))? == Bind::Unlink {
        // Bind the probe result to the pathname at the destructive step. A same-uid actor that
        // swaps the stale socket for any other inode loses the race by changing its identity or
        // type; a socket owned by another uid was never ours to remove.
        let stale = std::fs::symlink_metadata(path)?;
        let same = probed_identity
            .as_ref()
            .is_some_and(|probed| probed.dev() == stale.dev() && probed.ino() == stale.ino());
        if !same || !stale.file_type().is_socket() || stale.uid() != ours {
            return Err(SocketErr::UnsafeSocket {
                path: path.to_path_buf(),
            });
        }
        tracing::warn!(path = %path.display(), "unlinking an adapter socket left by a dead daemon");
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE))?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.uid() != ours {
        return Err(SocketErr::UnsafeSocket {
            path: path.to_path_buf(),
        });
    }
    Ok((
        listener,
        BoundPath {
            path: path.to_path_buf(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        },
    ))
}

struct BoundPath {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl BoundPath {
    fn matches(&self, metadata: &std::fs::Metadata) -> bool {
        metadata.dev() == self.dev && metadata.ino() == self.ino
    }
}

/// The socket files one session created. Shared with the signal task, which cannot rely on a
/// `Drop` the process never reaches.
pub struct SocketPaths {
    /// Bound socket paths, in bind order.
    paths: Vec<BoundPath>,
}

impl SocketPaths {
    /// Remove every socket file this session created. Idempotent: a path already gone is the
    /// normal case when both the signal task and the drop run.
    pub fn unlink(&self) {
        for bound in &self.paths {
            let same_socket = std::fs::symlink_metadata(&bound.path)
                .is_ok_and(|metadata| metadata.file_type().is_socket() && bound.matches(&metadata));
            if !same_socket {
                if std::fs::symlink_metadata(&bound.path).is_ok() {
                    tracing::warn!(path = %bound.path.display(), "adapter socket path no longer names this session's socket; leaving it intact");
                }
                continue;
            }
            match std::fs::remove_file(&bound.path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!(path = %bound.path.display(), error = %e, "could not unlink the adapter socket")
                }
            }
        }
    }
}

/// Every adapter socket this daemon bound. Dropping it unlinks them all, and every ending
/// `serve` can act on — a normal return, an error, SIGINT, SIGTERM, SIGHUP — reaches either that
/// drop or the signal task's own [`SocketPaths::unlink`]. `SIGKILL` cannot be caught by
/// anything, so it is the one ending that strands a socket, and the stale-socket protocol above
/// is what covers it.
pub struct AdapterSockets {
    /// Bound listeners, drained into their accept loops at startup.
    pub bound: Vec<(Arc<LoadedManifest>, UnixListener)>,
    /// The paths behind those listeners, also held by the signal task.
    pub paths: Arc<SocketPaths>,
}

impl AdapterSockets {
    /// Bind one socket per adapter. A failure part-way unlinks whatever was already bound,
    /// because the daemon is not starting.
    pub fn bind(adapters: Vec<LoadedManifest>) -> Result<Self, SocketErr> {
        let mut bound = Vec::with_capacity(adapters.len());
        let mut paths = SocketPaths {
            paths: Vec::with_capacity(adapters.len()),
        };
        for adapter in adapters {
            let path = adapter.socket();
            let (listener, owned_path) = match bind_socket(&path) {
                Ok(bound) => bound,
                Err(e) => {
                    paths.unlink();
                    return Err(e);
                }
            };
            tracing::info!(
                adapter = %adapter.manifest.id,
                manifest = %adapter.path.display(),
                sha256 = %hex::encode(adapter.digest),
                path = %path.display(),
                "adapter socket listening"
            );
            paths.paths.push(owned_path);
            bound.push((Arc::new(adapter), listener));
        }
        Ok(AdapterSockets {
            bound,
            paths: Arc::new(paths),
        })
    }
}

impl Drop for AdapterSockets {
    fn drop(&mut self) {
        self.paths.unlink();
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
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_socket_probe_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make the probe dir");
        assert_eq!(probe(&dir.join("nothing.sock")), Probe::Absent);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_socket_path_is_never_unlinked_as_stale() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_socket_type_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make socket directory");
        let path = dir.join("adapter.sock");
        std::fs::write(&path, b"operator data").expect("plant a regular file");

        assert_eq!(probe(&path), Probe::Failed(io::ErrorKind::InvalidInput));
        assert!(matches!(
            bind_socket(&path),
            Err(SocketErr::ProbeFailed {
                kind: io::ErrorKind::InvalidInput,
                ..
            })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"operator data");

        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Claiming a path is one step, so a second bind of a LIVE socket refuses instead of
    /// stealing it, and the first daemon is still the one reachable at that path afterwards.
    /// The file a dead daemon leaves behind stays rebindable, which is the only unlink there is.
    #[tokio::test]
    async fn a_second_bind_refuses_a_live_socket_and_leaves_it_reachable() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_socket_claim_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("adapter.sock");
        let (first, _) = bind_socket(&path).expect("the first bind claims the path");

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
        let _ = bind_socket(&path).expect("a socket no process is behind is rebindable");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Shutdown owns the inode it bound, not the pathname forever. If another same-uid actor
    /// removes that socket and installs a file at the name, cleanup must leave the replacement
    /// intact rather than turning an ordinary shutdown into a pathname deletion primitive.
    #[test]
    fn cleanup_does_not_unlink_a_replacement() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_socket_cleanup_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("adapter.sock");
        std::fs::create_dir_all(&dir).expect("make the socket directory");
        let original = std::fs::File::create(&path).expect("reserve the original inode");
        let metadata = original.metadata().expect("identify the original inode");
        let owned = BoundPath {
            path: path.clone(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        std::fs::remove_file(&path).expect("remove the socket path");
        std::fs::write(&path, b"replacement").expect("install a replacement");
        let replacement = std::fs::symlink_metadata(&path).expect("identify the replacement");
        assert!(
            !owned.matches(&replacement),
            "the still-open original inode cannot be reused for the replacement"
        );

        SocketPaths { paths: vec![owned] }.unlink();

        assert_eq!(
            std::fs::read(&path).expect("replacement survives"),
            b"replacement"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
