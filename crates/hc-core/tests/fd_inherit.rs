//! Descriptor inheritance across `exec`, in a test binary of its own.
//!
//! The control arm below deliberately leaves a listening socket inheritable for the length of one
//! spawn. A sibling test forking in that window would capture it too and make the hardened arm
//! meaningless, so this file holds exactly one test and every other spawning test in the workspace
//! runs in a different process.
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// A listener in the state Darwin's socket paths leave one in between `socket(2)` and the `fcntl`
/// that marks it close-on-exec.
fn inheritable_listener(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).expect("bind the probe listener");
    // SAFETY: `listener` owns the descriptor for the whole call, and `F_SETFD` only rewrites its
    // close-on-exec flag.
    let cleared = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_SETFD, 0) };
    assert_eq!(cleared, 0, "clear close-on-exec on the probe listener");
    listener
}

/// A child that holds whatever it inherited until its stdin closes.
fn holder() -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("IFS= read -r _hold || :")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn reap(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Whether a path still leads to a live listener, which is exactly how the daemon tells a stale
/// socket from another instance.
fn reachable(path: &Path) -> bool {
    UnixStream::connect(path).is_ok()
}

/// A child spawned through `close_inherited_fds_on_exec` keeps no descriptor above stdio: an
/// ordinary child leaves the dropped listener answering connects and a hardened one does not,
/// while marking rather than closing keeps std's own exec-failure report working.
#[test]
fn a_spawned_child_inherits_no_listener_and_still_reports_a_missing_program() {
    let dir = std::env::temp_dir().join(format!("hc_fd_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("make the probe directory");
    let plain = dir.join("a.sock");
    let hardened = dir.join("b.sock");

    let listener = inheritable_listener(&plain);
    let plain_child = holder().spawn().expect("spawn the control child");
    drop(listener);
    let plain_reachable = reachable(&plain);

    let listener = inheritable_listener(&hardened);
    let mut command = holder();
    hc_core::close_inherited_fds_on_exec(&mut command);
    let hardened_child = command.spawn().expect("spawn the hardened child");
    drop(listener);
    let hardened_reachable = reachable(&hardened);

    reap(plain_child);
    reap(hardened_child);

    let mut missing = Command::new(dir.join("no_such_program"));
    hc_core::close_inherited_fds_on_exec(&mut missing);
    let refused = missing
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        plain_reachable,
        "the control child failed to capture the listener, so this test proves nothing"
    );
    assert!(
        !hardened_reachable,
        "a hardened child kept the listening socket alive past its exec"
    );
    assert_eq!(
        refused
            .expect_err("a program that does not exist cannot spawn")
            .kind(),
        std::io::ErrorKind::NotFound,
        "closing rather than marking would have taken std's exec-failure pipe with it"
    );
}
