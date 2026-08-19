//! The key core: the DEK envelope, the keyring, the Secure Enclave / passphrase unlockers,
//! and the on-disk locations they use. Synchronous and runtime-free, so it builds for iOS.
pub mod config;
pub mod crypto;
pub mod keyring;
pub mod mac;
pub mod share;
pub mod solana;
pub mod unlock;
pub mod wire;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

pub const MAX_NAME_BYTES: usize = 64;
/// Files a valid key store may contain, shared by backup, bootstrap, migration and listings.
pub const MAX_STORE_FILES: usize = 2048;
/// Bytes a valid key store may contain.
pub const MAX_STORE_BYTES: u64 = 128 * 1024 * 1024;
/// Junk names are not valid store files, but enumerating millions of them is still work. This
/// ceiling gives legitimate files headroom while bounding every whole-store directory pass.
pub const MAX_STORE_ENUM_ENTRIES: usize = MAX_STORE_FILES * 2;

/// Render a bounded external diagnostic as inert ASCII. Child stderr can be controlled by a
/// remote SSH host or repository and eventually reaches a terminal through tracing or the
/// console; escaping every non-printable/non-ASCII scalar prevents CSI/OSC, bidi and newline
/// injection while retaining enough text to diagnose the failure.
pub fn safe_diagnostic(bytes: &[u8]) -> String {
    const DISPLAY_BYTES: usize = 4096;
    const DISPLAY_CHARS: usize = 8192;
    let kept = &bytes[..bytes.len().min(DISPLAY_BYTES)];
    let mut rendered: String = String::from_utf8_lossy(kept)
        .chars()
        .flat_map(char::escape_default)
        .take(DISPLAY_CHARS)
        .collect();
    if bytes.len() > kept.len() {
        rendered.push_str("...[truncated]");
    }
    rendered
}

/// String counterpart to [`safe_diagnostic`].
pub fn safe_diagnostic_text(text: &str) -> String {
    safe_diagnostic(text.as_bytes())
}

/// Read at most `max` bytes from an untrusted stream. One extra byte is consumed only to
/// distinguish an exactly-full input from an oversized one; the returned buffer is always
/// bounded. Callers that need a domain-specific size error can implement the same pattern.
pub fn read_bounded<R: Read>(reader: R, max: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("input exceeds {max} bytes"),
        ));
    }
    Ok(bytes)
}

/// Open and boundedly read one file. The handle, rather than a separate metadata/read pair,
/// carries the ceiling through growth or replacement races.
pub fn read_file_bounded(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    read_bounded(std::fs::File::open(path)?, max)
}

/// Open a regular file without following its final symlink. `O_NONBLOCK` matters before the
/// file type is known: opening an attacker-planted FIFO for an ordinary read would otherwise
/// wait forever before the caller could reject it.
pub fn open_regular_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("not a regular file: {}", path.display()),
        ));
    }
    Ok(file)
}

/// No-follow, regular-file counterpart to [`read_file_bounded`] for files whose pathname is a
/// trust boundary (config, policies, manifests, keystores, and peer-synchronised bundles).
pub fn read_regular_file_bounded(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    read_bounded(open_regular_file(path)?, max)
}

/// Whether a file is regular, owned by the effective uid, and closed to group and other.
pub fn is_owner_only_regular(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: `geteuid` has no preconditions and changes no process state.
    let ours = unsafe { libc::geteuid() };
    metadata.file_type().is_file()
        && metadata.uid() == ours
        && metadata.permissions().mode() & 0o077 == 0
}

/// Open an owner-only regular file without following a final symlink and read it boundedly into
/// memory that is wiped on drop. This is the common boundary for private key material.
///
/// The wiped buffer is sized up front from `max` alone, which is exactly what the read is capped
/// at, so it can never grow: a reallocation mid-read would leave an unwiped copy of every byte
/// read so far on the heap, and a writer that grew the file after a metadata-derived size was
/// taken would force one. Every caller's `max` is a private-key ceiling of at most a mebibyte,
/// so paying it up front is cheaper than the residue.
pub fn read_private_file_bounded(path: &Path, max: u64) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let file = open_regular_file(path)?;
    let metadata = file.metadata()?;
    if !is_owner_only_regular(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "private file must be regular, owned by this user, and mode 0600: {}",
                path.display()
            ),
        ));
    }
    let capacity = usize::try_from(max.saturating_add(1)).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private file does not fit in an in-memory buffer",
        )
    })?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("input exceeds {max} bytes"),
        ));
    }
    Ok(bytes)
}

/// Apply a kernel-enforced per-file write ceiling to a child and every descendant it starts.
/// Ignoring `SIGXFSZ` makes an over-limit write return an ordinary error, giving well-behaved
/// tools a chance to remove their incomplete temporary file before they exit.
pub fn limit_child_file_size(command: &mut std::process::Command, max: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let max = libc::rlim_t::try_from(max).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "child file-size limit does not fit rlim_t",
            )
        })?;
        // SAFETY: the closure runs after fork and before exec, captures only one integer, and
        // calls async-signal-safe libc functions. The resource limit affects only the child and
        // its descendants.
        unsafe {
            command.pre_exec(move || {
                if libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
                let limit = libc::rlimit {
                    rlim_cur: max,
                    rlim_max: max,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (command, max);
    Ok(())
}

/// Run a child while draining both output pipes concurrently and retaining only bounded
/// buffers. Closing an over-limit pipe also prevents a verbose child from continuing to feed
/// memory through `Command::output()`'s otherwise-unbounded collector.
pub fn output_bounded(
    command: &mut std::process::Command,
    stdout_max: u64,
    stderr_max: u64,
) -> std::io::Result<std::process::Output> {
    output_bounded_inner(command, stdout_max, stderr_max, None, None)
}

/// [`output_bounded`] with a wall-clock deadline. The child starts in its own process group so
/// timing out an `rsync` also kills the `ssh` it spawned; otherwise a grandchild retaining one of
/// the pipes could make the reader threads wait forever after the direct child was killed.
pub fn output_bounded_timeout(
    command: &mut std::process::Command,
    stdout_max: u64,
    stderr_max: u64,
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    output_bounded_inner(command, stdout_max, stderr_max, Some(timeout), None)
}

/// [`output_bounded_timeout`] with an aggregate physical-memory ceiling for the child process
/// group. This is used at trust boundaries where a parser in a subprocess can expand a compact
/// hostile input before the caller gets a chance to validate its logical size.
///
/// macOS's `RLIMIT_RSS` is advisory, so the parent measures every member of the process group
/// with `proc_pid_rusage(3)` and kills the whole group when their combined physical memory crosses
/// `memory_max`. The ceiling remains active after the direct child exits while descendants retain
/// either output pipe. The ordinary wall deadline remains in force as well.
pub fn output_bounded_timeout_memory(
    command: &mut std::process::Command,
    stdout_max: u64,
    stderr_max: u64,
    timeout: Duration,
    memory_max: u64,
) -> std::io::Result<std::process::Output> {
    output_bounded_inner(
        command,
        stdout_max,
        stderr_max,
        Some(timeout),
        Some(memory_max),
    )
}

/// A tiny, independent process that is both a parent-death watcher and the permanent leader of
/// an owned subprocess group. Keeping the leader alive until cleanup is important: once a normal
/// child has been reaped, its numeric pid can otherwise be reused before a later whole-group
/// kill. Commands configured through this guard join the watcher's still-live group, so its id
/// cannot be recycled while any cleanup operation can address it.
///
/// EOF means the parent died and makes the watcher kill its own group. An explicit termination
/// line takes the same path on ordinary cleanup. This complements Rust destructors, which do not
/// run after `process::exit`, SIGKILL, a crash, or the default action for Ctrl-C. The watcher
/// ignores terminal/session shutdown signals long enough to observe its pipe, has an empty
/// environment, and uses only fixed absolute command paths.
#[derive(Debug)]
pub struct ParentDeathGuard {
    watcher: Option<Child>,
    input: Option<ChildStdin>,
    process_group: libc::pid_t,
}

impl ParentDeathGuard {
    const SCRIPT: &'static str = r#"
trap '' HUP INT TERM QUIT
IFS= read -r _terminate || :
/bin/kill -KILL -- "-$$" 2>/dev/null
"#;

    /// Start the group leader before the protected command is spawned, eliminating the interval
    /// in which a child can exist without a process capable of cleaning up after it.
    pub fn start() -> std::io::Result<Self> {
        #[cfg(unix)]
        use std::os::unix::process::CommandExt;

        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(Self::SCRIPT)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        command.process_group(0);
        let mut watcher = command.spawn()?;
        let process_group = match libc::pid_t::try_from(watcher.id()) {
            Ok(process_group) if process_group > 0 => process_group,
            _ => {
                let _ = watcher.kill();
                let _ = watcher.wait();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "parent-death watcher pid does not fit pid_t",
                ));
            }
        };
        let Some(input) = watcher.stdin.take() else {
            let _ = watcher.kill();
            let _ = watcher.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "parent-death watcher had no control pipe",
            ));
        };
        Ok(Self {
            watcher: Some(watcher),
            input: Some(input),
            process_group,
        })
    }

    /// Make `command` join this still-live, owned process group immediately before `exec`.
    pub fn configure(&self, command: &mut std::process::Command) {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(self.process_group);
        }
    }

    /// Stable id of the live sentinel's process group, for bounded resource accounting.
    pub fn process_group_id(&self) -> u32 {
        self.process_group as u32
    }

    /// Kill every remaining group member and reap the sentinel. This is idempotent so error paths
    /// can invoke it eagerly and still let Drop run safely.
    pub fn terminate_group(&mut self) -> std::io::Result<()> {
        use std::io::Write;

        let write_result = match self.input.as_mut() {
            Some(input) => input.write_all(b"terminate\n").and_then(|()| input.flush()),
            None => Ok(()),
        };
        self.input.take();
        let wait_result = match self.watcher.take() {
            Some(mut watcher) => watcher.wait().map(|_| ()),
            None => Ok(()),
        };
        write_result.and(wait_result)
    }

    /// Consuming counterpart to [`Self::terminate_group`].
    pub fn disarm(mut self) -> std::io::Result<()> {
        self.terminate_group()
    }
}

impl Drop for ParentDeathGuard {
    fn drop(&mut self) {
        // Closing the pipe without an explicit line is the fail-safe path: the fixed script kills
        // its own protected group before it exits. Waiting also prevents a watcher zombie when an
        // ordinary Rust error unwinds through the guard.
        self.input.take();
        if let Some(mut watcher) = self.watcher.take() {
            let _ = watcher.wait();
        }
    }
}

fn output_bounded_inner(
    command: &mut std::process::Command,
    stdout_max: u64,
    stderr_max: u64,
    timeout: Option<Duration>,
    memory_max: Option<u64>,
) -> std::io::Result<std::process::Output> {
    use std::time::Instant;

    let mut watchdog = ParentDeathGuard::start()?;
    watchdog.configure(command);
    let process_group = watchdog.process_group_id();
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "child stdout was not piped")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "child stderr was not piped")
    })?;
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout, stdout_max));
    let stderr_reader = std::thread::spawn(move || read_bounded(stderr, stderr_max));
    let started = Instant::now();
    let kill_group = |child: &mut std::process::Child, watchdog: &mut ParentDeathGuard| {
        let _ = watchdog.terminate_group();
        let _ = child.kill();
    };
    let status = loop {
        match timeout {
            None => break child.wait(),
            Some(limit) => match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if started.elapsed() < limit => {
                    if let Some(memory_max) = memory_max {
                        match process_group_over_memory_limit(process_group, memory_max) {
                            Ok(false) => {}
                            Ok(true) => {
                                kill_group(&mut child, &mut watchdog);
                                let _ = child.wait();
                                break Err(process_group_memory_error(memory_max));
                            }
                            Err(error) => {
                                kill_group(&mut child, &mut watchdog);
                                let _ = child.wait();
                                break Err(error);
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    kill_group(&mut child, &mut watchdog);
                    let _ = child.wait();
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("child exceeded {} ms", limit.as_millis()),
                    ));
                }
                Err(error) => {
                    kill_group(&mut child, &mut watchdog);
                    let _ = child.wait();
                    break Err(error);
                }
            },
        }
    };
    // The direct child can exit after spawning a descendant that inherited either pipe. Its
    // status does not complete the operation: retain the same wall deadline through EOF, then
    // kill the owned process group so joining the drain threads cannot hang forever.
    let mut pipe_error = None;
    if let (Some(limit), Ok(_)) = (timeout, &status) {
        while !(stdout_reader.is_finished() && stderr_reader.is_finished())
            && started.elapsed() < limit
        {
            if let Some(memory_max) = memory_max {
                match process_group_over_memory_limit(process_group, memory_max) {
                    Ok(false) => {}
                    Ok(true) => {
                        kill_group(&mut child, &mut watchdog);
                        pipe_error = Some(process_group_memory_error(memory_max));
                        break;
                    }
                    Err(error) => {
                        kill_group(&mut child, &mut watchdog);
                        pipe_error = Some(error);
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if pipe_error.is_none() && !(stdout_reader.is_finished() && stderr_reader.is_finished()) {
            kill_group(&mut child, &mut watchdog);
            pipe_error = Some(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "child process group retained output pipes past {} ms",
                    limit.as_millis()
                ),
            ));
        }
    }
    let stdout = stdout_reader.join();
    let stderr = stderr_reader.join();
    // A direct child can report success after leaving a detached helper that closed both pipes.
    // The operation is complete, so no member of the sentinel-owned group is legitimate any
    // longer. The still-live sentinel makes this whole-group termination immune to pid reuse.
    let watchdog_result = watchdog.terminate_group();
    let _ = child.kill();
    if let Some(error) = pipe_error {
        return Err(error);
    }
    watchdog_result?;
    let status = status?;
    let stdout = stdout.map_err(|_| std::io::Error::other("child stdout reader panicked"))??;
    let stderr = stderr.map_err(|_| std::io::Error::other("child stderr reader panicked"))??;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

fn process_group_memory_error(memory_max: u64) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::OutOfMemory,
        format!(
            "child process group exceeded {} bytes of physical memory",
            memory_max
        ),
    )
}

#[cfg(target_os = "macos")]
fn accumulated_memory_over_limit(
    total: &mut u64,
    physical_footprint: u64,
    resident_size: u64,
    memory_max: u64,
) -> bool {
    *total = total.saturating_add(physical_footprint.max(resident_size));
    *total > memory_max
}

#[cfg(target_os = "macos")]
fn process_group_over_memory_limit(group: u32, memory_max: u64) -> std::io::Result<bool> {
    const MAX_GROUP_PROCESSES: usize = 64;
    let group = i32::try_from(group)
        .map_err(|_| std::io::Error::other("child process group id does not fit pid_t"))?;
    let mut pids = [0 as libc::pid_t; MAX_GROUP_PROCESSES];
    let buffer_bytes = std::mem::size_of_val(&pids);
    let buffer_bytes_i32 = i32::try_from(buffer_bytes)
        .map_err(|_| std::io::Error::other("process id buffer is too large"))?;
    // SAFETY: `pids` is a writable, correctly sized pid_t array for the duration of the call.
    let copied =
        unsafe { libc::proc_listpgrppids(group, pids.as_mut_ptr().cast(), buffer_bytes_i32) };
    if copied < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let copied =
        usize::try_from(copied).map_err(|_| std::io::Error::other("negative process id count"))?;
    if copied >= pids.len() {
        // A normal command here has only a handful of descendants. Filling the entire fixed
        // buffer is itself an untrusted-process explosion, and means an unmeasured child may
        // exist, so fail closed.
        return Ok(true);
    }
    let mut total = 0_u64;
    for pid in pids[..copied].iter().copied().filter(|pid| *pid > 0) {
        // SAFETY: the all-zero bit pattern is valid for this C plain-data output structure.
        let mut usage: libc::rusage_info_v0 = unsafe { std::mem::zeroed() };
        // SAFETY: `usage` is writable and has the exact layout requested by RUSAGE_INFO_V0.
        let rc = unsafe {
            libc::proc_pid_rusage(
                pid,
                libc::RUSAGE_INFO_V0,
                (&mut usage as *mut libc::rusage_info_v0).cast(),
            )
        };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            // A short-lived helper can disappear between the group listing and this query.
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(error);
        }
        if accumulated_memory_over_limit(
            &mut total,
            usage.ri_phys_footprint,
            usage.ri_resident_size,
            memory_max,
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(not(target_os = "macos"))]
fn process_group_over_memory_limit(_group: u32, _memory_max: u64) -> std::io::Result<bool> {
    // hot_cheese's production backend is macOS-only. Keep other targets buildable; their test
    // and development fetches still retain the byte, output, and wall-clock ceilings.
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Command;
    use std::time::Instant;

    fn now_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    }

    /// Whether `pid` is a process that is still running. An orphaned descendant is reparented to
    /// launchd, so it cannot be waited on here, and a killed-but-not-yet-reaped zombie still
    /// answers `kill(pid, 0)` — the kernel's own process state is the only honest probe.
    #[cfg(target_os = "macos")]
    fn process_is_running(pid: libc::pid_t) -> bool {
        // SAFETY: the all-zero bit pattern is valid for this C plain-data output structure.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let Ok(size) = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>()) else {
            return false;
        };
        // SAFETY: `info` is writable and has the exact layout requested by PROC_PIDTBSDINFO.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        written == size && info.pbi_status != libc::SZOMB
    }

    #[cfg(not(target_os = "macos"))]
    fn process_is_running(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 only probes the numeric pid printed by our own fixture.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    #[test]
    fn bounded_output_times_out_a_child_and_its_process_group() {
        let started = Instant::now();
        let error = output_bounded_timeout(
            Command::new("sh").args(["-c", "sleep 30"]),
            1024,
            1024,
            Duration::from_millis(100),
        )
        .expect_err("a silent child must not outlive its deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn bounded_output_deadline_includes_descendants_retaining_pipes() {
        let started = Instant::now();
        let error = output_bounded_timeout(
            Command::new("/bin/sh").args(["-c", "(sleep 30) & exit 0"]),
            1024,
            1024,
            Duration::from_millis(100),
        )
        .expect_err("a descendant retaining the pipes must not outlive the deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn bounded_output_reaps_a_detached_descendant_that_closed_its_pipes() {
        let output = output_bounded_timeout(
            Command::new("/bin/sh").args([
                "-c",
                "(exec </dev/null >/dev/null 2>&1; sleep 30) & echo $!",
            ]),
            1024,
            1024,
            Duration::from_secs(2),
        )
        .expect("the direct shell exits successfully");
        assert!(output.status.success());
        let pid: libc::pid_t = std::str::from_utf8(&output.stdout)
            .expect("pid is utf8")
            .trim()
            .parse()
            .expect("pid parses");
        assert!(
            !process_is_running(pid),
            "no helper may outlive a completed subprocess call"
        );
    }

    #[test]
    fn parent_death_guard_kills_its_process_group_when_dropped() {
        let marker = std::env::temp_dir().join(format!(
            "hot-cheese-parent-guard-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        let watchdog = ParentDeathGuard::start().expect("start the independent watcher");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "sleep 5; /usr/bin/touch \"$1\"",
                "parent-death-fixture",
            ])
            .arg(&marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        watchdog.configure(&mut command);
        let mut child = command.spawn().expect("spawn the protected group");

        drop(watchdog);
        let status = child.wait().expect("reap the killed group leader");
        assert!(!status.success());
        assert!(
            !marker.exists(),
            "the protected child must not outlive its owner"
        );
    }

    #[test]
    fn parent_death_sentinel_keeps_the_group_id_live_after_child_reaping() {
        let mut watchdog = ParentDeathGuard::start().expect("start the group sentinel");
        let process_group = watchdog.process_group_id();

        let mut first_command = Command::new("/usr/bin/true");
        watchdog.configure(&mut first_command);
        let mut first = first_command.spawn().expect("join the sentinel group");
        assert_ne!(
            first.id(),
            process_group,
            "the sentinel, not the workload, permanently owns the group id"
        );
        assert!(first.wait().expect("reap the first workload").success());

        // A second child can still join the exact group after the first child has been reaped.
        // This is the property that prevents its numeric id from being recycled in between.
        let mut second_command = Command::new("/bin/sleep");
        second_command.arg("30");
        watchdog.configure(&mut second_command);
        let mut second = second_command
            .spawn()
            .expect("the sentinel group remains live");
        watchdog
            .terminate_group()
            .expect("terminate the sentinel-owned group");
        assert!(!second.wait().expect("reap the second workload").success());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bounded_output_kills_a_process_over_its_memory_ceiling() {
        let started = Instant::now();
        let error = output_bounded_timeout_memory(
            Command::new("/bin/sleep").arg("30"),
            1024,
            1024,
            Duration::from_secs(5),
            1,
        )
        .expect_err("even a minimal child exceeds a one-byte physical-memory ceiling");
        assert_eq!(error.kind(), std::io::ErrorKind::OutOfMemory);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn process_group_memory_ceiling_is_aggregate() {
        let mut total = 0;
        assert!(!accumulated_memory_over_limit(&mut total, 40, 30, 60));
        assert!(accumulated_memory_over_limit(&mut total, 20, 40, 60));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn memory_ceiling_includes_descendants_retaining_pipes() {
        let started = Instant::now();
        let error = output_bounded_timeout_memory(
            Command::new("/bin/sh").args(["-c", "(sleep 30) & exit 0"]),
            1024,
            1024,
            Duration::from_secs(5),
            1,
        )
        .expect_err("a descendant retaining the pipes remains subject to the memory ceiling");
        assert_eq!(error.kind(), std::io::ErrorKind::OutOfMemory);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn regular_file_reader_refuses_symlinks_and_directories() {
        let dir = std::env::temp_dir().join(format!(
            "hot_cheese_regular_reader_{}_{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("file");
        let link = dir.join("link");
        std::fs::write(&file, b"bounded").unwrap();
        symlink(&file, &link).unwrap();

        assert_eq!(read_regular_file_bounded(&file, 7).unwrap(), b"bounded");
        assert!(read_regular_file_bounded(&link, 7).is_err());
        assert!(read_regular_file_bounded(&dir, 7).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn external_diagnostics_cannot_emit_terminal_controls() {
        let rendered = safe_diagnostic(b"line\n\x1b[31mred\x07\xe2\x80\xae");
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{7}'));
        assert!(rendered.contains("\\n"), "{rendered}");
        assert!(rendered.contains("\\u{1b}[31mred\\u{7}"), "{rendered}");
        assert!(rendered.contains("\\u{202e}"), "{rendered}");
    }

    #[test]
    fn private_reads_refuse_open_permissions_and_symlinks() {
        let root = std::env::temp_dir().join(format!(
            "hot-cheese-private-read-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("test dir");
        let key = root.join("key");
        crate::crypto::envelope::write_private_file_new(&key, b"secret").expect("private key");
        assert_eq!(
            &*read_private_file_bounded(&key, 32).expect("secure read"),
            b"secret"
        );

        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644))
            .expect("loosen mode");
        assert_eq!(
            read_private_file_bounded(&key, 32)
                .expect_err("group-readable private data must fail")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );

        let link = root.join("link");
        symlink(&key, &link).expect("make final-component symlink");
        assert!(read_private_file_bounded(&link, 32).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    /// The wiped buffer is sized from the caller's bound, never from metadata a concurrent writer
    /// can invalidate, because growing it mid-read strands an unwiped prefix on the heap.
    #[test]
    fn private_reads_size_their_buffer_from_the_bound() {
        const MAX: u64 = 4096;
        let root = std::env::temp_dir().join(format!(
            "hot-cheese-private-capacity-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&root).expect("test dir");
        let key = root.join("key");
        crate::crypto::envelope::write_private_file_new(&key, b"secret").expect("private key");

        let read = read_private_file_bounded(&key, MAX).expect("secure read");
        assert_eq!(&*read, b"secret");
        assert!(
            read.capacity() > MAX as usize,
            "a six-byte file was allocated {} bytes, so the file sized the buffer",
            read.capacity()
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

/// Expand a leading `~/` against `$HOME`; every other path is taken verbatim.
pub fn resolve_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home_dir) = std::env::var("HOME") {
            return PathBuf::from(home_dir).join(path.trim_start_matches("~/"));
        }
    }
    PathBuf::from(path)
}

/// Whether `name` is a safe, portable identifier: a non-empty `[A-Za-z0-9_]` string.
pub fn is_valid_string_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `name` is a legal keystore name. `policies` is the one otherwise-valid identifier
/// reserved by the store layout: allowing a file at that path would prevent the policy directory
/// from existing and make policy-backed signing impossible. Reserve every ASCII case variant so
/// the layout remains safe on case-insensitive filesystems as well as case-sensitive ones.
pub fn is_valid_key_name(name: &str) -> bool {
    is_valid_string_name(name) && !name.eq_ignore_ascii_case("policies")
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn the_policy_directory_is_not_a_keystore_name() {
        assert!(is_valid_string_name("policies"));
        assert!(!is_valid_key_name("policies"));
        assert!(!is_valid_key_name("POLICIES"));
        assert!(!is_valid_key_name("PoLiCiEs"));
    }
}
