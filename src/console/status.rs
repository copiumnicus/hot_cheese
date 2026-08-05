//! Log capture for the console: nothing may print over the menu, so every line is teed into
//! a ring buffer (shown in the status view) and appended to the console log file.
use super::{Console, Serving, UnlockGate};
use crate::config::home_dir;
use crate::keyring::{EnrollParams, Keyring};
use crate::mac::MacBackend;
use crate::server::is_valid_string_name;
use err_mac::create_err_with_impls;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::util::SubscriberInitExt;

/// Log lines kept for the status view.
const RING_CAPACITY: usize = 200;

/// Log lines the status view shows, newest last.
const LOG_TAIL: usize = 12;

/// Terminal width assumed when the size query fails.
const FALLBACK_WIDTH: usize = 100;

/// File under the home dir that every console log line is appended to.
const LOG_FILE: &str = "console.log";

create_err_with_impls!(
    #[derive(Debug)]
    pub StatusErr,
    StdIo(io::Error),
    Init(tracing_subscriber::util::TryInitError)
    ;
);

/// The most recent log lines, newest last.
#[derive(Debug)]
pub struct LogRing {
    lines: Mutex<VecDeque<String>>,
}

impl LogRing {
    /// The last `n` lines, oldest first.
    pub fn recent(&self, n: usize) -> Vec<String> {
        let lines = self.lines.lock();
        let skip = lines.len().saturating_sub(n);
        lines.iter().skip(skip).cloned().collect()
    }

    fn push(&self, line: &str) {
        let mut lines = self.lines.lock();
        if lines.len() == RING_CAPACITY {
            lines.pop_front();
        }
        lines.push_back(line.to_string());
    }
}

/// Tees one formatted event into the ring buffer and the log file.
#[derive(Clone)]
pub struct TeeWriter {
    ring: Arc<LogRing>,
    file: Arc<Mutex<File>>,
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        for line in text.lines() {
            self.ring.push(line);
        }
        self.file.lock().write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.lock().flush()
    }
}

impl<'a> MakeWriter<'a> for TeeWriter {
    type Writer = TeeWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Redirect tracing away from the terminal for the rest of the process.
pub fn install_subscriber(home: &Path, level: tracing::Level) -> Result<Arc<LogRing>, StatusErr> {
    let ring = Arc::new(LogRing {
        lines: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
    });
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(home.join(LOG_FILE))?;
    let writer = TeeWriter {
        ring: ring.clone(),
        file: Arc::new(Mutex::new(file)),
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(false)
        .with_writer(writer)
        .finish()
        .try_init()?;
    Ok(ring)
}

/// The Status screen: where the daemon is listening, what is exposed, and recent log lines.
pub fn view(console: &Console) -> String {
    let store = console.config.store_path();
    let mut keystores = 0usize;
    if let Ok(entries) = std::fs::read_dir(&store) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_file())
                && entry.file_name().to_str().is_some_and(is_valid_string_name)
            {
                keystores += 1;
            }
        }
    }

    let enrollments = match Keyring::load(&MacBackend::keyring_path(&console.config.store)) {
        Ok(keyring) => {
            let mut se = 0usize;
            let mut pass = 0usize;
            for enrollment in &keyring.enrollments {
                match enrollment.params {
                    EnrollParams::SecureEnclave { .. } => se += 1,
                    EnrollParams::Passphrase { .. } => pass += 1,
                }
            }
            let mut line = format!(
                "{} ({se} secure enclave, {pass} passphrase)",
                keyring.enrollments.len()
            );
            if pass == 0 {
                line.push_str("  [no recovery passphrase]");
            }
            line
        }
        Err(e) => {
            tracing::warn!(error = ?e, "status could not read the keyring");
            "unreadable".to_string()
        }
    };

    let serving = match &console.serving {
        Serving::Live { addr, .. } => format!("https://{addr}"),
        Serving::Refused => "refused, this session may not release keys off-process".to_string(),
    };
    let unlock = match console.gate {
        UnlockGate::Biometric => "secure enclave, Touch ID gates every request",
        UnlockGate::Passphrase => "recovery passphrase, one prompt at startup",
    };
    let mut remotes = Vec::new();
    for remote in &console.config.backup_remotes {
        remotes.push(format!("{}:{}", remote.host, remote.folder));
    }
    let tunnels = console.tunnels.list();

    let mut out = vec![
        "hot_cheese status".to_string(),
        String::new(),
        format!("  {:<12} {}", "serving", serving),
        format!("  {:<12} {}", "unlock", unlock),
        format!(
            "  {:<12} {} ({keystores} keystores)",
            "store",
            store.display()
        ),
        format!("  {:<12} {}", "enrollments", enrollments),
        format!(
            "  {:<12} {}",
            "backups",
            if remotes.is_empty() {
                "none".to_string()
            } else {
                remotes.join(", ")
            }
        ),
        format!(
            "  {:<12} {}",
            "tunnels",
            if tunnels.is_empty() {
                "none".to_string()
            } else {
                format!("{} open", tunnels.len())
            }
        ),
    ];
    for (id, spec) in &tunnels {
        out.push(format!(
            "  {:<12} #{} {} remote localhost:{} -> local :{}",
            "", id.0, spec.target, spec.remote_port, spec.local_port
        ));
    }
    out.push(format!(
        "  {:<12} {}",
        "log",
        home_dir().join(LOG_FILE).display()
    ));
    out.push(String::new());

    let recent = console.log.recent(LOG_TAIL);
    if recent.is_empty() {
        out.push(format!("  {:<12} empty", "recent log"));
        return out.join("\n");
    }
    let width = crossterm::terminal::size()
        .map(|(w, _)| w as usize)
        .unwrap_or(FALLBACK_WIDTH)
        .saturating_sub(6);
    out.push(format!("  {:<12} {} lines", "recent log", recent.len()));
    for line in recent {
        out.push(format!(
            "    {}",
            line.chars().take(width).collect::<String>()
        ));
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring must stay bounded at its capacity while keeping the newest lines: it drops the
    /// oldest on overflow, and `recent` returns the tail window in oldest-first order.
    #[test]
    fn ring_evicts_oldest_and_keeps_newest() {
        let ring = LogRing {
            lines: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
        };
        let overflow = 50;
        for i in 0..RING_CAPACITY + overflow {
            ring.push(&format!("line {i}"));
        }

        let all = ring.recent(RING_CAPACITY * 2);
        assert_eq!(all.len(), RING_CAPACITY, "ring must stay bounded");
        assert_eq!(all[0], format!("line {overflow}"), "oldest must be evicted");
        assert_eq!(
            all[RING_CAPACITY - 1],
            format!("line {}", RING_CAPACITY + overflow - 1),
            "newest must survive"
        );

        assert_eq!(
            ring.recent(3),
            vec![
                format!("line {}", RING_CAPACITY + overflow - 3),
                format!("line {}", RING_CAPACITY + overflow - 2),
                format!("line {}", RING_CAPACITY + overflow - 1),
            ]
        );
    }
}
