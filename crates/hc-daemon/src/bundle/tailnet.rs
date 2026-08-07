//! Who else is on this operator's tailnet, read from `tailscale status --json`.
//!
//! Discovery is a shell-out and nothing more: hot_cheese links no Tailscale code, opens no
//! socket to it, and asks it for exactly two facts — a machine's MagicDNS name and whether
//! tailscaled currently sees it. Names, never addresses: a tailnet IP changes and a MagicDNS
//! name does not, so an enrolled peer keeps working after a re-key or a re-install.
//!
//! Being on the tailnet grants NO authority here. Nothing in hot_cheese listens on it; the
//! only thing a name buys is somewhere for `rsync` to push to, and every byte that comes back
//! is verified locally by [`super::ingest`].
use err_mac::create_err_with_impls;
use hashbrown::HashMap;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The CLI's name on `$PATH`.
const BINARY: &str = "tailscale";

/// Where the macOS app keeps the same binary when it is not on `$PATH`.
const APP_BINARY: &str = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";

create_err_with_impls!(
    #[derive(Debug)]
    pub TailnetErr,
    StatusSignal,
    StdIo(std::io::Error),
    Json(serde_json::Error)
    ;
    BinaryNotFound { searched: Vec<PathBuf> },
    StatusFailed { code: i32 },
    BackendNotRunning { state: Backend }
);

/// `BackendState` as tailscaled reports it. Only [`Backend::Running`] can answer for a tailnet;
/// each of the others names its own fix — log in, bring it up, or wait for it to finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Up and logged in; peers are real.
    Running,
    /// Logged out: `tailscale login`.
    NeedsLogin,
    /// The tailnet admin has not approved this machine yet.
    NeedsMachineAuth,
    /// Brought down: `tailscale up`.
    Stopped,
    /// Coming up; poll again.
    Starting,
    /// tailscaled has not been started.
    NoState,
    /// A state this build does not name.
    Other,
}

/// One machine on the tailnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// MagicDNS name with its root dot stripped; absent when the tailnet has none for it.
    pub dns_name: Option<String>,
    /// The machine's own hostname, which MagicDNS names are usually derived from.
    pub host_name: String,
    /// Whether tailscaled currently sees it.
    pub online: bool,
}

impl Node {
    /// The first label of the MagicDNS name — the short form an operator types.
    pub fn short(&self) -> Option<&str> {
        let full = self.dns_name.as_deref()?;
        Some(full.split('.').next().unwrap_or(full))
    }

    /// Whether `name` identifies this node: its hostname, its short MagicDNS label, or the
    /// fully-qualified MagicDNS name, all case-insensitively.
    pub fn is(&self, name: &str) -> bool {
        if self.host_name.eq_ignore_ascii_case(name) {
            return true;
        }
        if self.short().is_some_and(|s| s.eq_ignore_ascii_case(name)) {
            return true;
        }
        self.dns_name
            .as_deref()
            .is_some_and(|d| d.eq_ignore_ascii_case(name))
    }
}

/// The `tailscale` binary: `$PATH` first, then the macOS app bundle. The error lists every
/// place that was tried, because "install Tailscale" and "it is installed but not linked" are
/// different problems with different fixes.
fn binary() -> Result<PathBuf, TailnetErr> {
    let mut searched = Vec::new();
    if let Ok(path) = std::env::var("PATH") {
        for entry in path.split(':') {
            if entry.is_empty() {
                continue;
            }
            let candidate = Path::new(entry).join(BINARY);
            if candidate.is_file() {
                return Ok(candidate);
            }
            searched.push(candidate);
        }
    }
    let app = PathBuf::from(APP_BINARY);
    if app.is_file() {
        return Ok(app);
    }
    searched.push(app);
    Err(TailnetErr::BinaryNotFound { searched })
}

/// Every peer on this machine's tailnet, sorted by hostname. Neither stdout nor stderr is
/// inherited, so a console that owns the terminal keeps owning it.
pub fn peers() -> Result<Vec<Node>, TailnetErr> {
    let bin = binary()?;
    let out = Command::new(&bin).args(["status", "--json"]).output()?;
    if !out.status.success() {
        tracing::warn!(
            binary = %bin.display(),
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "tailscale status failed"
        );
        return match out.status.code() {
            Some(code) => Err(TailnetErr::StatusFailed { code }),
            None => Err(TailnetErr::StatusSignal),
        };
    }
    parse_status(&out.stdout)
}

/// `tailscale status --json`, cut down to the three fields discovery needs.
#[derive(Deserialize)]
struct StatusJson {
    /// Whether tailscaled is up and logged in.
    #[serde(rename = "BackendState", default)]
    backend_state: String,
    /// Peers by node key; null when this machine is alone on its tailnet.
    #[serde(rename = "Peer", default)]
    peer: Option<HashMap<String, NodeJson>>,
}

/// One entry of the `Peer` map.
#[derive(Deserialize)]
struct NodeJson {
    /// Fully-qualified MagicDNS name, with a trailing root dot.
    #[serde(rename = "DNSName", default)]
    dns_name: String,
    /// The machine's own hostname.
    #[serde(rename = "HostName", default)]
    host_name: String,
    /// Whether tailscaled currently sees it.
    #[serde(rename = "Online", default)]
    online: bool,
}

fn backend(state: &str) -> Backend {
    match state {
        "Running" => Backend::Running,
        "NeedsLogin" => Backend::NeedsLogin,
        "NeedsMachineAuth" => Backend::NeedsMachineAuth,
        "Stopped" => Backend::Stopped,
        "Starting" => Backend::Starting,
        "NoState" => Backend::NoState,
        _ => Backend::Other,
    }
}

/// Peers out of one status document. A backend that is not `Running` is refused rather than
/// reported as an empty tailnet: "no peers" and "you are logged out" must not look alike, or
/// `peer add` blames the wrong thing. The peer map is a JSON object and therefore unordered,
/// so the result is sorted before it is returned.
fn parse_status(json: &[u8]) -> Result<Vec<Node>, TailnetErr> {
    let status: StatusJson = serde_json::from_slice(json)?;
    let state = backend(&status.backend_state);
    if state != Backend::Running {
        return Err(TailnetErr::BackendNotRunning { state });
    }
    let mut out = Vec::new();
    for node in status.peer.unwrap_or_default().into_values() {
        let trimmed = node.dns_name.trim_end_matches('.');
        out.push(Node {
            dns_name: match trimmed.is_empty() {
                true => None,
                false => Some(trimmed.to_string()),
            },
            host_name: node.host_name,
            online: node.online,
        });
    }
    out.sort_by(|a, b| (&a.host_name, &a.dns_name).cmp(&(&b.host_name, &b.dns_name)));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic document: one online Mac, one offline Mac, and a node the tailnet has no
    /// MagicDNS name for. All three must survive parsing, the trailing root dot must be gone
    /// so the name is usable as an ssh target, the nameless one must stay identifiable by
    /// hostname alone, and the unordered `Peer` object must come back sorted.
    #[test]
    fn peers_keep_their_names_their_state_and_a_stable_order() {
        let json = br#"{
          "Version": "1.80.0",
          "BackendState": "Running",
          "Self": { "HostName": "desktop", "DNSName": "desktop.tail1a2b.ts.net.", "Online": true },
          "Peer": {
            "nodekey:22": { "HostName": "macbook", "DNSName": "macbook.tail1a2b.ts.net.",
                            "TailscaleIPs": ["100.64.0.2"], "Online": true, "OS": "macOS" },
            "nodekey:11": { "HostName": "airgap", "DNSName": "", "TailscaleIPs": [], "Online": false },
            "nodekey:33": { "HostName": "studio", "DNSName": "studio.tail1a2b.ts.net.",
                            "TailscaleIPs": ["100.64.0.3"], "Online": false, "OS": "macOS" }
          }
        }"#;

        let peers = parse_status(json).expect("a Running tailnet parses");
        let names: Vec<&str> = peers.iter().map(|p| p.host_name.as_str()).collect();
        assert_eq!(names, vec!["airgap", "macbook", "studio"]);

        let airgap = &peers[0];
        assert_eq!(airgap.dns_name, None);
        assert_eq!(airgap.short(), None);
        assert!(!airgap.online);
        assert!(airgap.is("airgap"), "a nameless node is still its hostname");

        let macbook = &peers[1];
        assert_eq!(
            macbook.dns_name.as_deref(),
            Some("macbook.tail1a2b.ts.net"),
            "the root dot must go, or ssh gets a name with a trailing dot"
        );
        assert_eq!(macbook.short(), Some("macbook"));
        assert!(macbook.online);
        assert!(macbook.is("MacBook"));
        assert!(macbook.is("macbook.tail1a2b.ts.net"));
        assert!(!macbook.is("studio"));

        assert!(!peers[2].online, "an offline peer is listed, not dropped");
    }

    /// "Nobody is here" and "you are logged out" must not look alike: a tailnet with no peers
    /// is an empty list, every other backend state is a refusal naming what is wrong.
    #[test]
    fn a_backend_that_is_not_running_is_refused_rather_than_reported_empty() {
        let empty = parse_status(br#"{"BackendState":"Running","Peer":null}"#)
            .expect("a lone machine is a Running tailnet with no peers");
        assert!(empty.is_empty());

        for (state, expected) in [
            ("NeedsLogin", Backend::NeedsLogin),
            ("Stopped", Backend::Stopped),
            ("Starting", Backend::Starting),
            ("NoState", Backend::NoState),
            ("NeedsMachineAuth", Backend::NeedsMachineAuth),
            ("SomethingNewInTailscale", Backend::Other),
        ] {
            let doc = format!(r#"{{"BackendState":"{state}","Peer":{{}}}}"#);
            match parse_status(doc.as_bytes()) {
                Err(TailnetErr::BackendNotRunning { state: found }) => assert_eq!(found, expected),
                other => panic!("expected a refusal for {state}, got {other:?}"),
            }
        }
    }
}
