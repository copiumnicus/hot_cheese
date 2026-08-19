//! Who else is on this operator's tailnet, read from `tailscale status --json`.
//!
//! Discovery is a shell-out and nothing more: hot_cheese links no Tailscale code, opens no
//! socket to it, and asks it for exactly two facts — a machine's MagicDNS name and whether
//! tailscaled currently sees it. Names, never addresses: a tailnet IP changes and a MagicDNS
//! name does not, so an enrolled peer keeps working after a re-key or a re-install.
//!
//! Being on the tailnet grants NO authority here. Nothing in hot_cheese listens on it; the
//! only thing a name buys is somewhere for `rsync` to push to, and every byte that comes back
//! is verified locally by [`crate::ingest`].
use err_mac::create_err_with_impls;
use hashbrown::HashMap;
use serde::Deserialize;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// Fixed macOS installation locations, preferred over executing a caller-controlled `$PATH`.
const BINARIES: [&str; 3] = [
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/opt/homebrew/bin/tailscale",
    "/usr/local/bin/tailscale",
];

/// A status response is already byte-bounded, but this separately bounds downstream sorting,
/// matching and terminal rows. Config can enroll at most 64 of these nodes.
const MAX_TAILNET_PEERS: usize = 1024;

/// DNS names are at most 253 bytes; the extra two bytes leave room for a root dot and avoid
/// silently accepting a non-hostname-sized display value from an external status document.
const MAX_NODE_NAME_BYTES: usize = 255;

create_err_with_impls!(
    #[derive(Debug)]
    pub TailnetErr,
    StatusSignal,
    StdIo(std::io::Error),
    Json(serde_json::Error)
    ;
    BinaryNotFound { searched: Vec<PathBuf> },
    StatusFailed { code: i32 },
    BackendNotRunning { state: Backend },
    TooManyPeers { found: usize, max: usize }
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

/// The `tailscale` binary from a fixed installation location. A candidate must resolve to a
/// regular executable that is not group/world writable; otherwise an environment or permissive
/// file cannot turn discovery into arbitrary code execution inside the signing process.
fn binary() -> Result<PathBuf, TailnetErr> {
    let mut searched = Vec::new();
    for location in BINARIES {
        let candidate = PathBuf::from(location);
        searched.push(candidate.clone());
        let Ok(resolved) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        let Ok(metadata) = std::fs::metadata(&resolved) else {
            continue;
        };
        let mode = metadata.permissions().mode();
        if metadata.file_type().is_file() && mode & 0o111 != 0 && mode & 0o022 == 0 {
            return Ok(resolved);
        }
    }
    Err(TailnetErr::BinaryNotFound { searched })
}

/// Every peer on this machine's tailnet, sorted by hostname. Neither stdout nor stderr is
/// inherited, so a console that owns the terminal keeps owning it.
pub fn peers() -> Result<Vec<Node>, TailnetErr> {
    const MAX_STATUS_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_STATUS_ERROR_BYTES: u64 = 256 * 1024;
    let bin = binary()?;
    let mut command = Command::new(&bin);
    command.args(["status", "--json"]);
    let out = hc_core::output_bounded_timeout(
        &mut command,
        MAX_STATUS_BYTES,
        MAX_STATUS_ERROR_BYTES,
        Duration::from_secs(15),
    )?;
    if !out.status.success() {
        tracing::warn!(
            binary = %bin.display(),
            stderr = %hc_core::safe_diagnostic(&out.stderr),
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
    let status: StatusJson = hc_core::wire::strict_json_from_slice(json)?;
    let state = backend(&status.backend_state);
    if state != Backend::Running {
        return Err(TailnetErr::BackendNotRunning { state });
    }
    let peers = status.peer.unwrap_or_default();
    if peers.len() > MAX_TAILNET_PEERS {
        return Err(TailnetErr::TooManyPeers {
            found: peers.len(),
            max: MAX_TAILNET_PEERS,
        });
    }
    let mut out = Vec::with_capacity(peers.len());
    for node in peers.into_values() {
        let trimmed = node.dns_name.trim_end_matches('.');
        let dns_name = (!trimmed.is_empty()
            && trimmed.len() <= MAX_NODE_NAME_BYTES
            && hc_core::config::validate_ssh_target(trimmed).is_ok())
        .then(|| trimmed.to_string());
        let host_bytes =
            &node.host_name.as_bytes()[..node.host_name.len().min(MAX_NODE_NAME_BYTES)];
        let mut host_name = hc_core::safe_diagnostic(host_bytes);
        if node.host_name.len() > MAX_NODE_NAME_BYTES {
            host_name.push_str("...[truncated]");
        }
        out.push(Node {
            dns_name,
            host_name,
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

    /// Node metadata comes from outside this process and reaches both tracing and the interactive
    /// console. Control/bidi bytes in a hostname must become inert ASCII, while a DNS name that
    /// cannot safely be handed to ssh must never become an enrollable address.
    #[test]
    fn hostile_node_names_are_inert_and_cannot_become_ssh_targets() {
        let json = br#"{
          "BackendState": "Running",
          "Peer": {
            "nodekey:bad": {
              "HostName": "line\n\u001b[31mred\u202e",
              "DNSName": "not a shell-safe name.",
              "Online": true
            }
          }
        }"#;
        let peers = parse_status(json).expect("the status document itself is valid");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].dns_name, None);
        assert!(peers[0].host_name.is_ascii());
        assert!(!peers[0].host_name.contains('\n'));
        assert!(!peers[0].host_name.contains('\u{1b}'));
        assert!(peers[0].host_name.contains("\\n"));
    }

    #[test]
    fn a_status_document_cannot_publish_an_unbounded_peer_set() {
        let mut peer = serde_json::Map::new();
        for at in 0..=MAX_TAILNET_PEERS {
            peer.insert(
                format!("nodekey:{at}"),
                serde_json::json!({
                    "HostName": format!("node-{at}"),
                    "DNSName": format!("node-{at}.example.ts.net."),
                    "Online": true,
                }),
            );
        }
        let json = serde_json::to_vec(&serde_json::json!({
            "BackendState": "Running",
            "Peer": peer,
        }))
        .expect("render the status fixture");
        assert!(matches!(
            parse_status(&json),
            Err(TailnetErr::TooManyPeers {
                found,
                max: MAX_TAILNET_PEERS,
            }) if found == MAX_TAILNET_PEERS + 1
        ));
    }
}
