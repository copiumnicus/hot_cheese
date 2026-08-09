//! The fence between the key core and everything else, read straight off `cargo tree`.
//!
//! Dev-dependencies are deliberately excluded (`--edges normal,build`): a test helper may pull
//! in whatever it likes, but what `hc-core` LINKS is what an iOS build has to carry and what an
//! audit of the key path has to read.
use std::collections::BTreeSet;
use std::process::Command;

/// Each of these drags a whole async runtime, TLS stack, terminal or argument parser into the
/// code that handles key material. `tokio` is the load-bearing one: no async runtime may sit
/// anywhere near the DEK, because that is what keeps `hc-core` a synchronous, portable library.
const FORBIDDEN: [&str; 9] = [
    "tokio",
    "hyper",
    "hyper-util",
    "rustls",
    "tokio-rustls",
    "inquire",
    "crossterm",
    "clap",
    "wasmtime",
];

/// Every crate `package` links, with all its features on and dev-dependencies excluded.
fn closure(package: &str) -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .args([
            "tree",
            "-p",
            package,
            "--all-features",
            "--edges",
            "normal,build",
            "--prefix",
            "none",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run cargo tree");
    assert!(
        out.status.success(),
        "cargo tree -p {package} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("cargo tree output is utf8");
    let mut names = BTreeSet::new();
    for line in text.lines() {
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        if name.starts_with('[') {
            continue;
        }
        names.insert(name.to_string());
    }
    assert!(
        names.contains(package),
        "cargo tree -p {package} did not list {package} itself"
    );
    names
}

/// The workspace crates inside `package`'s closure.
fn local(package: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for name in closure(package) {
        if name.starts_with("hc-") {
            found.insert(name);
        }
    }
    found
}

/// `hc-core` is the bottom of the workspace: it may not reach sideways or upwards, or the
/// "minimal auditable core" is only a directory layout.
#[test]
fn hc_core_depends_on_no_other_workspace_crate() {
    let found = local("hc-core");
    for name in &found {
        assert_eq!(
            name, "hc-core",
            "hc-core must depend on no local crate, but it pulls in {name}"
        );
    }
    assert_eq!(found.len(), 1, "hc-core's local closure is {found:?}");
}

/// An iPhone signer builds `hc-core` for `aarch64-apple-ios` and leaves the daemon behind. That
/// only works while none of the server stack has crept into the key core.
#[test]
fn hc_core_links_no_runtime_tls_terminal_or_cli() {
    let found = closure("hc-core");
    for banned in FORBIDDEN {
        assert!(
            !found.contains(banned),
            "hc-core must not link {banned}, but it is in hc-core's dependency closure"
        );
    }
}

/// An iPhone links `hc-sign` to run the same policy, digest and grant code the daemon runs, so
/// its trusted computing base is exactly these two crates. Anything else appearing here is a
/// crate that would have to be ported, audited and shipped with the app.
#[test]
fn hc_sign_links_the_key_core_and_nothing_else_local() {
    let found = local("hc-sign");
    let expected: BTreeSet<String> = ["hc-core", "hc-sign"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(found, expected, "hc-sign's local closure is {found:?}");
}

/// The bundle engine is what a proposer links, and `hc-daemon` being outside its closure is what
/// makes `HotApi::sign_intent` unnameable rather than merely unused: Rust hands out no path to a
/// transitive dependency, so proposing and signing are separated by a compile error.
#[test]
fn hc_bundle_links_the_key_core_and_neither_the_daemon_nor_a_runtime() {
    let found = local("hc-bundle");
    let expected: BTreeSet<String> = ["hc-bundle", "hc-core", "hc-sign"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(found, expected, "hc-bundle's local closure is {found:?}");

    let found = closure("hc-bundle");
    for banned in FORBIDDEN {
        assert!(
            !found.contains(banned),
            "hc-bundle must not link {banned}, but it is in hc-bundle's dependency closure"
        );
    }
}

/// The MCP proposal server may reach the bundle engine and the policy code, and nothing else.
/// `hc-daemon` outside its closure is what makes the signing API unnameable there rather than
/// merely unused, so "an agent proposes and can never sign" is a compile error. No runtime, no
/// TLS and no argument parser either: this binary owns a pipe, not a socket and not a terminal.
///
/// What this does NOT cover: `hc-sign/test-util`, which gates a forgeable grant, adds no
/// dependency edge at all — `cargo tree` cannot see it at any feature setting, so the only
/// enforcement is that no manifest anywhere enables it.
#[test]
fn hc_mcp_links_the_bundle_engine_and_neither_the_daemon_nor_a_runtime() {
    let found = local("hc-mcp");
    let expected: BTreeSet<String> = ["hc-bundle", "hc-core", "hc-mcp", "hc-sign"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(found, expected, "hc-mcp's local closure is {found:?}");

    let found = closure("hc-mcp");
    for banned in FORBIDDEN {
        assert!(
            !found.contains(banned),
            "hc-mcp must not link {banned}, but it is in hc-mcp's dependency closure"
        );
    }
}

/// The daemon serves; it does not own the terminal and it is not the command line. A dependency
/// either way would put inquire/crossterm behind `serve` and make the seam unenforceable.
#[test]
fn hc_daemon_depends_on_neither_the_console_nor_the_cli() {
    let found = local("hc-daemon");
    for banned in ["hc-console", "hc-cli"] {
        assert!(
            !found.contains(banned),
            "hc-daemon must not depend on {banned}, but its local closure is {found:?}"
        );
    }
}
