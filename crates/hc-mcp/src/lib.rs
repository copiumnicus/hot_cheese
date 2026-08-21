//! The MCP proposal server: an agent drafts Safe transactions, a human still signs them.
//!
//! This server PROPOSES and can never sign, and that is structural rather than a rule. The
//! crate does not depend on `hc-daemon`, so `HotApi`, `sign_intent`, `execute` and `Approver`
//! are not merely unused here — they are unnameable, because Rust hands out no path to a crate
//! that is not a dependency. Reaching for one is a compile error. It links no async runtime, no
//! socket and no HTTP client either. `hc-sign/test-util` is a different matter and is stated
//! honestly: `hc-daemon` enables it, a workspace build unifies features, so `grant_for_test` is
//! compiled into the `hc-sign` this crate links. It buys nothing, because a grant is spent by
//! the daemon's signing path and that path is the thing this crate cannot name.
//!
//! The agent is bounded as well as narrowed, and by TOML rather than by anything it can reach:
//! `config.toml`'s `[mcp]` table ([`limits`]) says which keys and Safes it may name, how far
//! above the anchor it may reserve a Safe nonce, how many proposals an hour it may file, how long
//! an unsigned one keeps its slot, and how often it may take the claim the operator's own CLI
//! needs. Every one of those has a default, so an install whose config predates them keeps
//! working. What it refuses with is deliberately thinner than what it logs: a caller is told
//! which rule refused, and the operator's log is told what the rule holds.
//!
//! What an agent can produce, at most, is a row in the operator's review queue, and that row can
//! only be one ERC-20 transfer: the [`tools`] surface exposes a shape, never a transaction
//! encoder, so `delegatecall`, arbitrary calldata, owner rotation, gas refunds and native value
//! are inexpressible here rather than merely denied. The decoded summary, the per-key policy
//! ceiling, the hardware-attested approval and the biometric all still stand between that row
//! and a signature, unchanged and untouched by this crate.
//!
//! Deliberately excluded, and excluded rather than forgotten: anything that signs (`sign`,
//! `collect`, `merge`); anything that reads or derives key material (the daemon's `/read`
//! route, its key-export permit, the address endpoints); anything that mutates policy,
//! `safes.toml` or `config.toml` (`peer add`/`peer rm`, `enroll`, `generate`, `seal`,
//! `backup`); the bundle export verb, because it yields the broadcastable blob and hot_cheese
//! deliberately has no RPC client; bundle retirement; tailnet discovery; and QR frames.
//!
//! Two traps of speaking JSON-RPC over stdio, both respected here:
//!
//! - **stdout is the protocol.** Tracing is installed against stderr, and a single stray
//!   `println!` anywhere in this crate corrupts the stream for the rest of the session.
//! - **No embedded newlines.** Every response is rendered with `serde_json::to_string` and
//!   never `to_string_pretty`, because the compact writer escapes newlines inside strings — so
//!   one message per line holds by construction even when a decoded summary is multi-line.
//!
//! Three fences keep the boundary, in descending order of strength: the missing `hc-daemon`
//! dependency (a compile error), the closure test in `hc-core/tests/boundary.rs` (a build-graph
//! assertion), and a string search over this crate's own source in `tests/fence.rs` — the
//! weakest of the three, since it is a test rather than a type and a future edit can delete it.
pub mod limits;
pub mod proposal;
pub mod rpc;
pub mod tools;

use alloy_primitives::{Address, B256, U256};
use err_mac::create_err_with_impls;

create_err_with_impls!(
    #[derive(Debug)]
    pub McpErr,
    Bundle(hc_bundle::BundleErr),
    Config(hc_core::config::ConfigErr),
    Policy(hc_sign::policy::PolicyErr),
    Sign(hc_sign::SignErr),
    Grant(hc_sign::grant::GrantErr),
    Io(std::io::Error),
    Serde(serde_json::Error)
    ;
    SlotTaken { nonce: U256, held: B256 },
    PendingCapReached { pending: usize, max: usize },
    InvalidKeyName { key: String },
    KeyNotAllowed { key: String },
    SafeNotAllowed { safe: Address, chain_id: U256 },
    NonceOutsideWindow { nonce: U256, anchor: U256, window: u64 },
    RateLimited { filed: usize, per_hour: usize },
    LockCooldown { since_ms: u64, cooldown_ms: u64 }
);

impl McpErr {
    /// What the agent is told, as opposed to what the operator's log records. This server's own
    /// refusals go back whole: they name the agent's own arguments and the bounds it has to work
    /// inside, which is what lets it correct itself. Everything a library raised goes back as
    /// the chain of variant names alone, because a policy denial's FIELDS are the payee list and
    /// the ceiling that `list_signing_keys` deliberately decides what to publish — answering a
    /// denial with them hands the whole policy to anyone willing to submit and read refusals.
    pub fn refusal(&self) -> String {
        match self {
            McpErr::Bundle(_)
            | McpErr::Config(_)
            | McpErr::Policy(_)
            | McpErr::Sign(_)
            | McpErr::Grant(_)
            | McpErr::Io(_)
            | McpErr::Serde(_) => variant_path(&self.to_string()),
            McpErr::SlotTaken { .. }
            | McpErr::PendingCapReached { .. }
            | McpErr::InvalidKeyName { .. }
            | McpErr::KeyNotAllowed { .. }
            | McpErr::SafeNotAllowed { .. }
            | McpErr::NonceOutsideWindow { .. }
            | McpErr::RateLimited { .. }
            | McpErr::LockCooldown { .. } => self.to_string(),
        }
    }
}

/// The chain of variant names in a `Debug` rendering with every field dropped, so
/// `Sign(PolicyDenied(Call(ToNotAllowed { to: 0x… })))` becomes
/// `Sign::PolicyDenied::Call::ToNotAllowed`. It names which rule refused and nothing the rule
/// holds, and what it returns is `[A-Za-z0-9_:]` by construction, so it is also inert in a
/// terminal no matter what the caller put in the value that was dropped.
fn variant_path(rendered: &str) -> String {
    let mut path = Vec::new();
    let mut rest = rendered;
    loop {
        let end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        if end == 0 {
            break;
        }
        path.push(&rest[..end]);
        let Some(inner) = rest[end..].strip_prefix('(') else {
            break;
        };
        rest = inner;
    }
    path.join("::")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The denial an adversarial agent reads: which rule refused, and none of what it holds.
    /// The policy's contents are the payee allow-list and the per-argument ceiling, so a refusal
    /// that echoed them would publish the whole policy to anyone willing to submit and read
    /// proposals — and a refusal that echoed a raw field would carry the caller's own bytes back
    /// out into the operator's terminal.
    #[test]
    fn a_library_denial_reaches_the_agent_as_a_rule_name_and_nothing_else() {
        let denial = McpErr::Sign(hc_sign::SignErr::PolicyDenied(
            hc_sign::policy::PolicyDenied::Call(hc_sign::policy::CallDenied::ValueTooHigh {
                value: U256::from(9_000u64),
                max: U256::from(1_000u64),
            }),
        ));
        let refusal = denial.refusal();
        assert_eq!(refusal, "Sign::PolicyDenied::Call::ValueTooHigh");
        assert!(
            !refusal.contains("1000") && !refusal.contains("9000"),
            "the ceiling and the offending value are the policy's contents: {refusal}"
        );
        assert!(
            denial.to_string().contains("1000"),
            "the operator's log still gets the whole thing"
        );

        let unsafe_config = McpErr::Config(hc_core::config::ConfigErr::ChownConfigToYourUser {
            path: std::path::PathBuf::from("/Users/someone/.config/hot_cheese/config.toml"),
            owner: 0,
            ours: 501,
        });
        assert_eq!(unsafe_config.refusal(), "Config::ChownConfigToYourUser");

        let anchored = McpErr::NonceOutsideWindow {
            nonce: U256::from(9_001u64),
            anchor: U256::from(12u64),
            window: 8,
        };
        assert!(
            anchored.refusal().contains("9001") && anchored.refusal().contains("12"),
            "this server's own bounds are what the agent has to correct against"
        );
    }
}
