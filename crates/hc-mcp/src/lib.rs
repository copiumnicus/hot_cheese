//! The MCP proposal server: an agent drafts Safe transactions, a human still signs them.
//!
//! This server PROPOSES and can never sign, and that is structural rather than a rule. The
//! crate does not depend on `hc-daemon`, so `HotApi`, `sign_intent`, `execute` and `Approver`
//! are not merely unused here — they are unnameable, because Rust hands out no path to a crate
//! that is not a dependency. Reaching for one is a compile error. It links no async runtime, no
//! socket and no HTTP client either, and `hc-sign/test-util` is never enabled anywhere, so the
//! forgeable grant that feature exposes for tests does not exist in this build.
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
pub mod proposal;
pub mod rpc;
pub mod tools;

use alloy_primitives::{B256, U256};
use err_mac::create_err_with_impls;

create_err_with_impls!(
    #[derive(Debug)]
    pub McpErr,
    Bundle(hc_bundle::BundleErr),
    Config(hc_core::config::ConfigErr),
    Policy(hc_sign::policy::PolicyErr),
    Sign(hc_sign::SignErr),
    Io(std::io::Error),
    Serde(serde_json::Error)
    ;
    SlotTaken { nonce: U256, held: B256 },
    PendingCapReached { pending: usize, max: usize },
    InvalidKeyName { key: String }
);
