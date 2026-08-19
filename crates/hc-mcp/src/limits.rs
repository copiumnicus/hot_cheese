//! What one agent session may ask this server for, from `config.toml`'s `[mcp]` table.
//!
//! That one table bounds the review QUEUE, which the CLI and the daemon read too, and it bounds
//! the AGENT: which keys and Safes it may name at all, how far ahead of the operator's own queue
//! it may reserve a Safe nonce, how often it may write, how long what it wrote keeps holding a
//! slot, and how often it may take the exclusive claim on the bundle tree that the operator's CLI
//! needs to run at all. Every one of those has a default, so an install whose config predates them
//! is bounded exactly as it was.
//!
//! The nonce anchor is the one bound this machine cannot derive on its own. hot_cheese has no
//! RPC client, so the Safe's real nonce is not knowable here: a `[[mcp.anchor]]` entry is the
//! operator stating it, and without one the anchor falls back to the lowest nonce the local
//! queue still holds live — which bounds how far apart an agent's proposals may be spread, but
//! not where the first one lands. [`NonceWindow::anchored`] says which of the two is in force.
use crate::McpErr;
use alloy_primitives::U256;
use hc_core::config::Mcp;
use hc_sign::intent::SafeTxIntent;
use serde::Serialize;

/// Milliseconds the hourly proposal allowance is measured over.
const RATE_WINDOW_MS: u64 = 60 * 60 * 1000;

/// Where one proposal's nonce sits against the anchor, and whether there is a real anchor at all.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct NonceWindow {
    /// The nonce the window is measured from.
    #[serde(with = "hc_core::wire::u256")]
    pub anchor: U256,
    /// The nonce the proposal claims.
    #[serde(with = "hc_core::wire::u256")]
    pub nonce: U256,
    /// How far above the anchor the proposal sits.
    #[serde(with = "hc_core::wire::u256")]
    pub above_anchor: U256,
    /// How far above the anchor any proposal may sit.
    pub window: u64,
    /// Whether the anchor is a fact rather than this proposal's own nonce standing in for one.
    pub anchored: bool,
    /// Whether the proposal is inside the window; `propose` refuses when it is not.
    pub within: bool,
}

impl NonceWindow {
    /// The window is a bound, not a report: this is where a proposal outside it dies.
    pub fn accept(&self) -> Result<(), McpErr> {
        if self.within {
            return Ok(());
        }
        Err(McpErr::NonceOutsideWindow {
            nonce: self.nonce,
            anchor: self.anchor,
            window: self.window,
        })
    }
}

/// The key and the Safe an agent may name. An empty list is every one of them, so an install
/// whose `[mcp]` table names neither proposes exactly what it proposed before.
pub fn allows(mcp: &Mcp, intent: &SafeTxIntent) -> Result<(), McpErr> {
    if !mcp.keys.is_empty() && !mcp.keys.iter().any(|key| key == &intent.key) {
        return Err(McpErr::KeyNotAllowed {
            key: intent.key.clone(),
        });
    }
    if !mcp.safes.is_empty() && !mcp.safes.contains(&intent.safe) {
        return Err(McpErr::SafeNotAllowed {
            safe: intent.safe,
            chain_id: intent.chain_id,
        });
    }
    Ok(())
}

/// Where this proposal's nonce sits. The operator's declared anchor wins; failing that, the
/// lowest nonce the local queue still holds live for the same Safe, which is the closest thing to
/// the Safe's current nonce a machine with no RPC client can observe; failing both, the
/// proposal's own nonce stands in and `anchored` says so, because a single row in an empty queue
/// has nothing to be far ahead OF.
pub fn place_nonce(mcp: &Mcp, intent: &SafeTxIntent, pending: Option<U256>) -> NonceWindow {
    let window = mcp.nonce_window();
    let (anchor, anchored) = match anchor_of(mcp, intent) {
        Some(declared) => (declared, true),
        None => match pending {
            Some(lowest) => (lowest.min(intent.nonce), true),
            None => (intent.nonce, false),
        },
    };
    NonceWindow {
        anchor,
        nonce: intent.nonce,
        above_anchor: intent.nonce.saturating_sub(anchor),
        window,
        anchored,
        within: intent.nonce >= anchor && intent.nonce <= anchor.saturating_add(U256::from(window)),
    }
}

fn anchor_of(mcp: &Mcp, intent: &SafeTxIntent) -> Option<U256> {
    for anchor in &mcp.anchor {
        if anchor.safe == intent.safe && anchor.chain_id == intent.chain_id {
            return Some(anchor.nonce);
        }
    }
    None
}

/// What one agent session has spent against the `[mcp]` bounds. A session is one client on one
/// stdio pipe, which is the only identity a stdio MCP server has.
#[derive(Debug, Default)]
pub struct Session {
    filed_at_ms: Vec<u64>,
    locked_at_ms: Option<u64>,
}

impl Session {
    /// Charge one tool call that will take the exclusive claim on the bundle tree. The
    /// operator's own CLI takes the same try-lock and fails outright when it loses, so without
    /// this an agent free to spin on the read tools decides whether a human can run a command.
    pub fn claim_lock(&mut self, mcp: &Mcp) -> Result<(), McpErr> {
        let now = hc_sign::grant::now_ms()?;
        let cooldown = mcp.lock_cooldown_ms();
        if let Some(last) = self.locked_at_ms {
            let since = now.saturating_sub(last);
            if since < cooldown {
                return Err(McpErr::LockCooldown {
                    since_ms: since,
                    cooldown_ms: cooldown,
                });
            }
        }
        self.locked_at_ms = Some(now);
        Ok(())
    }

    /// Charge one proposal against the hourly allowance, and charge it on the ATTEMPT: a refused
    /// proposal that cost nothing is an unmetered retry loop, and `preview_erc20_transfer` is
    /// the free verb an agent is meant to iterate against instead.
    pub fn claim_proposal(&mut self, mcp: &Mcp) -> Result<(), McpErr> {
        let now = hc_sign::grant::now_ms()?;
        let oldest = now.saturating_sub(RATE_WINDOW_MS);
        self.filed_at_ms.retain(|at| *at >= oldest);
        let per_hour = mcp.proposals_per_hour();
        if self.filed_at_ms.len() >= per_hour {
            return Err(McpErr::RateLimited {
                filed: self.filed_at_ms.len(),
                per_hour,
            });
        }
        self.filed_at_ms.push(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes};
    use hc_core::config::NonceAnchor;
    use hc_sign::intent::Operation;

    const SAFE: Address = Address::new([0x11u8; 20]);

    fn intent(nonce: u64) -> SafeTxIntent {
        SafeTxIntent {
            key: "AGENT".to_string(),
            safe: SAFE,
            chain_id: U256::from(1u64),
            to: Address::new([0x22u8; 20]),
            value: U256::ZERO,
            data: Bytes::new(),
            operation: Operation::Call,
            safe_tx_gas: U256::ZERO,
            base_gas: U256::ZERO,
            gas_price: U256::ZERO,
            gas_token: Address::ZERO,
            refund_receiver: Address::ZERO,
            nonce: U256::from(nonce),
        }
    }

    fn anchored(nonce: u64) -> Mcp {
        Mcp {
            nonce_window: Some(4),
            anchor: vec![NonceAnchor {
                safe: SAFE,
                chain_id: U256::from(1u64),
                nonce: U256::from(nonce),
            }],
            ..Mcp::default()
        }
    }

    /// The window is what stops one approval becoming a cheque that executes whenever the agent
    /// decided. Both ends are closed: a nonce the Safe has already passed can never execute, and
    /// a nonce far above the anchor sits behind however many transactions the agent likes.
    #[test]
    fn a_declared_anchor_closes_the_nonce_window_at_both_ends() {
        let mcp = anchored(100);
        for inside in [100, 101, 104] {
            let placed = place_nonce(&mcp, &intent(inside), None);
            assert!(placed.within, "{inside} is inside a window of 4 from 100");
            assert!(placed.anchored);
            assert_eq!(placed.above_anchor, U256::from(inside - 100));
            assert!(placed.accept().is_ok());
        }
        for outside in [99, 105, 1_000_000] {
            let placed = place_nonce(&mcp, &intent(outside), None);
            assert!(!placed.within, "{outside} is outside a window of 4 from 100");
            assert!(matches!(
                placed.accept(),
                Err(McpErr::NonceOutsideWindow {
                    anchor,
                    window: 4,
                    ..
                }) if anchor == U256::from(100u64)
            ));
        }
    }

    /// With no declared anchor the queue is the anchor: the lowest nonce still live for the Safe.
    /// Proposals then have to sit within one window of each OTHER, which bounds how far apart an
    /// agent can spread them. An empty queue anchors nothing at all and says so rather than
    /// inventing a nonce this machine has no way to know.
    #[test]
    fn the_queue_anchors_the_window_when_the_operator_declared_nothing() {
        let mcp = Mcp {
            nonce_window: Some(4),
            ..Mcp::default()
        };

        let unanchored = place_nonce(&mcp, &intent(9_000), None);
        assert!(!unanchored.anchored);
        assert!(unanchored.within);
        assert_eq!(unanchored.above_anchor, U256::ZERO);

        let held = Some(U256::from(20u64));
        assert!(place_nonce(&mcp, &intent(24), held).within);
        assert!(!place_nonce(&mcp, &intent(25), held).within);

        let below = place_nonce(&mcp, &intent(3), held);
        assert!(below.anchored, "the queue is still an anchor");
        assert!(below.within, "a nonce below what is pending re-anchors it");
        assert_eq!(below.anchor, U256::from(3u64));
    }

    /// An empty list is every key and every Safe, so an install whose `[mcp]` table names neither
    /// proposes exactly what it proposed before; a list that is present admits nothing else.
    #[test]
    fn an_allow_list_admits_only_what_it_names() {
        assert!(allows(&Mcp::default(), &intent(0)).is_ok());

        let mcp = Mcp {
            keys: vec!["OTHER".to_string()],
            ..Mcp::default()
        };
        assert!(matches!(
            allows(&mcp, &intent(0)),
            Err(McpErr::KeyNotAllowed { key }) if key == "AGENT"
        ));

        let mcp = Mcp {
            keys: vec!["AGENT".to_string()],
            safes: vec![Address::new([0x99u8; 20])],
            ..Mcp::default()
        };
        assert!(matches!(
            allows(&mcp, &intent(0)),
            Err(McpErr::SafeNotAllowed { safe, .. }) if safe == SAFE
        ));

        let mcp = Mcp {
            keys: vec!["AGENT".to_string()],
            safes: vec![SAFE],
            ..Mcp::default()
        };
        assert!(allows(&mcp, &intent(0)).is_ok());
    }

    /// The allowance is spent on the attempt and refills by elapsed time, not by the queue
    /// draining: filling the queue, having the operator empty it and filling it again is the
    /// exact loop that wedges every peer.
    #[test]
    fn the_hourly_allowance_is_spent_on_the_attempt() {
        let mcp = Mcp {
            proposals_per_hour: Some(2),
            ..Mcp::default()
        };
        let mut session = Session::default();
        assert!(session.claim_proposal(&mcp).is_ok());
        assert!(session.claim_proposal(&mcp).is_ok());
        assert!(matches!(
            session.claim_proposal(&mcp),
            Err(McpErr::RateLimited { per_hour: 2, .. })
        ));

        let stale = hc_sign::grant::now_ms().unwrap() - RATE_WINDOW_MS - 1;
        session.filed_at_ms = vec![stale, stale];
        assert!(
            session.claim_proposal(&mcp).is_ok(),
            "an hour-old proposal no longer occupies the allowance"
        );
    }
}
