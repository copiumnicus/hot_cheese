//! The one capability in this crate that writes.
//!
//! [`Proposal`] mirrors `ApprovedSafeTx`: private fields, no constructor but [`Proposal::check`],
//! and [`Proposal::file`] takes it by value. So a bundle that was not policy-checked cannot be
//! filed, because there is no other way to reach the write — the same trick the signer uses to
//! make "the policy ran before the prompt" a fact of the type system.
//!
//! The dry run is the signer's own `prepare`, not a second implementation of it, so what this
//! server accepts cannot drift from what the signer will actually do. Its `ApprovedSafeTx` is
//! dropped on the spot: this crate has no way to spend one.
use crate::McpErr;
use alloy_primitives::B256;
use hc_bundle::sync::SyncMode;
use hc_bundle::Safes;
use hc_core::config::{bundles_dir, Config};
use hc_sign::intent::SafeTxIntent;
use hc_sign::policy::Policy;

/// Digests already competing for an intent's (Safe, chain, nonce), ascending. A Safe executes
/// each nonce exactly once, so every one of these is mutually exclusive with the intent.
///
/// Read without syncing: an agent may poll, and a sync shells out to rsync over ssh with a
/// five-second timeout per peer. A rival a co-signer started and has not pushed yet is
/// therefore invisible here — this guard keeps the operator's queue clean, it is not a lock.
pub fn slot_held(intent: &SafeTxIntent) -> Result<Vec<B256>, McpErr> {
    let mut held = Vec::new();
    for (slot, bundles) in hc_bundle::list(SyncMode::Off)? {
        if slot.safe != intent.safe
            || slot.chain_id != intent.chain_id
            || slot.nonce != intent.nonce
        {
            continue;
        }
        for one in bundles {
            held.push(one.hash);
        }
    }
    Ok(held)
}

/// A proposal that passed every guard, holding the intent one bundle will be filed from.
pub struct Proposal {
    intent: SafeTxIntent,
    summary: String,
}

impl Proposal {
    /// Everything that can refuse, in the order it must run, all of it before any write: the
    /// Safe has to be one this machine describes, its (Safe, chain, nonce) slot has to be free,
    /// the queue has to be under its cap, and the policy has to allow the call. A denial ends
    /// here and leaves nothing behind — a stored denial is a permanently unsignable row filling
    /// the very queue the dry run exists to protect.
    pub fn check(intent: SafeTxIntent) -> Result<Self, McpErr> {
        Safes::load()?.find(intent.safe, intent.chain_id)?;

        if let Some(held) = slot_held(&intent)?.first() {
            return Err(McpErr::SlotTaken {
                nonce: intent.nonce,
                held: *held,
            });
        }

        let config = Config::load()?;
        let root = bundles_dir();
        let mut pending = 0;
        if root.is_dir() {
            for entry in std::fs::read_dir(&root)? {
                if entry?.file_type()?.is_dir() {
                    pending += 1;
                }
            }
        }
        let max = config.mcp_max_pending();
        if pending >= max {
            return Err(McpErr::PendingCapReached { pending, max });
        }

        let policy = Policy::load(&config.store_path(), &intent.key)?;
        let (_approved, summary) =
            hc_sign::sign::prepare(intent.clone(), &policy, B256::ZERO, &config)?;
        Ok(Proposal { intent, summary })
    }

    /// The decoded text the approval prompt will show, so the agent describes the transaction
    /// in the same words the operator is about to read.
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// File the bundle and push it to every enrolled peer: a proposal a co-signer cannot see is
    /// half a proposal.
    pub fn file(self) -> Result<B256, McpErr> {
        Ok(hc_bundle::new(SyncMode::On, self.intent)?)
    }
}
