//! The one capability in this crate that writes.
//!
//! [`Proposal`] mirrors the signer's `Approved`: private fields, no constructor but
//! [`Proposal::check`], and [`Proposal::file`] takes it by value. So a bundle that was not
//! policy-checked cannot be filed, because there is no other way to reach the write — the same
//! trick the signer uses to make "the policy ran before the prompt" a fact of the type system.
//!
//! The dry run is the signer's own `prepare`, not a second implementation of it, so what this
//! server accepts cannot drift from what the signer will actually do. The `Approved` it hands
//! back is dropped on the spot: this crate has no way to spend one.
//!
//! Everything that can be decided without the bundle tree — the allow-lists, the Safe, the
//! policy and the whole dry run — is decided BEFORE the exclusive claim is taken. The claim then
//! covers exactly the queue read and the write, which is the shortest span that still closes the
//! check-then-file race, because the operator's CLI takes the same try-lock and fails outright
//! when it loses.
use crate::limits::{allows, place_nonce, NonceWindow};
use crate::McpErr;
use alloy_primitives::{B256, U256};
use hc_bundle::sync::SyncMode;
use hc_bundle::Safes;
use hc_core::config::{Config, Mcp};
use hc_sign::intent::SafeTxIntent;
use hc_sign::policy::Policy;
use std::os::unix::fs::MetadataExt;

/// Milliseconds since this machine's kernel stamped the bundle directory. A bundle's own
/// `created_at_ms` is whatever the machine that wrote it says, so measuring a lifetime against
/// it would let one peer backdate a proposal out of the cap that bounds the agent.
fn local_age_ms(hash: B256, now: u64) -> Result<u64, McpErr> {
    let meta = std::fs::symlink_metadata(hc_bundle::bundle_dir(hash))?;
    let stamped = meta
        .ctime()
        .saturating_mul(1000)
        .saturating_add(meta.ctime_nsec() / 1_000_000);
    let now = i64::try_from(now).unwrap_or(i64::MAX);
    Ok(u64::try_from(now.saturating_sub(stamped)).unwrap_or(0))
}

/// What the local queue holds that bears on one intent, read in a single pass.
pub struct Queue {
    /// Live bundles anywhere in the tree, which is what the pending cap counts.
    pub live: usize,
    /// Live digests already claiming this intent's (Safe, chain, nonce).
    pub slot: Vec<B256>,
    /// The lowest nonce still live for this intent's (Safe, chain).
    pub lowest_nonce: Option<U256>,
}

impl Queue {
    /// Read under a claim the caller holds. An unsigned proposal past its lifetime stops
    /// counting and stops holding its slot: filling the queue otherwise wedges it — and every
    /// peer's, since a proposal is pushed — until a human clears it by hand. A proposal that has
    /// collected even one signature never expires, because that is the operator's own work.
    pub fn read(
        mutation: &hc_bundle::Mutation,
        intent: &SafeTxIntent,
        ttl_ms: u64,
    ) -> Result<Self, McpErr> {
        let now = hc_sign::grant::now_ms()?;
        let mut queue = Queue {
            live: 0,
            slot: Vec::new(),
            lowest_nonce: None,
        };
        for (slot, bundles) in hc_bundle::list_locked(mutation)? {
            let ours = slot.safe == intent.safe && slot.chain_id == intent.chain_id;
            for one in bundles {
                if one.bundle.signatures.is_empty() && local_age_ms(one.hash, now)? >= ttl_ms {
                    continue;
                }
                queue.live += 1;
                if !ours {
                    continue;
                }
                if queue.lowest_nonce.is_none_or(|lowest| slot.nonce < lowest) {
                    queue.lowest_nonce = Some(slot.nonce);
                }
                if slot.nonce == intent.nonce {
                    queue.slot.push(one.hash);
                }
            }
        }
        Ok(queue)
    }
}

/// Read the queue under a claim of its own.
///
/// Read without syncing: an agent may poll, and a sync shells out to rsync over ssh with a
/// five-second timeout per peer. A rival a co-signer started and has not pushed yet is therefore
/// invisible here — this guard keeps the operator's queue clean, it is not a lock.
pub fn survey(mcp: &Mcp, intent: &SafeTxIntent) -> Result<Queue, McpErr> {
    let mutation = hc_bundle::Mutation::take()?;
    Queue::read(&mutation, intent, mcp.proposal_ttl_ms())
}

/// A proposal that passed every guard, holding the intent one bundle will be filed from.
pub struct Proposal {
    mutation: hc_bundle::Mutation,
    intent: SafeTxIntent,
    summary: hc_sign::adapter::Summary,
    nonce: NonceWindow,
}

impl Proposal {
    /// Everything that can refuse, in the order it must run, all of it before any write: the key
    /// and the Safe have to be ones the agent may name, the Safe has to be one this machine
    /// describes, the policy has to allow the call, the (Safe, chain, nonce) slot has to be
    /// free, the queue has to be under its cap, and the nonce has to sit inside the window the
    /// operator's approval is measured against. A denial ends here and leaves nothing behind — a
    /// stored denial is a permanently unsignable row filling the very queue this protects.
    pub fn check(config: &Config, intent: SafeTxIntent) -> Result<Self, McpErr> {
        allows(config.mcp(), &intent)?;
        Safes::load()?.find(intent.safe, intent.chain_id)?;
        let policy = Policy::load(&config.store_path(), &intent.key)?;
        let (_approved, summary) =
            hc_sign::sign::prepare(intent.clone(), &policy, None, B256::ZERO, config)?;

        let mutation = hc_bundle::Mutation::take()?;
        let queue = Queue::read(&mutation, &intent, config.mcp().proposal_ttl_ms())?;
        if let Some(held) = queue.slot.first() {
            return Err(McpErr::SlotTaken {
                nonce: intent.nonce,
                held: *held,
            });
        }
        let max = config.mcp().max_pending();
        if queue.live >= max {
            return Err(McpErr::PendingCapReached {
                pending: queue.live,
                max,
            });
        }
        let nonce = place_nonce(config.mcp(), &intent, queue.lowest_nonce);
        nonce.accept()?;
        Ok(Proposal {
            mutation,
            intent,
            summary,
            nonce,
        })
    }

    /// What the approval prompt will show, in two parts: the decoded body the agent may be told
    /// so it describes the transaction in the operator's own words, and the alarms, which are
    /// the operator's alone.
    pub fn summary(&self) -> &hc_sign::adapter::Summary {
        &self.summary
    }

    /// Where the nonce the agent chose sits against the anchor, which is what says whether this
    /// approval executes next or behind however many transactions the agent likes.
    pub fn nonce(&self) -> NonceWindow {
        self.nonce
    }

    /// File the bundle and push it to every enrolled peer: a proposal a co-signer cannot see is
    /// half a proposal.
    pub fn file(self) -> Result<B256, McpErr> {
        Ok(self.mutation.new(SyncMode::On, self.intent)?)
    }
}
