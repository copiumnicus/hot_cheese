//! The one gauge no subsystem already publishes — requests queued for this session's approver —
//! and the handle a renderer reads every live fact through.
//!
//! Nothing here owns store, bundle or peer state: [`crate::git_store::GitStatus`] and
//! [`crate::bundle_poll::BundlePoll`] are the single definitions of those, and this module holds
//! their `Arc`s rather than a second copy of what they say.
use crate::bundle_poll::BundlePoll;
use crate::git_store::{GitOp, GitStore, Relation};
use crate::runtime::UnlockGate;
use hc_core::config::Config;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Requests handed to the approver and not yet answered.
#[derive(Debug, Default)]
pub struct Pending {
    count: AtomicUsize,
}

impl Pending {
    /// What the band shows. A display counter, so `Relaxed` is the whole ordering it needs.
    pub fn get(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}

/// One queued request, counted for exactly as long as it is outstanding. The count has one
/// increment site and one decrement site, both here, so a connection task that is cancelled
/// mid-await or unwinds still gives its slot back.
pub struct Outstanding {
    pending: Arc<Pending>,
}

impl Outstanding {
    pub fn new(pending: Arc<Pending>) -> Self {
        pending.count.fetch_add(1, Ordering::Relaxed);
        Self { pending }
    }
}

impl Drop for Outstanding {
    fn drop(&mut self) {
        self.pending.count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Every live subsystem a renderer reads, in one handle, so a widget takes one argument instead
/// of four. It holds handles and copies nothing: `config`, `git` and `bundles` are the same
/// `Arc`s [`crate::runtime::Runtime`] holds.
#[derive(Clone)]
pub struct Live {
    /// Remote and peer enrolment: what decides which chips exist at all.
    pub config: Arc<Config>,
    /// Which KEK opened this session, and therefore whether anything is ever served.
    pub gate: UnlockGate,
    /// The git store's own status object, and the fetch the Status panel asks for.
    pub git: Arc<GitStore>,
    /// The bundle poller's own status object.
    pub bundles: Arc<BundlePoll>,
    /// Requests queued for this session's approver.
    pub pending: Arc<Pending>,
}

/// How many remotes are in one state, and when the newest of them was recorded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Remotes in this state.
    pub count: usize,
    /// Unix seconds of the newest one; `None` when none of them carries a stamp.
    pub at: Option<u64>,
}

/// Exactly what one band line renders from: counts, relations and stamps, owned, with no `Arc`
/// and no guard, so the render runs outside both subsystems' locks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BandSource {
    /// Unix seconds the band was built at, so the render is pure over its argument.
    pub now: u64,
    /// Which KEK opened this session.
    pub gate: UnlockGate,
    /// Configured backup remotes: what decides whether the store chips exist at all.
    pub remotes: usize,
    /// The worst relation any configured remote reported at its last fetch.
    pub relation: Relation,
    /// How many remotes are in that relation, and the newest fetch that learned it.
    pub relation_seen: Tally,
    /// A fetch is running right now.
    pub fetching: bool,
    /// Newest successful push across the remotes.
    pub pushed_at: Option<u64>,
    /// Remotes whose last recorded failure was a push.
    pub push_failed: Tally,
    /// Remotes whose last recorded failure was anything else.
    pub store_failed: Tally,
    /// Enrolled bundle peers: what decides whether the bundle chips exist at all.
    pub peers: usize,
    /// Peers whose last pull succeeded and that have been reached at least once.
    pub peers_ok: usize,
    /// Unix seconds the last bundle tick finished.
    pub polled_at: Option<u64>,
    /// Bundle directories this machine holds.
    pub bundles: usize,
    /// How many of them have met their threshold.
    pub ready: usize,
    /// Files quarantined since this session started.
    pub quarantined: u64,
    /// Whether the last bundle tick failed.
    pub poll_failed: bool,
    /// Requests waiting for approval.
    pub pending: usize,
}

/// The order the band shows one remote over another: the worst is the one an operator has to act
/// on, and a fork outranks everything.
fn severity(relation: Relation) -> u8 {
    match relation {
        Relation::InSync => 0,
        Relation::LocalAhead => 1,
        Relation::Absent => 2,
        Relation::RemoteAhead => 3,
        Relation::Unknown => 4,
        Relation::Diverged => 5,
    }
}

impl Live {
    /// Everything the band needs, taken in one pass so each subsystem's lock is taken once and
    /// dropped before anything is rendered. No filesystem, no subprocess, no network: every fact
    /// here was produced by a background task on its own cadence and stored.
    pub fn band_source(&self, now: u64) -> BandSource {
        let git = self.git.status().snapshot();
        let mut worst: Option<Relation> = None;
        for remote in &git.remotes {
            if worst.is_none_or(|seen| severity(remote.relation) > severity(seen)) {
                worst = Some(remote.relation);
            }
        }
        let relation = worst.unwrap_or(Relation::Unknown);
        let mut relation_seen = Tally::default();
        let mut pushed_at = None;
        let mut push_failed = Tally::default();
        let mut store_failed = Tally::default();
        for remote in &git.remotes {
            if remote.relation == relation {
                relation_seen.count += 1;
                relation_seen.at = relation_seen.at.max(remote.last_fetch_ok_at);
            }
            pushed_at = pushed_at.max(remote.last_push_ok_at);
            if let Some(failure) = &remote.last_failure {
                let tally = match failure.op {
                    GitOp::Push => &mut push_failed,
                    _ => &mut store_failed,
                };
                tally.count += 1;
                tally.at = tally.at.max(Some(failure.at));
            }
        }

        let poll = self.bundles.status();
        let mut peers_ok = 0usize;
        for peer in &poll.peers {
            if peer.pull.is_ok() && peer.last_ok_at.is_some() {
                peers_ok += 1;
            }
        }
        let polled_at = poll.last_finished_at;
        let bundles = poll.bundles;
        let ready = poll.ready;
        let quarantined = poll.quarantined;
        let poll_failed = poll.failure.is_some();
        drop(poll);

        BandSource {
            now,
            gate: self.gate,
            remotes: self.config.backup_remotes.len(),
            relation,
            relation_seen,
            fetching: git.fetching,
            pushed_at,
            push_failed,
            store_failed,
            peers: self.config.bundle_peers.len(),
            peers_ok,
            polled_at,
            bundles,
            ready,
            quarantined,
            poll_failed,
            pending: self.pending.get(),
        }
    }
}
