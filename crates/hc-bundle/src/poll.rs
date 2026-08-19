//! One tick of bundle polling: pull from one peer, judge only what that pull changed, name what
//! arrived, and push back only what this device wrote.
//!
//! The loop, the clock, the thread and the status belong to the caller — `hc_daemon`'s
//! `bundle_poll` — exactly as they did for the foreground pollers this replaces. Nothing here
//! spawns or backgrounds anything, and nothing here reaches a key.
//!
//! This machine is not a relay. A tick pushes the digests in [`Poller::contributed`] and nothing
//! else, so a bundle a hostile peer injected is never redistributed unattended. Signatures still
//! converge because every device pulls [`Scope::All`] from every peer it enrolled — which makes
//! enrolment load-bearing in BOTH directions.
use crate::ingest::{Delivered, Ingest, Verdict};
use crate::sync::{self, SyncErr, Truncated};
use crate::{bundle_dir, loaded, Arrival, Scope};
use alloy_primitives::{Address, B256};
use err_mac::create_err_with_impls;
use hashbrown::{HashMap, HashSet};
use hc_core::config::BundlePeer;

create_err_with_impls!(
    #[derive(Debug)]
    pub PollErr,
    PollerGone,
    Config(hc_core::config::ConfigErr),
    Ingest(crate::ingest::IngestErr),
    Bundle(crate::BundleErr),
    Grant(hc_sign::grant::GrantErr),
    Lock(crate::lock::LockErr)
    ;
    PokeTimedOut { secs: u64 }
);

/// What one judging pass of the tree found.
pub struct Stock {
    /// Signatures that were not in the tree at the previous pass.
    pub arrivals: Vec<Arrival>,
    /// Bundle directories this machine holds.
    pub bundles: usize,
    /// How many of them meet their threshold.
    pub ready: usize,
    /// What the validator did to what is on disk.
    pub verdict: Verdict,
}

/// What one peer's half of a tick did.
pub struct PeerTick {
    /// The one [`Scope::All`] pull.
    pub pull: Result<(), SyncErr>,
    /// What that peer offered which this pull left for the next one.
    pub truncated: Truncated,
    /// Every contributed bundle pushed to this peer: the first failure, or `Ok` for all.
    pub push: Result<(), SyncErr>,
    /// Bundles pushed to this peer this tick.
    pub pushed: usize,
    /// What judging the tree after this peer's pull found; `None` when the pull never ran.
    pub stock: Option<Stock>,
}

/// One machine's view of the bundle tree between ticks.
pub struct Poller {
    ingest: Ingest,
    /// Signers each bundle held at the previous pass, so a pass can name what arrived.
    seen: HashMap<B256, HashSet<Address>>,
    /// Bundles this device wrote a file into, and the only ones a tick pushes.
    contributed: HashSet<B256>,
    /// Bundle directories the last pass found.
    bundles: usize,
    /// How many of them met their threshold when they were last loaded.
    ready: usize,
}

impl Poller {
    /// Prime from what is already on this disk, judging it once, without touching a peer. What is
    /// already here has not ARRIVED, so the priming pass's own stock is taken and dropped.
    pub fn start() -> Result<Self, PollErr> {
        let mut poller = Poller {
            ingest: Ingest::new()?,
            seen: HashMap::new(),
            contributed: HashSet::new(),
            bundles: 0,
            ready: 0,
        };
        poller.stock()?;
        Ok(poller)
    }

    /// Record that this device wrote a file into a bundle, so a tick pushes it and no cap evicts
    /// it. Fed by an explicit poke and by nothing else — never by a pull, and never by what a
    /// directory happens to contain.
    pub fn contributed(&mut self, hash: B256) {
        self.contributed.insert(hash);
    }

    /// Judge the tree, then name every signature that was not there at the previous pass.
    ///
    /// The union is loaded only when the pass judged a file or a directory came or went: loading
    /// it ecrecovers every signature it holds, and a signature cannot appear in a file whose
    /// local identity did not move.
    pub fn stock(&mut self) -> Result<Stock, PollErr> {
        self.take_stock(Delivered::Locally)
    }

    /// One pass, crediting whatever appeared since the last one to `from`, which is what bounds
    /// one peer's share of the tree across every tick rather than within one.
    fn take_stock(&mut self, from: Delivered<'_>) -> Result<Stock, PollErr> {
        let verdict = self.ingest.validate(Scope::All, &self.contributed, from)?;
        let mut arrivals = Vec::new();
        if verdict.changed || verdict.judged > 0 || verdict.dirs != self.bundles {
            let mut ready = 0usize;
            let mut present = HashSet::new();
            for one in loaded(Scope::All)? {
                present.insert(one.hash);
                if one.quorum.met {
                    ready += 1;
                }
                let current: HashSet<Address> = one
                    .bundle
                    .signatures
                    .iter()
                    .map(|signature| signature.signer)
                    .collect();
                let seen = self.seen.entry(one.hash).or_default();
                for sig in &one.bundle.signatures {
                    if !seen.contains(&sig.signer) {
                        arrivals.push(Arrival {
                            hash: one.hash,
                            signer: sig.signer,
                            quorum: one.quorum,
                        });
                    }
                }
                *seen = current;
            }
            self.seen.retain(|hash, _| present.contains(hash));
            self.ready = ready;
        }
        self.bundles = verdict.dirs;
        Ok(Stock {
            arrivals,
            bundles: self.bundles,
            ready: self.ready,
            verdict,
        })
    }

    /// Pull the whole tree from one peer, judge what that pull changed, and push back the bundles
    /// this device wrote into. [`Scope::All`] on the pull is not a choice: the point of polling is
    /// to learn about a bundle a co-signer created and this machine has never seen, and no other
    /// scope can name it. The push runs even when the judging failed, because a signature that
    /// never leaves this disk is the one failure this loop must not have.
    pub fn pull_from(&mut self, peer: &BundlePeer) -> Result<PeerTick, PollErr> {
        // The transfer runs with no local claim held. A peer may stall for the whole rsync
        // timeout, and a claim held across that is one a `collect` behind a biometric cannot take.
        let pulled = sync::pull_from(peer, Scope::All);
        let truncated = match &pulled {
            Ok(truncated) => *truncated,
            Err(_) => Truncated::default(),
        };
        let pull = pulled.map(|_| ());
        let mutation = crate::lock::Lock::take()?;
        // rsync can install some files and then exit non-zero. Judge after every attempt, not
        // only a successful one, or a peer could leave a partially transferred poison file in
        // the live union until the next poll.
        let stock = Some(self.take_stock(Delivered::By(&peer.host)));
        self.contributed.retain(|hash| bundle_dir(*hash).is_dir());
        drop(mutation);
        let mut push = Ok(());
        let mut pushed = 0usize;
        for hash in &self.contributed {
            match sync::push_to(peer, Scope::One(*hash)) {
                Ok(()) => pushed += 1,
                Err(e) => {
                    if push.is_ok() {
                        push = Err(e);
                    }
                }
            }
        }
        Ok(PeerTick {
            pull,
            truncated,
            push,
            pushed,
            stock: stock.transpose()?,
        })
    }
}
