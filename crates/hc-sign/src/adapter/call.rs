//! Decoding the calldata arguments into the line naming the action.
//!
//! A SELECTOR IS NOT A CONTRACT. What a decode here proves is the ABI shape of the bytes, never
//! the nature of the address they are sent to: `transfer(to=…, amount=…)` says the calldata is a
//! `transfer(address,uint256)` call, not that the destination is an ERC-20. ERC-721's `approve`
//! and `transferFrom` are byte-identical in shape to ERC-20's — the decode is unambiguous, the
//! semantics are not — so the argument names stay neutral about which standard is meant unless a
//! `[[token]]` entry declares one, and `tokenId` is never scaled the way a quantity is.
//!
//! `multiSend` is the one decode whose arguments are themselves calls, so it hands off to
//! [`batch`](super::batch) rather than printing a `bytes` blob: the sub-calls inside are the part
//! [`policy`](crate::policy) never saw, and a line naming only the library would say nothing
//! about them.
//!
//! `permit` is printed field by field and nothing more is claimed of it. Its EIP-712 domain needs
//! the token's `name`, its `version` and the owner's on-chain `nonce`, none of which exist here
//! without an RPC client, so this never says the signature is valid, that it came from `owner`,
//! or what digest it covers. What holds with no chain state at all is that the authority it can
//! grant is bounded by `spender` and `value`, because an invalid signature reverts — which is the
//! whole reason an unlimited `value` still alarms.
use super::{annotate, batch, selector4, Known, Site};
use hc_core::config::Config;
use sha2::{Digest, Sha256};

/// Hex characters of the calldata digest shown when the arguments do not decode. All of them:
/// a truncated digest is a shorter hash, and 64 bits of it costs a birthday collision anyone
/// who can propose a transaction could grind, which is exactly how two different payloads would
/// come to print the same line.
const DIGEST_CHARS: usize = 64;

/// Render the arguments of the calls the `sol!` interface declares, so the human approves WHO
/// gets HOW MUCH instead of a selector label. `decoded` is the one canonical-only decode of this
/// payload: calldata that does not re-encode to the exact submitted bytes arrives here as `None`
/// and is reported as undecoded, named by its length and digest so two payloads can never render
/// the same. Amounts are scaled against the DESTINATION of this call, which is the contract whose
/// base units they are in. `site` is one call — the transaction's own, or one entry of a batch —
/// so a batch entry's arguments are read against the entry's destination, never the batch's.
pub(super) fn render(site: &Site, config: &Config, decoded: Option<&Known::KnownCalls>) -> String {
    if site.data.is_empty() {
        return "no calldata (value transfer only)".to_string();
    }
    let Some(decoded) = decoded else {
        let full = hex::encode(Sha256::digest(&site.data));
        let short: String = full.chars().take(DIGEST_CHARS).collect();
        let len = site.data.len();
        return match selector4(&site.data) {
            Some(s) => format!(
                "UNDECODED CALL 0x{}: {len} bytes, sha256 {short}",
                hex::encode(s)
            ),
            None => format!("UNDECODED CALL: {len} bytes, sha256 {short}"),
        };
    };
    let who = |a| annotate::address(a, site.chain_id, config);
    let how_much = |v| annotate::amount(v, site.to, site.chain_id, config);
    match decoded {
        Known::KnownCalls::multiSend(c) => batch::render(&c.transactions, site, config),
        Known::KnownCalls::transfer(c) => {
            format!("transfer(to={}, amount={})", who(c.to), how_much(c.amount))
        }
        Known::KnownCalls::approve(c) => {
            format!(
                "approve(spender={}, amount={})",
                who(c.spender),
                how_much(c.amount)
            )
        }
        Known::KnownCalls::transferFrom(c) => format!(
            "transferFrom(from={}, to={}, amount={})",
            who(c.from),
            who(c.to),
            how_much(c.amount)
        ),
        Known::KnownCalls::increaseAllowance(c) => format!(
            "increaseAllowance(spender={}, added={})",
            who(c.spender),
            how_much(c.addedValue)
        ),
        Known::KnownCalls::decreaseAllowance(c) => format!(
            "decreaseAllowance(spender={}, subtracted={})",
            who(c.spender),
            how_much(c.subtractedValue)
        ),
        Known::KnownCalls::setApprovalForAll(c) => format!(
            "setApprovalForAll(operator={}, approved={})",
            who(c.operator),
            c.approved
        ),
        Known::KnownCalls::permit(c) => format!(
            "permit(owner={}, spender={}, value={}, deadline={}, v={}, r={}, s={})",
            who(c.owner),
            who(c.spender),
            how_much(c.value),
            annotate::count(c.deadline),
            c.v,
            c.r,
            c.s
        ),
        Known::KnownCalls::safeTransferFrom_0(c) => format!(
            "safeTransferFrom(from={}, to={}, tokenId={})",
            who(c.from),
            who(c.to),
            annotate::count(c.tokenId)
        ),
        Known::KnownCalls::safeTransferFrom_1(c) => format!(
            "safeTransferFrom(from={}, to={}, tokenId={}, data={})",
            who(c.from),
            who(c.to),
            annotate::count(c.tokenId),
            c.data
        ),
        Known::KnownCalls::enableModule(c) => {
            format!("enableModule(module={})", who(c.module))
        }
        Known::KnownCalls::disableModule(c) => format!(
            "disableModule(prevModule={}, module={})",
            who(c.prevModule),
            who(c.module)
        ),
        Known::KnownCalls::setGuard(c) => format!("setGuard(guard={})", who(c.guard)),
        Known::KnownCalls::setFallbackHandler(c) => {
            format!("setFallbackHandler(handler={})", who(c.handler))
        }
        Known::KnownCalls::approveHash(c) => {
            format!("approveHash(hash={})", c.hashToApprove)
        }
        Known::KnownCalls::swapOwner(c) => format!(
            "swapOwner(prevOwner={}, oldOwner={}, newOwner={})",
            who(c.prevOwner),
            who(c.oldOwner),
            who(c.newOwner)
        ),
        Known::KnownCalls::addOwnerWithThreshold(c) => format!(
            "addOwnerWithThreshold(owner={}, threshold={})",
            who(c.owner),
            annotate::count(c.threshold)
        ),
        Known::KnownCalls::removeOwner(c) => format!(
            "removeOwner(prevOwner={}, owner={}, threshold={})",
            who(c.prevOwner),
            who(c.owner),
            annotate::count(c.threshold)
        ),
        Known::KnownCalls::changeThreshold(c) => {
            format!("changeThreshold(threshold={})", annotate::count(c.threshold))
        }
    }
}
