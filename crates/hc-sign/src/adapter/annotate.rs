//! The one place `config.toml` reaches an approval summary.
//!
//! Annotation is additive and never authoritative, and that is a property of this module rather
//! than of its callers: an address is always written in full before a name can be appended, an
//! amount always carries the integer that was actually submitted, and an unconfigured
//! `(address, chain_id)` renders exactly the bytes an empty table renders. So a wrong or hostile
//! table entry can add noise to the text a human reads, and can never subtract truth from it.
use alloy_primitives::{Address, U256};
use hc_core::config::{Config, TokenAnnotation};

/// Bit width past which an amount exceeds any plausible token supply.
const HUGE_AMOUNT_BITS: usize = 128;

fn marked(body: String, v: U256) -> String {
    if v == U256::MAX {
        return format!("{body} \u{26a0} UNLIMITED (2^256-1)");
    }
    if v.bit_len() > HUGE_AMOUNT_BITS {
        return format!("{body} \u{26a0} HUGE (>2^{HUGE_AMOUNT_BITS})");
    }
    body
}

/// A quantity no table can describe — an owner threshold — as the exact integer, called out when
/// it is past anything a real payment carries.
pub(super) fn count(v: U256) -> String {
    marked(v.to_string(), v)
}

fn find(config: &Config, address: Address, chain_id: U256) -> Option<&TokenAnnotation> {
    config
        .token
        .iter()
        .find(|t| t.address == address && t.chain_id == chain_id)
}

/// `U256::to_string()` with a decimal point cut into it: left-pad to `decimals + 1` digits, then
/// split there. No float ever touches an amount, and no trailing zero is trimmed — trimming would
/// render `1.10` and `1.1` alike and hide how many decimals were assumed.
fn scaled(v: U256, decimals: u8) -> String {
    let width = usize::from(decimals) + 1;
    let digits = v.to_string();
    let padded = format!("{digits:0>width$}");
    if decimals == 0 {
        return padded;
    }
    let point = padded.len() - usize::from(decimals);
    format!("{}.{}", &padded[..point], &padded[point..])
}

/// A token quantity as BOTH the scaled amount and the raw integer, so a wrong `decimals` in the
/// table is bounded by the integer printed beside it. `token` is the contract the call is made
/// TO — decimals belong to the contract being called, never to a spender or a recipient — and
/// `Address::ZERO` names the chain's native asset. An unconfigured contract renders the integer
/// alone: nothing here ever guesses 18.
pub(super) fn amount(v: U256, token: Address, chain_id: U256, config: &Config) -> String {
    match find(config, token, chain_id) {
        Some(t) => marked(format!("{} {} ({v})", scaled(v, t.decimals), t.symbol), v),
        None => count(v),
    }
}

/// The full EIP-55 address, then a configured name in parentheses. Never `{:#}`, which is
/// alloy's middle-out truncation, and never a name on its own: truncating an address destroys
/// the injectivity a reader is relying on, and is exactly what makes a lookalike address — two
/// addresses are trivially ground to share their leading hex digits — pass for the real one.
pub(super) fn address(a: Address, chain_id: U256, config: &Config) -> String {
    for label in &config.label {
        if label.address == a && label.chain_id == chain_id {
            return format!("{a} ({})", label.name);
        }
    }
    a.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VENDOR: Address = Address::new([0x33u8; 20]);
    const TOKEN: Address = Address::new([0x22u8; 20]);
    const CHAIN: u64 = 1;

    fn config(tables: &str) -> Config {
        toml::from_str(&format!(
            "service = \"\"\naccount = \"\"\nstore = \"/nonexistent\"\n{tables}"
        ))
        .expect("the annotation tables parse")
    }

    fn usdc(decimals: u8) -> Config {
        config(&format!(
            "[[token]]\naddress = \"{TOKEN}\"\nchain_id = {CHAIN}\n\
             symbol = \"USDC\"\ndecimals = {decimals}\nstandard = \"erc20\"\n"
        ))
    }

    /// A name is added to an address and can never stand in for one: the full checksummed text
    /// survives verbatim, on the labelled chain and on any other, so a reader comparing the
    /// address they were given against the sheet is never comparing prose instead.
    #[test]
    fn a_label_is_appended_to_the_whole_address_never_substituted_for_it() {
        let labelled = config(&format!(
            "[[label]]\naddress = \"{VENDOR}\"\nchain_id = {CHAIN}\nname = \"Vendor payouts\"\n"
        ));
        let chain = U256::from(CHAIN);
        let shown = address(VENDOR, chain, &labelled);
        assert!(shown.contains(&VENDOR.to_string()));
        assert_eq!(shown, format!("{VENDOR} (Vendor payouts)"));

        assert_eq!(address(VENDOR, U256::from(10u64), &labelled), VENDOR.to_string());
        assert_eq!(address(TOKEN, chain, &labelled), TOKEN.to_string());
        assert_eq!(address(VENDOR, chain, &config("")), VENDOR.to_string());
    }

    /// Decimals are an operator's claim about a contract, so the amount that was actually
    /// submitted is printed beside every scaled one: a right table reads `1.000000 USDC`, a wrong
    /// table still shows `1000000`, and no table at all reads exactly as it did before there were
    /// tables. Scaling is decimal-string surgery, so nothing is rounded and no zero is trimmed.
    #[test]
    fn an_amount_shows_the_scaled_and_the_raw_form_together() {
        let chain = U256::from(CHAIN);
        let raw = U256::from(1_000_000u64);

        assert_eq!(
            amount(raw, TOKEN, chain, &usdc(6)),
            "1.000000 USDC (1000000)"
        );
        assert_eq!(amount(raw, TOKEN, chain, &config("")), "1000000");
        assert_eq!(amount(raw, VENDOR, chain, &usdc(6)), "1000000");
        assert_eq!(amount(raw, TOKEN, U256::from(10u64), &usdc(6)), "1000000");

        let wrong = amount(raw, TOKEN, chain, &usdc(18));
        assert!(wrong.contains("(1000000)"), "{wrong}");
        assert_eq!(wrong, "0.000000000001000000 USDC (1000000)");

        assert_eq!(amount(U256::from(11u64), TOKEN, chain, &usdc(1)), "1.1 USDC (11)");
        assert_eq!(
            amount(U256::from(110u64), TOKEN, chain, &usdc(2)),
            "1.10 USDC (110)"
        );
        assert_eq!(amount(U256::ZERO, TOKEN, chain, &usdc(6)), "0.000000 USDC (0)");
        assert_eq!(amount(raw, TOKEN, chain, &usdc(0)), "1000000 USDC (1000000)");

        let unlimited = amount(U256::MAX, TOKEN, chain, &usdc(6));
        assert!(unlimited.contains(&U256::MAX.to_string()));
        assert!(unlimited.ends_with(" \u{26a0} UNLIMITED (2^256-1)"));
        assert_eq!(count(U256::MAX), amount(U256::MAX, TOKEN, chain, &config("")));
    }
}
