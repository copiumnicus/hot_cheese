//! Rendering a decoded call as the line naming the action.
//!
//! A SELECTOR IS NOT A CONTRACT, and now neither is a signature: what a decode proves is the ABI
//! shape of the bytes, never the nature of the address they are sent to. `transfer(to=…,
//! amount=…)` says the calldata is a `transfer(address,uint256)` call, not that the destination
//! is an ERC-20. So the labels a human reads come from the OPERATOR — they are the names written
//! beside each argument in the policy file — rather than from a table that guessed which standard
//! was meant, and only a `max` rule's `amount_of` ever scales an integer.
//!
//! `multiSend` is the one call whose arguments are themselves calls, so it hands off to
//! [`batch`](super::batch) rather than printing a `bytes` blob.
use super::{annotate, batch, Body, TypedCall};
use crate::schema::FieldRule;
use alloy_dyn_abi::DynSolValue;
use alloy_primitives::U256;
use hc_core::config::Config;

/// The decoded call as `name(label=value, …)`, with one entry per DECLARED argument in
/// signature order. Nothing is ever dropped: an argument the rule set somehow does not name is
/// still printed, under its position, because an argument that never reaches the screen is an
/// argument the human cannot approve.
pub(super) fn render(call: &TypedCall, config: &Config) -> String {
    if let Body::Batch { entries, .. } = &call.body {
        return batch::render(entries, config);
    }
    let mut out = String::new();
    out.push_str(&call.rule.signature.function().name);
    out.push('(');
    for (at, value) in call.args.iter().enumerate() {
        if at > 0 {
            out.push_str(", ");
        }
        match call.rule.at(at) {
            Some(arg) => out.push_str(&format!(
                "{}={}",
                arg.name,
                shown(&arg.rule, value, call.site.chain_id, config)
            )),
            None => out.push_str(&format!(
                "@{at}={}",
                plain(value, call.site.chain_id, config)
            )),
        }
    }
    out.push(')');
    out
}

/// One value, rendered under the rule that bounds it. Only a `max` rule changes anything: it
/// names the contract whose decimals scale the integer, which is the one thing the value's own
/// type cannot say.
fn shown(rule: &FieldRule, value: &DynSolValue, chain_id: U256, config: &Config) -> String {
    match (rule, value) {
        (FieldRule::Max { amount_of, .. }, DynSolValue::Uint(v, _)) => {
            annotate::amount(*v, *amount_of, chain_id, config)
        }
        (
            FieldRule::Each { of, .. },
            DynSolValue::Array(items) | DynSolValue::FixedArray(items),
        ) => {
            let mut out = String::from("[");
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push_str(", ");
                }
                out.push_str(&shown(of, item, chain_id, config));
            }
            out.push(']');
            out
        }
        _ => plain(value, chain_id, config),
    }
}

/// One value by its own decoded type. An address is always written in full before a name can be
/// appended, an integer is always the exact integer, and `bytes` carries its hex plus the UTF-8
/// text when it is valid — appended, never substituted.
pub(super) fn plain(value: &DynSolValue, chain_id: U256, config: &Config) -> String {
    match value {
        DynSolValue::Address(a) => annotate::address(*a, chain_id, config),
        DynSolValue::Uint(v, _) => annotate::count(*v),
        DynSolValue::Int(v, _) => v.to_string(),
        DynSolValue::Bool(b) => b.to_string(),
        DynSolValue::FixedBytes(w, n) => format!("0x{}", hex::encode(&w[..*n])),
        DynSolValue::Function(f) => format!("0x{}", hex::encode(f.as_slice())),
        DynSolValue::String(s) => format!("{s:?}"),
        DynSolValue::Bytes(b) => match std::str::from_utf8(b) {
            Ok(text) => format!("0x{} {text:?}", hex::encode(b)),
            Err(_) => format!("0x{}", hex::encode(b)),
        },
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) | DynSolValue::Tuple(items) => {
            let mut out = String::from("[");
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push_str(", ");
                }
                out.push_str(&plain(item, chain_id, config));
            }
            out.push(']');
            out
        }
        DynSolValue::CustomStruct {
            name,
            prop_names,
            tuple,
        } => {
            let mut out = format!("{name}{{");
            for (n, item) in tuple.iter().enumerate() {
                if n > 0 {
                    out.push_str(", ");
                }
                let label = prop_names.get(n).map(String::as_str).unwrap_or("?");
                out.push_str(&format!("{label}={}", plain(item, chain_id, config)));
            }
            out.push('}');
            out
        }
    }
}
