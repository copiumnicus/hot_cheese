//! The write path end to end in a throwaway home, driven through `dispatch` the way a client
//! drives it.
//!
//! ONE test function, deliberately. `HOT_CHEESE_HOME` is read through `std::env::var`, so a
//! second test setting it on another harness thread would race this one; owning the process
//! environment is the whole reason this lives in its own binary. Nothing here prompts, unlocks
//! or reaches hardware — the proposal server cannot, which is the point being tested.
use hc_mcp::rpc::Server;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const SAFE: &str = "0x1111111111111111111111111111111111111111";
const TOKEN: &str = "0x2222222222222222222222222222222222222222";
const RECIPIENT: &str = "0x3333333333333333333333333333333333333333";
const ELSEWHERE: &str = "0x9999999999999999999999999999999999999999";
const TRANSFER: &str = "transfer(address,uint256)";

/// A home holding exactly what the proposal server reads: a config, a `safes.toml`, a policy.
fn home() -> PathBuf {
    let home = std::env::temp_dir().join("hot_cheese_mcp_propose");
    let _ = std::fs::remove_dir_all(&home);
    let store = home.join("store");
    std::fs::create_dir_all(store.join("policies")).expect("make the policy dir");
    std::fs::create_dir_all(home.join("bundles")).expect("make the bundles dir");

    let config = home.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "service = \"\"\naccount = \"\"\nstore = \"{}\"\n\n[mcp]\nmax_pending = 4\nkeys = \
             [\"AGENT\"]\nsafes = [\"{SAFE}\"]\nnonce_window = 2\nlock_cooldown_ms = \
             0\n\n[[mcp.anchor]]\nsafe = \"{SAFE}\"\nchain_id = 1\nnonce = 7\n",
            store.display()
        ),
    )
    .expect("write the config");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
        .expect("an allow-list any other account can rewrite allows nothing");

    std::fs::write(
        home.join("bundles").join("safes.toml"),
        format!(
            "[[safe]]\naddress = \"{SAFE}\"\nchain_id = 1\nthreshold = 2\nowners = \
             [\"0x3333333333333333333333333333333333333333\", \
             \"0x4444444444444444444444444444444444444444\"]\n"
        ),
    )
    .expect("write safes.toml");
    std::fs::write(
        store.join("policies").join("AGENT.toml"),
        format!(
            r#"safe = "{SAFE}"
chain_id = 1

[[allow]]
to = "{TOKEN}"
max_value = "0"
operation = "call"

  [[allow.call]]
  signature = "{TRANSFER}"

    [[allow.call.arg]]
    at = 0
    name = "to"
    rule = {{ one_of = {{ addresses = ["{RECIPIENT}"] }} }}

    [[allow.call.arg]]
    at = 1
    name = "amount"
    rule = {{ max = {{ max = "1000", amount_of = "{TOKEN}" }} }}
"#
        ),
    )
    .expect("write the policy");
    home
}

fn transfer(token: &str, amount: u64, nonce: u64) -> Value {
    json!({
        "key": "AGENT",
        "safe": SAFE,
        "chain_id": 1,
        "token": token,
        "recipient": RECIPIENT,
        "amount": amount,
        "nonce": nonce,
    })
}

fn named(key: &str, safe: &str, nonce: u64) -> Value {
    json!({
        "key": key,
        "safe": safe,
        "chain_id": 1,
        "token": TOKEN,
        "recipient": RECIPIENT,
        "amount": 1,
        "nonce": nonce,
    })
}

fn propose(server: &mut Server, id: u64, transfer: &Value) -> Value {
    let request = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": "propose_erc20_transfer", "arguments": transfer},
    });
    let line = server
        .dispatch(&serde_json::to_string(&request).expect("render the request"))
        .expect("a call carrying an id is answered");
    serde_json::from_str(&line).expect("the answer is one line of json")
}

fn text(answer: &Value) -> String {
    answer["result"]["content"][0]["text"]
        .as_str()
        .expect("a tool result carries text")
        .to_string()
}

fn dirs(path: &Path) -> usize {
    let mut found = 0;
    for entry in std::fs::read_dir(path).expect("read the bundles dir") {
        if entry
            .expect("read a directory entry")
            .file_type()
            .expect("stat a directory entry")
            .is_dir()
        {
            found += 1;
        }
    }
    found
}

/// A refused proposal must reach the MODEL rather than abort the turn, must leave the operator's
/// queue exactly as it found it — a stored denial is a permanently unsignable row — and must
/// name which rule refused WITHOUT handing back what that rule contains, because an agent that
/// reads its own refusals otherwise maps the whole policy without writing anything. Then the
/// three bounds an adversarial agent runs into: a Safe executes each nonce once, so a taken
/// nonce is refused by the digest holding it; a nonce far above the anchor is refused because
/// that approval would execute at a time the operator did not agree to; and a key or a Safe
/// outside the `[mcp]` allow-lists is not proposable at all.
#[test]
fn a_denial_names_only_its_rule_and_every_bound_holds_against_the_agent() {
    let home = home();
    std::env::set_var("HOT_CHEESE_HOME", &home);
    let bundles = home.join("bundles");
    let mut server = Server::default();

    let denied = propose(&mut server, 1, &transfer(ELSEWHERE, 1, 7));
    assert!(
        denied.get("error").is_none(),
        "a policy denial is a result the model can correct, never a JSON-RPC error: {denied}"
    );
    assert_eq!(denied["result"]["isError"], json!(true), "{denied}");
    let refusal = text(&denied);
    assert!(
        refusal.contains("ToNotAllowed"),
        "the failing rule reaches the model: {refusal}"
    );
    assert!(
        !refusal.contains("0x"),
        "no address, digest or ceiling the policy holds may come back: {refusal}"
    );
    assert!(
        !refusal.contains(RECIPIENT) && !refusal.contains("1000"),
        "the one_of payee list and the max are exactly what must not leak: {refusal}"
    );
    assert_eq!(dirs(&bundles), 0, "a refused proposal writes nothing");

    let far = propose(&mut server, 2, &transfer(TOKEN, 1, 200));
    assert_eq!(far["result"]["isError"], json!(true), "{far}");
    let refusal = text(&far);
    assert!(refusal.contains("NonceOutsideWindow"), "{refusal}");
    assert!(
        refusal.contains("200") && refusal.contains('7'),
        "the refusal names the nonce asked for and the anchor it is measured from: {refusal}"
    );
    assert_eq!(dirs(&bundles), 0, "the nonce bound wrote nothing either");

    for outside in [named("OTHER", SAFE, 7), named("AGENT", ELSEWHERE, 7)] {
        let refused = propose(&mut server, 3, &outside);
        assert_eq!(refused["result"]["isError"], json!(true), "{refused}");
        let refusal = text(&refused);
        assert!(
            refusal.contains("NotAllowed"),
            "nothing outside the allow-lists is proposable: {refusal}"
        );
        assert_eq!(dirs(&bundles), 0);
    }

    let filed = propose(&mut server, 4, &transfer(TOKEN, 1, 7));
    assert_eq!(filed["result"]["isError"], json!(false), "{filed}");
    let proposed: Value = serde_json::from_str(&text(&filed)).expect("the payload is json");
    let hash = proposed["hash"]
        .as_str()
        .expect("a filed proposal names its bundle")
        .to_string();
    assert!(bundles.join(&hash).is_dir(), "the bundle is on disk");
    assert_eq!(dirs(&bundles), 1);
    assert_eq!(
        proposed["nonce"]["above_anchor"],
        json!("0"),
        "the operator is told how far ahead of the anchor they are approving: {proposed}"
    );
    assert_eq!(proposed["nonce"]["anchored"], json!(true), "{proposed}");

    let rival = propose(&mut server, 5, &transfer(TOKEN, 2, 7));
    assert!(rival.get("error").is_none(), "{rival}");
    assert_eq!(rival["result"]["isError"], json!(true), "{rival}");
    let refusal = text(&rival);
    assert!(refusal.contains("SlotTaken"), "{refusal}");
    assert!(
        refusal.contains(&hash),
        "the refusal names the digest already holding the slot: {refusal}"
    );
    assert_eq!(
        dirs(&bundles),
        1,
        "the rival guard left the queue as it found it"
    );

    let _ = std::fs::remove_dir_all(&home);
}
