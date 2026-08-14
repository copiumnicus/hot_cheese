//! The write path end to end in a throwaway home, driven through `dispatch` the way a client
//! drives it.
//!
//! ONE test function, deliberately. `HOT_CHEESE_HOME` is read through `std::env::var`, so a
//! second test setting it on another harness thread would race this one; owning the process
//! environment is the whole reason this lives in its own binary. Nothing here prompts, unlocks
//! or reaches hardware — the proposal server cannot, which is the point being tested.
use hc_mcp::rpc::Server;
use serde_json::{json, Value};
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

    std::fs::write(
        home.join("config.toml"),
        format!(
            "service = \"\"\naccount = \"\"\nstore = \"{}\"\n\n[mcp]\nmax_pending = 4\n",
            store.display()
        ),
    )
    .expect("write the config");
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

/// A refused proposal must reach the MODEL rather than abort the turn, and must leave the
/// operator's queue exactly as it found it: a stored denial is a permanently unsignable row.
/// Then the guard the agent is most likely to trip — a Safe executes each nonce once, so a
/// second transaction under a taken nonce is refused by the digest already holding it.
#[test]
fn a_denial_stores_nothing_and_one_nonce_takes_one_bundle() {
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
        "the typed variant reaches the model: {refusal}"
    );
    assert!(
        refusal.contains(ELSEWHERE),
        "carrying the value that caused it: {refusal}"
    );
    assert_eq!(dirs(&bundles), 0, "a refused proposal writes nothing");

    let filed = propose(&mut server, 2, &transfer(TOKEN, 1, 7));
    assert_eq!(filed["result"]["isError"], json!(false), "{filed}");
    let proposed: Value = serde_json::from_str(&text(&filed)).expect("the payload is json");
    let hash = proposed["hash"]
        .as_str()
        .expect("a filed proposal names its bundle")
        .to_string();
    assert!(bundles.join(&hash).is_dir(), "the bundle is on disk");
    assert_eq!(dirs(&bundles), 1);

    let rival = propose(&mut server, 3, &transfer(TOKEN, 2, 7));
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
