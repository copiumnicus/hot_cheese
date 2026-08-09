//! Hand-rolled JSON-RPC 2.0, one message per line, over `serde_json` alone.
//!
//! Two protocol eras are served and the client's FIRST request decides which: a `server/discover`
//! opens the modern one, whose results carry a `resultType`, and anything else the legacy one of
//! `initialize` / `tools/list` / `tools/call`. Nothing else about a session is remembered.
//!
//! The load-bearing distinction is between a JSON-RPC `error` and a `result` carrying
//! `isError`. A malformed line, an unknown method, an unknown tool or arguments that will not
//! parse are protocol errors: the client failed, and the model cannot fix them. A refusal from
//! a tool — a policy denial above all — is a RESULT with `isError: true`, because that is what
//! clients feed back to the model for self-correction. Answering a denial with a JSON-RPC error
//! would abort the turn instead of teaching the agent what the policy actually allows.
use crate::tools::{self, CallErr, Tool};
use serde_json::{json, Value};

/// The only JSON-RPC version this server speaks.
const JSONRPC: &str = "2.0";

/// MCP revision reported when a client does not name one itself.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// How the server names itself in `initialize`.
const SERVER_NAME: &str = "hot_cheese";

/// The line was not JSON at all.
const PARSE_ERROR: i64 = -32700;

/// It was JSON, but not a JSON-RPC 2.0 request.
const INVALID_REQUEST: i64 = -32600;

/// Unknown method, or a `tools/call` naming a tool this server does not have.
const METHOD_NOT_FOUND: i64 = -32601;

/// The tool's arguments did not deserialize.
const INVALID_PARAMS: i64 = -32602;

/// The answer itself could not be rendered.
const INTERNAL_ERROR: i64 = -32603;

/// The modern era's tag for a result that is finished.
const RESULT_TYPE_COMPLETE: &str = "complete";

/// The method that opens the modern era.
const DISCOVER: &str = "server/discover";

/// Which protocol era the client speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Era {
    /// `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`.
    Legacy,
    /// [`DISCOVER`], and results tagged with [`RESULT_TYPE_COMPLETE`].
    Modern,
}

/// One client session over stdio.
#[derive(Debug, Default)]
pub struct Server {
    /// The era the first request settled on.
    era: Option<Era>,
}

impl Server {
    /// Answer one line. `None` means the line was a notification, which JSON-RPC says gets no
    /// reply at all. The answer is compact, so it can never contain a newline of its own.
    pub fn dispatch(&mut self, line: &str) -> Option<String> {
        let request: Value = match serde_json::from_str(line) {
            Ok(request) => request,
            Err(e) => return render(Value::Null, Err(failure(PARSE_ERROR, e.to_string()))),
        };
        let id = request.get("id").cloned();
        if request.get("jsonrpc") != Some(&json!(JSONRPC)) {
            let message = format!("jsonrpc must be \"{JSONRPC}\"");
            return render(
                id.unwrap_or(Value::Null),
                Err(failure(INVALID_REQUEST, message)),
            );
        }
        let Some(Value::String(method)) = request.get("method") else {
            return render(
                id.unwrap_or(Value::Null),
                Err(failure(INVALID_REQUEST, "method must be a string".into())),
            );
        };
        let era = *self.era.get_or_insert(match method.as_str() {
            DISCOVER => Era::Modern,
            _ => Era::Legacy,
        });
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        let mut answer = match method.as_str() {
            "initialize" => Ok(initialize(&params)),
            "notifications/initialized" | "ping" => Ok(json!({})),
            "tools/list" | DISCOVER => Ok(tools::listing()),
            "tools/call" => call(&params),
            _ => Err(failure(
                METHOD_NOT_FOUND,
                format!("unknown method {method}"),
            )),
        };
        if let (Era::Modern, Ok(Value::Object(result))) = (era, &mut answer) {
            result.insert("resultType".to_string(), json!(RESULT_TYPE_COMPLETE));
        }
        render(id?, answer)
    }
}

/// The handshake. A client's own protocol revision is echoed back when it names one, so a
/// client older or newer than [`PROTOCOL_VERSION`] still gets an answer it recognises.
fn initialize(params: &Value) -> Value {
    let version = match params.get("protocolVersion") {
        Some(Value::String(asked)) => asked.clone(),
        _ => PROTOCOL_VERSION.to_string(),
    };
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
    })
}

/// Run one tool. An unknown name is a `-32601` exactly like an unknown method, arguments that
/// will not parse are a `-32602`, and everything the tool itself refuses comes back as a result
/// the model is meant to read and correct.
fn call(params: &Value) -> Result<Value, Value> {
    let Some(name) = params.get("name") else {
        return Err(failure(INVALID_PARAMS, "tools/call needs a name".into()));
    };
    let Ok(tool) = serde_json::from_value::<Tool>(name.clone()) else {
        return Err(failure(METHOD_NOT_FOUND, format!("unknown tool {name}")));
    };
    match tool.call(params.get("arguments").cloned().unwrap_or(Value::Null)) {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(text) => Ok(content(text, false)),
            Err(e) => Err(failure(INTERNAL_ERROR, e.to_string())),
        },
        Err(CallErr::Params(e)) => Err(failure(INVALID_PARAMS, e.to_string())),
        Err(CallErr::Tool(e)) => {
            tracing::warn!(error = %e, "a tool refused");
            Ok(content(e.to_string(), true))
        }
    }
}

/// A tool result in MCP's shape: text the model reads, plus the flag that tells the client to
/// hand a failure back to the model instead of aborting the turn.
fn content(text: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

/// A JSON-RPC error object.
fn failure(code: i64, message: String) -> Value {
    json!({"code": code, "message": message})
}

/// One response line. `to_string` and never `to_string_pretty`: the compact writer escapes the
/// newlines inside a decoded summary, so one message per line holds by construction.
fn render(id: Value, answer: Result<Value, Value>) -> Option<String> {
    let response = match answer {
        Ok(result) => json!({"jsonrpc": JSONRPC, "id": id, "result": result}),
        Err(error) => json!({"jsonrpc": JSONRPC, "id": id, "error": error}),
    };
    match serde_json::to_string(&response) {
        Ok(text) => Some(text),
        Err(e) => {
            tracing::error!(error = %e, "a response could not be rendered");
            Some(format!(
                "{{\"jsonrpc\":\"{JSONRPC}\",\"id\":null,\"error\":{{\"code\":{INTERNAL_ERROR},\
                 \"message\":\"response could not be rendered\"}}}}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(server: &mut Server, line: &str) -> Value {
        let text = server
            .dispatch(line)
            .expect("a request with an id is answered");
        serde_json::from_str(&text).expect("the answer is one line of json")
    }

    /// The frame every request passes before a tool can run. A line that is not JSON has no id
    /// to echo, so it is answered against a null one; an unknown method and an unknown TOOL are
    /// the same refusal, because a tool name is a method name to the model; and the published
    /// listing is exactly the six names the enum can be called by — a name in one and not the
    /// other is a tool the model can see and not reach, or reach and not see. The two generic
    /// transaction tools were deleted, so they must now be unreachable names like any other.
    #[test]
    fn the_protocol_frame_answers_before_any_tool_runs() {
        let mut server = Server::default();

        let bad = answer(&mut server, "{not json");
        assert_eq!(bad["error"]["code"], json!(PARSE_ERROR));
        assert_eq!(bad["id"], Value::Null);

        let stray = answer(&mut server, r#"{"id":1,"method":"tools/list"}"#);
        assert_eq!(stray["error"]["code"], json!(INVALID_REQUEST));

        let unknown = answer(&mut server, r#"{"jsonrpc":"2.0","id":2,"method":"sign"}"#);
        assert_eq!(unknown["error"]["code"], json!(METHOD_NOT_FOUND));

        for gone in ["sign_intent", "propose_transaction", "preview_intent"] {
            let request = json!({
                "jsonrpc": JSONRPC,
                "id": 3,
                "method": "tools/call",
                "params": {"name": gone},
            });
            let no_tool = answer(
                &mut server,
                &serde_json::to_string(&request).expect("render the request"),
            );
            assert_eq!(
                no_tool["error"]["code"],
                json!(METHOD_NOT_FOUND),
                "{gone} must not be callable"
            );
        }

        assert!(
            server
                .dispatch(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .is_none(),
            "a notification carries no id and gets no reply"
        );

        let listed = answer(
            &mut server,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#,
        );
        let published = listed["result"]["tools"]
            .as_array()
            .expect("the listing is an array");
        let mut names = Vec::with_capacity(published.len());
        for tool in published {
            serde_json::from_value::<Tool>(tool["name"].clone())
                .expect("every published name is callable");
            names.push(tool["name"].clone());
        }
        assert_eq!(
            names,
            vec![
                json!("list_safes"),
                json!("list_signing_keys"),
                json!("list_bundles"),
                json!("bundle_status"),
                json!("preview_erc20_transfer"),
                json!("propose_erc20_transfer"),
            ],
            "the published surface is exactly these six tools"
        );
    }
}
