//! Hand-rolled JSON-RPC 2.0, one message per line, over `serde_json` alone.
//!
//! Two protocol eras are served. Legacy clients open a stateful session with `initialize`;
//! modern clients identify version and capabilities independently on every request and may use
//! `server/discover` first. A modern request never inherits trust in metadata from an earlier
//! request, which is the defining security property of that stateless protocol era.
//!
//! The load-bearing distinction is between a JSON-RPC `error` and a `result` carrying
//! `isError`. A malformed line, an unknown method, an unknown tool or arguments that will not
//! parse are protocol errors: the client failed, and the model cannot fix them. A refusal from
//! a tool — a policy denial above all — is a RESULT with `isError: true`, because that is what
//! clients feed back to the model for self-correction. Answering a denial with a JSON-RPC error
//! would abort the turn instead of teaching the agent what the policy actually allows.
use crate::limits::Session;
use crate::tools::{self, CallErr, Tool};
use serde_json::{json, Value};

/// The only JSON-RPC version this server speaks.
const JSONRPC: &str = "2.0";

/// Stateful MCP revision this build implements for existing clients.
const LEGACY_PROTOCOL_VERSION: &str = "2025-06-18";

/// Stateless, per-request MCP revision this build implements.
const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

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

/// A modern request selected a revision this server does not implement.
const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// The modern era's tag for a result that is finished.
const RESULT_TYPE_COMPLETE: &str = "complete";

/// The method that opens the modern era.
const DISCOVER: &str = "server/discover";

/// Which protocol era was most recently observed. This is diagnostic state only: modern
/// requests are validated from their own metadata and never authorized from this value.
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
    /// Last observed era; legacy initialization is session state, modern selection is not.
    era: Option<Era>,
    /// What this session has spent against the agent limits. One stdio pipe is one agent, which
    /// is the only identity a stdio server has to rate-limit against.
    session: Session,
}

impl Server {
    /// A framing/encoding failure has no trustworthy request id, so answer it as a JSON-RPC
    /// parse error against `null` without changing the session's protocol era.
    pub fn parse_error(message: impl Into<String>) -> String {
        render(Value::Null, Err(failure(PARSE_ERROR, message.into())))
    }

    /// Answer one line. `None` means the line was a notification, which JSON-RPC says gets no
    /// reply at all. The answer is compact, so it can never contain a newline of its own.
    pub fn dispatch(&mut self, line: &str) -> Option<String> {
        self.dispatch_with(line, call)
    }

    fn dispatch_with<F>(&mut self, line: &str, mut call_tool: F) -> Option<String>
    where
        F: FnMut(&mut Session, &Value) -> Result<Value, Value>,
    {
        let request: Value = match hc_core::wire::strict_json_from_str(line) {
            Ok(request) => request,
            Err(e) => return Some(Self::parse_error(e.to_string())),
        };
        let Some(request) = request.as_object() else {
            return Some(render(
                Value::Null,
                Err(failure(INVALID_REQUEST, "request must be an object".into())),
            ));
        };
        let id = request.get("id").cloned();
        if request.get("jsonrpc") != Some(&json!(JSONRPC)) {
            let message = format!("jsonrpc must be \"{JSONRPC}\"");
            return Some(render(
                id.unwrap_or(Value::Null),
                Err(failure(INVALID_REQUEST, message)),
            ));
        }
        let Some(Value::String(method)) = request.get("method") else {
            return Some(render(
                id.unwrap_or(Value::Null),
                Err(failure(INVALID_REQUEST, "method must be a string".into())),
            ));
        };

        // MCP defines `tools/call` as a request with a string or integer id, never a
        // notification. Check that boundary before dispatch: JSON-RPC notifications cannot
        // report either success or refusal, so executing a writing tool here would silently
        // enqueue a proposal. Unknown notifications are deliberately ignored as JSON-RPC
        // requires; the sole notification this server uses is the initialization acknowledgement.
        let Some(id) = id else {
            if method != "notifications/initialized" {
                tracing::warn!(method = %hc_core::safe_diagnostic_text(method), "ignoring an unsupported JSON-RPC notification");
            }
            return None;
        };
        if !valid_request_id(&id) {
            return Some(render(
                Value::Null,
                Err(failure(
                    INVALID_REQUEST,
                    "id must be a non-null string or integer".into(),
                )),
            ));
        }

        let params = request.get("params").cloned().unwrap_or(Value::Null);

        let modern = method == DISCOVER
            || looks_modern(&params)
            || (self.era == Some(Era::Modern) && method != "initialize");
        let era = if method == "initialize" {
            Era::Legacy
        } else if modern {
            if let Err(error) = validate_modern_metadata(&params) {
                return Some(render(id, Err(error)));
            }
            self.era = Some(Era::Modern);
            Era::Modern
        } else {
            // Keep accepting the legacy tools directly. The legacy lifecycle says a client
            // SHOULD initialize first rather than making it a server-side authorization gate,
            // and older stdio clients in the wild rely on that tolerance.
            Era::Legacy
        };

        let mut answer = match method.as_str() {
            "initialize" => initialize(&params),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(tools::listing()),
            DISCOVER => Ok(discover()),
            "tools/call" => call_tool(&mut self.session, &params),
            _ => Err(failure(
                METHOD_NOT_FOUND,
                format!(
                    "unknown method {}",
                    hc_core::safe_diagnostic_text(method.as_str())
                ),
            )),
        };
        if method == "initialize" && answer.is_ok() {
            self.era = Some(Era::Legacy);
        }
        if let (Era::Modern, Ok(Value::Object(result))) = (era, &mut answer) {
            result.insert("resultType".to_string(), json!(RESULT_TYPE_COMPLETE));
        }
        Some(render(id, answer))
    }
}

/// Any modern reserved metadata marker. Wrongly typed or incomplete metadata still selects the
/// modern validator so a malformed modern request cannot fall through to permissive legacy
/// parsing merely by omitting one required field.
fn looks_modern(params: &Value) -> bool {
    params
        .get("_meta")
        .and_then(Value::as_object)
        .is_some_and(|meta| {
            [
                "io.modelcontextprotocol/protocolVersion",
                "io.modelcontextprotocol/clientInfo",
                "io.modelcontextprotocol/clientCapabilities",
            ]
            .iter()
            .any(|key| meta.contains_key(*key))
        })
}

/// Validate every required modern per-request field. The version is not connection state: a
/// second request with missing or different metadata must not borrow the first one's result.
fn validate_modern_metadata(params: &Value) -> Result<(), Value> {
    let Some(params) = params.as_object() else {
        return Err(failure(
            INVALID_PARAMS,
            "modern request params must be an object".into(),
        ));
    };
    let Some(meta) = params.get("_meta").and_then(Value::as_object) else {
        return Err(failure(
            INVALID_PARAMS,
            "modern request needs an object _meta".into(),
        ));
    };
    let Some(version) = meta
        .get("io.modelcontextprotocol/protocolVersion")
        .and_then(Value::as_str)
    else {
        return Err(failure(
            INVALID_PARAMS,
            "modern request needs a string protocol version".into(),
        ));
    };
    if version != MODERN_PROTOCOL_VERSION {
        return Err(json!({
            "code": UNSUPPORTED_PROTOCOL_VERSION,
            "message": "Unsupported protocol version",
            "data": {
                "supported": [MODERN_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION],
                "requested": hc_core::safe_diagnostic_text(version),
            },
        }));
    }
    if !meta
        .get("io.modelcontextprotocol/clientCapabilities")
        .is_some_and(Value::is_object)
    {
        return Err(failure(
            INVALID_PARAMS,
            "modern request needs object client capabilities".into(),
        ));
    }
    Ok(())
}

fn valid_request_id(id: &Value) -> bool {
    match id {
        Value::String(_) => true,
        Value::Number(number) => number.is_i64() || number.is_u64(),
        _ => false,
    }
}

/// The handshake reports the revision this server actually implements. Echoing an arbitrary
/// client revision would falsely negotiate features and message shapes this binary does not
/// understand; MCP requires the client to decide whether it can continue with the server's
/// supported revision.
fn initialize(params: &Value) -> Result<Value, Value> {
    let valid = params.as_object().is_some_and(|params| {
        params.get("protocolVersion").is_some_and(Value::is_string)
            && params.get("capabilities").is_some_and(Value::is_object)
            && params.get("clientInfo").is_some_and(|info| {
                info.as_object().is_some_and(|info| {
                    info.get("name").is_some_and(Value::is_string)
                        && info.get("version").is_some_and(Value::is_string)
                })
            })
    });
    if !valid {
        return Err(failure(
            INVALID_PARAMS,
            "initialize needs protocolVersion, capabilities, and clientInfo".into(),
        ));
    }
    Ok(json!({
        "protocolVersion": LEGACY_PROTOCOL_VERSION,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
    }))
}

/// Modern discovery describes the server; it is not an alias for `tools/list`.
fn discover() -> Value {
    json!({
        "supportedVersions": [MODERN_PROTOCOL_VERSION],
        "capabilities": {"tools": {"listChanged": false}},
        "_meta": {
            "io.modelcontextprotocol/serverInfo": {
                "name": SERVER_NAME,
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
    })
}

/// Run one tool. An unknown name is a `-32601` exactly like an unknown method, arguments that
/// will not parse are a `-32602`, and everything the tool itself refuses comes back as a result
/// the model is meant to read and correct.
///
/// The refusal the model reads and the refusal the operator's log records are deliberately
/// different renderings of the same typed error: the log gets every field, the model gets which
/// rule refused. Nothing here reflects a caller's own bytes back at it either — an unknown tool
/// name is escaped before it is named.
fn call(session: &mut Session, params: &Value) -> Result<Value, Value> {
    let Some(name) = params.get("name") else {
        return Err(failure(INVALID_PARAMS, "tools/call needs a name".into()));
    };
    let Ok(tool) = serde_json::from_value::<Tool>(name.clone()) else {
        return Err(failure(
            METHOD_NOT_FOUND,
            format!(
                "unknown tool {}",
                hc_core::safe_diagnostic_text(&name.to_string())
            ),
        ));
    };
    match tool.call(session, params.get("arguments").cloned().unwrap_or(Value::Null)) {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(text) => Ok(content(text, false)),
            Err(e) => Err(failure(INTERNAL_ERROR, e.to_string())),
        },
        Err(CallErr::Params(e)) => Err(failure(
            INVALID_PARAMS,
            hc_core::safe_diagnostic_text(&e.to_string()),
        )),
        Err(CallErr::Tool(e)) => {
            tracing::warn!(
                detail = %hc_core::safe_diagnostic_text(&e.to_string()),
                "a tool refused; the agent was told only which rule refused"
            );
            Ok(content(e.refusal(), true))
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
fn render(id: Value, answer: Result<Value, Value>) -> String {
    let response = match answer {
        Ok(result) => json!({"jsonrpc": JSONRPC, "id": id, "result": result}),
        Err(error) => json!({"jsonrpc": JSONRPC, "id": id, "error": error}),
    };
    match serde_json::to_string(&response) {
        Ok(text) => text,
        Err(e) => {
            tracing::error!(error = %e, "a response could not be rendered");
            format!(
                "{{\"jsonrpc\":\"{JSONRPC}\",\"id\":null,\"error\":{{\"code\":{INTERNAL_ERROR},\
                 \"message\":\"response could not be rendered\"}}}}"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

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

        let injected = answer(
            &mut server,
            r#"{"jsonrpc":"2.0","id":21,"method":"\u001b[2Ksign\u202e"}"#,
        );
        assert_eq!(
            injected["error"]["code"],
            json!(METHOD_NOT_FOUND),
            "the escaped name still parses as a method, so the echo is reached: {injected}"
        );
        let echoed = injected["error"]["message"]
            .as_str()
            .expect("an unknown method is named");
        assert!(
            echoed.contains("sign") && !echoed.contains('\u{1b}') && !echoed.contains('\u{202e}'),
            "a name this server does not know is escaped before it is echoed: {echoed}"
        );

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

    #[test]
    fn a_tool_notification_cannot_execute_silently_or_select_an_era() {
        let mut server = Server::default();
        let invoked = Cell::new(false);
        let response = server.dispatch_with(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"propose_erc20_transfer","arguments":{}}}"#,
            |_, _| {
                invoked.set(true);
                Ok(json!({}))
            },
        );
        assert!(response.is_none(), "notifications never receive a response");
        assert!(!invoked.get(), "a notification must not reach any tool");
        assert_eq!(server.era, None, "a notification is not the first request");

        let response = server
            .dispatch_with(
                r#"{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{"name":"propose_erc20_transfer","arguments":{}}}"#,
                |_, _| {
                    invoked.set(true);
                    Ok(json!({}))
                },
            )
            .expect("an invalid request id receives an error");
        assert!(!invoked.get(), "an invalid id must not reach any tool");
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));
        assert_eq!(response["id"], Value::Null);
    }

    #[test]
    fn initialize_never_claims_an_unsupported_client_revision() {
        let mut server = Server::default();
        let response = answer(
            &mut server,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#,
        );
        assert_eq!(
            response["result"]["protocolVersion"],
            json!(LEGACY_PROTOCOL_VERSION)
        );

        let malformed = answer(
            &mut server,
            r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        );
        assert_eq!(malformed["error"]["code"], json!(INVALID_PARAMS));
    }

    fn modern_params() -> Value {
        json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"},
            },
        })
    }

    #[test]
    fn modern_discovery_and_every_later_request_validate_their_own_metadata() {
        let mut server = Server::default();

        let missing = answer(
            &mut server,
            r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}"#,
        );
        assert_eq!(missing["error"]["code"], json!(INVALID_PARAMS));

        let discovery = answer(
            &mut server,
            &json!({
                "jsonrpc": JSONRPC,
                "id": 2,
                "method": DISCOVER,
                "params": modern_params(),
            })
            .to_string(),
        );
        assert_eq!(
            discovery["result"]["supportedVersions"],
            json!([MODERN_PROTOCOL_VERSION])
        );
        assert_eq!(
            discovery["result"]["resultType"],
            json!(RESULT_TYPE_COMPLETE)
        );
        assert!(discovery["result"].get("tools").is_none());

        let downgraded = answer(
            &mut server,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}"#,
        );
        assert_eq!(downgraded["error"]["code"], json!(INVALID_PARAMS));

        let mut wrong = modern_params();
        wrong["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("1900-01-01");
        let unsupported = answer(
            &mut server,
            &json!({
                "jsonrpc": JSONRPC,
                "id": 4,
                "method": "tools/list",
                "params": wrong,
            })
            .to_string(),
        );
        assert_eq!(
            unsupported["error"]["code"],
            json!(UNSUPPORTED_PROTOCOL_VERSION)
        );
        assert_eq!(
            unsupported["error"]["data"]["requested"],
            json!("1900-01-01")
        );

        let listed = answer(
            &mut server,
            &json!({
                "jsonrpc": JSONRPC,
                "id": 5,
                "method": "tools/list",
                "params": modern_params(),
            })
            .to_string(),
        );
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 6);
        assert_eq!(listed["result"]["resultType"], json!(RESULT_TYPE_COMPLETE));
    }
}
