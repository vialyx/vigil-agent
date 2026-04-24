use crate::config::PolicyConfig;
use crate::risk::{BaselineStore, RiskEvent, UsageFeatures};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Notify, RwLock};

// ── JSON-RPC 2.0 types ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
            }),
            id,
        }
    }
}

// ── Shared agent state exposed over IPC ──────────────────────────────────────

/// Shared, lock-guarded view of the agent's current state.
pub struct AgentState {
    pub latest_event: Option<RiskEvent>,
    pub latest_features: Option<UsageFeatures>,
    pub baseline: BaselineStore,
    pub rescore_requested: bool,
    pub pending_policy: Option<PolicyConfig>,
    pub ipc_auth_token: Option<String>,
    pub rescore_notify: Arc<Notify>,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            latest_event: None,
            latest_features: None,
            baseline: BaselineStore::default(),
            rescore_requested: false,
            pending_policy: None,
            ipc_auth_token: None,
            rescore_notify: Arc::new(Notify::new()),
        }
    }
}

pub type SharedState = Arc<RwLock<AgentState>>;

// ── IPC server ────────────────────────────────────────────────────────────────

/// Dispatch a single JSON-RPC request and return a serialised response.
pub async fn handle_request(raw: &str, state: SharedState) -> String {
    let req: JsonRpcRequest = match serde_json::from_str(raw) {
        Ok(r) => r,
        Err(e) => {
            let resp = JsonRpcResponse::error(None, -32700, format!("Parse error: {e}"));
            return serde_json::to_string(&resp).unwrap_or_default();
        }
    };

    let id = req.id.clone();

    let requires_auth = matches!(req.method.as_str(), "rescore" | "update_policy");

    if requires_auth {
        let st = state.read().await;
        if let Some(expected) = st.ipc_auth_token.as_deref() {
            let provided = req
                .params
                .as_ref()
                .and_then(|params| params.get("token"))
                .and_then(Value::as_str);
            if provided != Some(expected) {
                let resp = JsonRpcResponse::error(id, -32003, "Unauthorized");
                return serde_json::to_string(&resp).unwrap_or_default();
            }
        }
    }

    let resp = match req.method.as_str() {
        "get_risk_state" => {
            let st = state.read().await;
            match &st.latest_event {
                Some(ev) => {
                    let v = serde_json::to_value(ev).unwrap_or(Value::Null);
                    JsonRpcResponse::ok(id, v)
                }
                None => JsonRpcResponse::error(id, -32001, "No risk state available yet"),
            }
        }

        "get_usage_summary" => {
            let st = state.read().await;
            match &st.latest_features {
                Some(f) => {
                    let v = serde_json::to_value(f).unwrap_or(Value::Null);
                    JsonRpcResponse::ok(id, v)
                }
                None => JsonRpcResponse::error(id, -32002, "No usage data available yet"),
            }
        }

        "get_baseline" => {
            let st = state.read().await;
            let v = serde_json::to_value(&st.baseline).unwrap_or(Value::Null);
            JsonRpcResponse::ok(id, v)
        }

        "rescore" => {
            let mut st = state.write().await;
            st.rescore_requested = true;
            st.rescore_notify.notify_one();
            JsonRpcResponse::ok(id, Value::Bool(true))
        }

        "update_policy" => {
            let payload = req.params.as_ref().and_then(|params| {
                params
                    .get("policy")
                    .cloned()
                    .or_else(|| Some(params.clone()))
            });

            match payload {
                Some(value) => match serde_json::from_value::<PolicyConfig>(value) {
                    Ok(policy) => {
                        let mut st = state.write().await;
                        st.pending_policy = Some(policy);
                        st.rescore_requested = true;
                        st.rescore_notify.notify_one();
                        JsonRpcResponse::ok(id, serde_json::json!({ "status": "accepted" }))
                    }
                    Err(e) => JsonRpcResponse::error(
                        id,
                        -32602,
                        format!("Invalid policy payload: {e}"),
                    ),
                },
                None => JsonRpcResponse::error(id, -32602, "Missing policy payload"),
            }
        }

        other => JsonRpcResponse::error(id, -32601, format!("Method not found: {other}")),
    };

    serde_json::to_string(&resp).unwrap_or_default()
}

/// Run the IPC server on a Unix domain socket (macOS / Linux).
///
/// Each connection receives newline-delimited JSON-RPC requests and
/// responses.
#[cfg(unix)]
pub async fn run_unix_server(socket_path: &str, state: SharedState) -> anyhow::Result<()> {
    use tokio::net::UnixListener;

    // Remove a stale socket file if present.
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating socket directory {:?}", parent))?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding Unix socket {socket_path}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(socket_path, perms)
            .with_context(|| format!("setting socket permissions for {socket_path}"))?;
    }

    tracing::info!("IPC server listening on {socket_path}");

    loop {
        let (stream, _) = listener.accept().await?;
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_unix_connection(stream, state_clone).await {
                tracing::warn!("IPC connection error: {e}");
            }
        });
    }
}

#[cfg(unix)]
async fn handle_unix_connection(
    stream: tokio::net::UnixStream,
    state: SharedState,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let response = handle_request(&line, Arc::clone(&state)).await;
        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
    Ok(())
}

/// Named-pipe IPC server for Windows.
#[cfg(windows)]
pub async fn run_windows_pipe_server(pipe_name: &str, state: SharedState) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    tracing::info!("IPC server listening on {pipe_name}");
    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(pipe_name)?;
        server.connect().await?;
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(server);
            let mut lines = BufReader::new(reader).lines();
            while let Some(line) = lines.next_line().await.unwrap_or(None) {
                let response = handle_request(&line, Arc::clone(&state_clone)).await;
                let _ = writer.write_all(response.as_bytes()).await;
                let _ = writer.write_all(b"\n").await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_state() -> SharedState {
        Arc::new(RwLock::new(AgentState::default()))
    }

    #[tokio::test]
    async fn test_get_risk_state_no_data() {
        let state = make_state().await;
        let req = r#"{"jsonrpc":"2.0","method":"get_risk_state","id":1}"#;
        let resp = handle_request(req, state).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(
            v.get("error").is_some(),
            "should return error when no state"
        );
    }

    #[tokio::test]
    async fn test_get_risk_state_with_data() {
        let state = make_state().await;
        {
            let mut st = state.write().await;
            st.latest_event = Some(RiskEvent {
                schema_version: "1.0".into(),
                event_id: "e1".into(),
                device_id: "d1".into(),
                user_id: "u1".into(),
                timestamp_utc: "2026-04-24T00:00:00Z".into(),
                score: 42,
                band: "Medium".into(),
                delta_from_baseline: 5,
                top_contributors: vec![],
                anomalies: vec![],
                platform: "linux".into(),
                os_version: "6.8".into(),
                agent_version: "0.1.0".into(),
            });
        }
        let req = r#"{"jsonrpc":"2.0","method":"get_risk_state","id":2}"#;
        let resp = handle_request(req, state).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(v.get("result").is_some());
        assert_eq!(v["result"]["score"], 42);
    }

    #[tokio::test]
    async fn test_rescore_sets_flag() {
        let state = make_state().await;
        let req = r#"{"jsonrpc":"2.0","method":"rescore","id":3}"#;
        handle_request(req, Arc::clone(&state)).await;
        let st = state.read().await;
        assert!(st.rescore_requested);
    }

    #[tokio::test]
    async fn test_unknown_method_returns_error() {
        let state = make_state().await;
        let req = r#"{"jsonrpc":"2.0","method":"nonexistent","id":9}"#;
        let resp = handle_request(req, state).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn test_invalid_json_returns_parse_error() {
        let state = make_state().await;
        let resp = handle_request("not-json", state).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn test_get_baseline() {
        let state = make_state().await;
        let req = r#"{"jsonrpc":"2.0","method":"get_baseline","id":4}"#;
        let resp = handle_request(req, state).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(v.get("result").is_some());
    }

    #[tokio::test]
    async fn test_update_policy_accepted() {
        let state = make_state().await;
        let req = r#"{"jsonrpc":"2.0","method":"update_policy","params":{"policy":{}},"id":5}"#;
        let resp = handle_request(req, state).await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["status"], "accepted");
    }

    #[tokio::test]
    async fn test_update_policy_stages_new_policy() {
        let state = make_state().await;
        let req = r#"{"jsonrpc":"2.0","method":"update_policy","params":{"policy":{"off_hours_start":"20:00","off_hours_end":"07:00"}},"id":6}"#;
        handle_request(req, Arc::clone(&state)).await;
        let st = state.read().await;
        let policy = st.pending_policy.as_ref().expect("policy should be staged");
        assert_eq!(policy.off_hours_start, "20:00");
        assert!(st.rescore_requested);
    }

    #[tokio::test]
    async fn test_rescore_requires_token_when_configured() {
        let state = make_state().await;
        {
            let mut st = state.write().await;
            st.ipc_auth_token = Some("secret-token".to_string());
        }

        let req_missing = r#"{"jsonrpc":"2.0","method":"rescore","id":7}"#;
        let resp_missing = handle_request(req_missing, Arc::clone(&state)).await;
        let v_missing: Value = serde_json::from_str(&resp_missing).unwrap();
        assert_eq!(v_missing["error"]["code"], -32003);

        let req_ok =
            r#"{"jsonrpc":"2.0","method":"rescore","params":{"token":"secret-token"},"id":8}"#;
        let resp_ok = handle_request(req_ok, Arc::clone(&state)).await;
        let v_ok: Value = serde_json::from_str(&resp_ok).unwrap();
        assert_eq!(v_ok["result"], true);
    }
}
