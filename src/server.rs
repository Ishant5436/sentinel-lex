use http_body_util::{BodyExt, Full};
use hyper::header::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use revm::primitives::{Address, U256};
use revm::state::AccountInfo;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

use crate::agent_auth::authenticate_agent_request;
use crate::fork_db::{MAX_ACCOUNT_CACHE_CAPACITY, MAX_STORAGE_CACHE_CAPACITY, RpcDb};
use crate::lru::LruCache;
use crate::rpc_client::RpcForwarder;

pub const MAX_REQUEST_BODY_SIZE: usize = 2 * 1024 * 1024; // 2 MB
const INTERNAL_ERROR_JSON: &str =
    r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal server error"}}"#;

#[derive(Clone)]
pub struct AppState {
    pub forwarder: RpcForwarder,
    pub upstream_url: String,
    pub fail_open: bool,
    pub http_client: reqwest::Client,
    pub account_cache: Arc<Mutex<LruCache<Address, AccountInfo>>>,
    pub storage_cache: Arc<Mutex<LruCache<(Address, U256), U256>>>,
    pub required_agent_secret: Option<Vec<u8>>,
}

fn build_json_response(body_str: String, status: StatusCode) -> Response<Full<Bytes>> {
    assert!(!body_str.is_empty(), "Response body string cannot be empty");
    let mut resp = Response::new(Full::new(Bytes::from(body_str)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    resp.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS"));
    resp.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Content-Type, X-Agent-Key, X-Agent-Timestamp, X-Agent-Signature"));
    assert_eq!(resp.status(), status, "Response status must match specified status");
    resp
}

async fn handle_request(req: Request<hyper::body::Incoming>, state: AppState) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == hyper::Method::OPTIONS {
        let mut preflight = Response::new(Full::new(Bytes::default()));
        *preflight.status_mut() = StatusCode::NO_CONTENT;
        preflight.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        preflight.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS"));
        preflight.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Content-Type, X-Agent-Key, X-Agent-Timestamp, X-Agent-Signature"));
        return Ok(preflight);
    }

    if req.method() == hyper::Method::GET && req.uri().path() == "/health" {
        let health = serde_json::json!({
            "status": "healthy",
            "service": "sentinel-lex",
            "compliance": "ISO/DIS 9001:2026",
            "invariants": "Deterministic Safety Standards",
            "fail_open": state.fail_open,
            "upstream": state.upstream_url
        });
        return Ok(build_json_response(health.to_string(), StatusCode::OK));
    }

    if req.method() != hyper::Method::POST {
        return Ok(build_json_response("Not Found".to_string(), StatusCode::NOT_FOUND));
    }

    let headers = req.headers().clone();
    let limited_body = http_body_util::Limited::new(req.into_body(), MAX_REQUEST_BODY_SIZE);
    let body_bytes = match limited_body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return Ok(build_json_response(r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Request body too large"}}"#.to_string(), StatusCode::PAYLOAD_TOO_LARGE)),
    };

    // Agent Authentication Gate
    if let Some(ref secret) = state.required_agent_secret {
        let timestamp_opt = headers.get("X-Agent-Timestamp").and_then(|v| v.to_str().ok());
        let sig_opt = headers.get("X-Agent-Signature").and_then(|v| v.to_str().ok());
        if let (Some(ts), Some(sig)) = (timestamp_opt, sig_opt) {
            if let Err(auth_err) = authenticate_agent_request(secret, "POST", ts, sig, &body_bytes) {
                let err_msg = format!(r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":-32001,"message":"Agent authentication failed: {}"}}}}"#, auth_err);
                return Ok(build_json_response(err_msg, StatusCode::UNAUTHORIZED));
            }
        } else {
            let err_msg = r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Missing required X-Agent-Timestamp and X-Agent-Signature headers"}}"#;
            return Ok(build_json_response(err_msg.to_string(), StatusCode::UNAUTHORIZED));
        }
    }

    let payload: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(build_json_response(r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#.to_string(), StatusCode::BAD_REQUEST)),
    };

    let upstream = state.upstream_url.clone();
    let payload_for_sim = payload.clone();
    let fail_open = state.fail_open;
    let http_client = state.http_client.clone();
    let account_cache = state.account_cache.clone();
    let storage_cache = state.storage_cache.clone();

    let check_result = tokio::task::spawn_blocking(move || {
        let db = RpcDb::new_with_client_and_caches(http_client, upstream, account_cache, storage_cache);
        crate::interceptor::check_payload_with_db(&payload_for_sim, db, fail_open)
    }).await;

    match check_result {
        Ok(Err(err_resp)) => {
            let resp_str = serde_json::to_string(&err_resp).unwrap_or_else(|_| INTERNAL_ERROR_JSON.to_string());
            return Ok(build_json_response(resp_str, StatusCode::OK));
        }
        Err(join_err) => {
            eprintln!("Simulation task join failure: {}", join_err);
            return Ok(build_json_response(INTERNAL_ERROR_JSON.to_string(), StatusCode::INTERNAL_SERVER_ERROR));
        }
        Ok(Ok(())) => {}
    }

    match state.forwarder.forward(payload).await {
        Ok(resp_val) => {
            let resp_str = serde_json::to_string(&resp_val).unwrap_or_else(|_| INTERNAL_ERROR_JSON.to_string());
            Ok(build_json_response(resp_str, StatusCode::OK))
        }
        Err(e) => {
            eprintln!("Upstream forward error: {}", e);
            Ok(build_json_response(INTERNAL_ERROR_JSON.to_string(), StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

pub async fn run_server_listener(
    listener: TcpListener,
    upstream_url: String,
    fail_open: bool,
    agent_secret: Option<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = listener.local_addr()?;
    println!("Sentinel-Lex Firewall listening on http://{}", addr);

    let http_client = reqwest::Client::builder()
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .pool_max_idle_per_host(20)
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()?;

    let state = AppState {
        forwarder: RpcForwarder::new(upstream_url.clone()),
        upstream_url,
        fail_open,
        http_client,
        account_cache: Arc::new(Mutex::new(LruCache::new(MAX_ACCOUNT_CACHE_CAPACITY))),
        storage_cache: Arc::new(Mutex::new(LruCache::new(MAX_STORAGE_CACHE_CAPACITY))),
        required_agent_secret: agent_secret,
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state_clone = state.clone();

        tokio::task::spawn(async move {
            let _ = http1::Builder::new().serve_connection(io, service_fn(move |req| handle_request(req, state_clone.clone()))).await;
        });
    }
}
