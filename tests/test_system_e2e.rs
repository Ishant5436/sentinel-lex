use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

type HmacSha256 = Hmac<Sha256>;

fn find_available_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");
    let port = listener.local_addr().expect("Failed to get local addr").port();
    assert!(port > 0, "Port must be positive non-zero");
    assert!(port < 65535, "Port must be within valid range");
    port
}

fn compute_hmac(secret: &[u8], method: &str, ts: &str, body: &[u8]) -> String {
    assert!(!secret.is_empty(), "Secret cannot be empty");
    assert!(!method.is_empty(), "Method cannot be empty");

    let mut body_hasher = Sha256::new();
    body_hasher.update(body);
    let body_hash = format!("{:x}", body_hasher.finalize());

    let canonical = format!("{method}\n{ts}\n{body_hash}");
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC keys can be any length");
    mac.update(canonical.as_bytes());
    let sig_bytes = mac.finalize().into_bytes();
    sig_bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn wait_for_health(port: u16, max_retries: u32) -> bool {
    assert!(port > 0, "Port must be valid");
    assert!(max_retries > 0, "Max retries must be positive");
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/health");
    for _ in 0..max_retries {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn test_system_binary_lifecycle_and_health_probe() {
    let bin_path = env!("CARGO_BIN_EXE_sentinel-lex");
    let port = find_available_port();
    assert!(!bin_path.is_empty(), "Binary path must be resolved by Cargo");

    let child = Command::new(bin_path)
        .env("PORT", port.to_string())
        .env("UPSTREAM_RPC_URL", "https://mainnet.optimism.io")
        .env("FAIL_OPEN", "true")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn sentinel-lex system process");

    let _guard = ChildGuard { child };

    let is_healthy = wait_for_health(port, 40).await;
    assert!(is_healthy, "System process must become healthy within timeout");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .expect("Health check request failed");

    assert_eq!(resp.status(), 200, "Health endpoint must return 200 OK");
    let body: Value = resp.json().await.expect("Failed to parse health JSON");
    assert_eq!(body["status"], "healthy", "Status field must be healthy");
    assert_eq!(body["service"], "sentinel-lex", "Service name must match");
}

#[tokio::test]
async fn test_system_binary_agent_auth_enforcement() {
    let bin_path = env!("CARGO_BIN_EXE_sentinel-lex");
    let port = find_available_port();
    let secret = b"system_test_hmac_secret_key_xyz";

    let child = Command::new(bin_path)
        .env("PORT", port.to_string())
        .env("UPSTREAM_RPC_URL", "http://127.0.0.1:1") // dummy upstream
        .env("FAIL_OPEN", "true")
        .env("AGENT_AUTH_SECRET", std::str::from_utf8(secret).unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn sentinel-lex with auth enabled");

    let _guard = ChildGuard { child };
    assert!(wait_for_health(port, 40).await, "Server must report healthy");

    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");
    let test_body = r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#;

    // 1. Missing Auth Headers -> 401
    let resp_no_auth = client.post(&rpc_url).body(test_body).send().await.unwrap();
    assert_eq!(resp_no_auth.status(), 401, "Missing auth headers must return 401");

    // 2. Expired Timestamp -> 401
    let stale_ts = "1000000000"; // far in the past
    let stale_sig = compute_hmac(secret, "POST", stale_ts, test_body.as_bytes());
    let resp_stale = client
        .post(&rpc_url)
        .header("X-Agent-Timestamp", stale_ts)
        .header("X-Agent-Signature", stale_sig)
        .body(test_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_stale.status(), 401, "Expired timestamp must return 401");

    // 3. Tampered Body -> 401
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
    let invalid_sig = compute_hmac(secret, "POST", &now, b"different_tampered_payload");
    let resp_tampered = client
        .post(&rpc_url)
        .header("X-Agent-Timestamp", now)
        .header("X-Agent-Signature", invalid_sig)
        .body(test_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_tampered.status(), 401, "Tampered signature must return 401");
}

#[tokio::test]
async fn test_system_binary_e2e_proxy_forwarding() {
    // 1. Spawn Mock Upstream RPC
    let upstream_port = find_available_port();
    let upstream_addr: SocketAddr = format!("127.0.0.1:{upstream_port}").parse().unwrap();
    let listener = TcpListener::bind(upstream_addr).await.expect("Bind upstream listener");

    let received_upstream = Arc::new(AtomicBool::new(false));
    let flag = received_upstream.clone();

    tokio::spawn(async move {
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use http_body_util::Full;
        use hyper::body::Bytes;

        if let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            let flag_inner = flag.clone();
            let _ = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |_req| {
                        flag_inner.store(true, Ordering::SeqCst);
                        let body = r#"{"jsonrpc":"2.0","id":1,"result":"0x123456"}"#;
                        let resp = hyper::Response::builder()
                            .header("Content-Type", "application/json")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap();
                        async move { Ok::<_, hyper::Error>(resp) }
                    }),
                )
                .await;
        }
    });

    // 2. Spawn Sentinel-Lex Binary pointing to Mock Upstream
    let bin_path = env!("CARGO_BIN_EXE_sentinel-lex");
    let lex_port = find_available_port();
    let secret = b"e2e_forwarding_secret";

    let child = Command::new(bin_path)
        .env("PORT", lex_port.to_string())
        .env("UPSTREAM_RPC_URL", format!("http://127.0.0.1:{upstream_port}"))
        .env("FAIL_OPEN", "true")
        .env("AGENT_AUTH_SECRET", std::str::from_utf8(secret).unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn sentinel-lex");

    let _guard = ChildGuard { child };
    assert!(wait_for_health(lex_port, 40).await, "Sentinel-Lex must be healthy");

    // 3. Send Signed Request to Sentinel-Lex
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{lex_port}");
    let test_body = r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
    let sig = compute_hmac(secret, "POST", &now, test_body.as_bytes());

    let resp = client
        .post(&rpc_url)
        .header("Content-Type", "application/json")
        .header("X-Agent-Timestamp", now)
        .header("X-Agent-Signature", sig)
        .body(test_body)
        .send()
        .await
        .expect("Client post failed");

    assert_eq!(resp.status(), 200, "Forwarded request must return 200 OK");
    let resp_json: Value = resp.json().await.expect("Parse upstream response JSON");
    assert_eq!(resp_json["result"], "0x123456", "Response result must match upstream value");
    assert!(received_upstream.load(Ordering::SeqCst), "Upstream must have received request");
}

#[tokio::test]
async fn test_system_binary_e2e_revert_interception() {
    let bin_path = env!("CARGO_BIN_EXE_sentinel-lex");
    let lex_port = find_available_port();
    assert!(!bin_path.is_empty(), "Binary path must exist");

    let child = Command::new(bin_path)
        .env("PORT", lex_port.to_string())
        .env("UPSTREAM_RPC_URL", "https://mainnet.optimism.io")
        .env("FAIL_OPEN", "true")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn sentinel-lex");

    let _guard = ChildGuard { child };
    assert!(wait_for_health(lex_port, 40).await, "Sentinel-Lex must be healthy");

    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{lex_port}");
    let test_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": ["0xdeadbeef"],
        "id": 99
    });

    let resp = client
        .post(&rpc_url)
        .header("Content-Type", "application/json")
        .json(&test_body)
        .send()
        .await
        .expect("Client post failed");

    assert_eq!(resp.status(), 200, "Intercepted response must return HTTP 200 with JSON-RPC error");
    let body: Value = resp.json().await.expect("Parse JSON response");
    assert_eq!(body["id"], 99, "JSON-RPC id must match request id");
    assert_eq!(body["error"]["code"], -32000, "Error code must indicate simulated revert");
    assert!(body["error"]["data"]["simulation_latency_ms"].is_number(), "Latency must be present");
}
