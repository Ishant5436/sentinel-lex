//! Sentinel-Lex: Agentic Pre-Execution Compliance & Consumer Protection Firewall.
//!
//! Entrypoint orchestrating configuration loading, deterministic invariant validation,
//! and async HTTP listener initialization.

use std::env;
use std::net::SocketAddr;
use tokio::net::TcpListener;

use sentinel_lex::server::run_server_listener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8545".to_string())
        .parse()
        .expect("PORT must be a valid u16 integer");

    let upstream_url = env::var("UPSTREAM_RPC_URL")
        .unwrap_or_else(|_| "https://mainnet.optimism.io".to_string());

    let fail_open = env::var("FAIL_OPEN")
        .map(|v| v.to_lowercase() != "false" && v != "0")
        .unwrap_or(true);

    let agent_secret = env::var("AGENT_AUTH_SECRET").ok().map(|s| s.into_bytes());

    assert!(port > 0, "Port must be positive non-zero");
    assert!(!upstream_url.is_empty(), "Upstream RPC URL cannot be empty");

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;

    println!("============================================================");
    println!("  SENTINEL-LEX: AGENTIC COMPLIANCE & REVERT FIREWALL        ");
    println!("  Compliance: ISO/DIS 9001:2026 | Safety: Deterministic Standards   ");
    println!("  Listening on: http://{}", addr);
    println!("  Upstream RPC: {}", upstream_url);
    println!("  Fail-Open Policy: {}", fail_open);
    println!("  Agent HMAC Auth: {}", if agent_secret.is_some() { "ENABLED" } else { "OPTIONAL" });
    println!("============================================================");

    run_server_listener(listener, upstream_url, fail_open, agent_secret).await
}
