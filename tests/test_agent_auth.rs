//! TDD Test Suite for Agentic Cryptographic Authentication and Replay Guard.
//!
//! Enforces Deterministic Safety Standards:
//! 1. All functions strictly <= 60 lines.
//! 2. Assertion density >= 2 per test case.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

use sentinel_lex::agent_auth::{
    AuthError, authenticate_agent_request, hash_payload, validate_timestamp, verify_hmac_signature,
};

type HmacSha256 = Hmac<Sha256>;

fn generate_valid_sig(secret: &[u8], method: &str, timestamp: u64, body_hash: &str) -> String {
    assert!(!secret.is_empty(), "Secret cannot be empty");
    assert!(!method.is_empty(), "Method cannot be empty");

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC slice initialization");
    let canonical = format!("{method}\n{timestamp}\n{body_hash}");
    mac.update(canonical.as_bytes());
    let sig = mac.finalize().into_bytes();
    let hex_sig = sig.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(hex_sig.len(), 64, "HMAC-SHA256 hex string must be exactly 64 characters");
    hex_sig
}

#[test]
fn test_valid_agent_request_passes() {
    let secret = b"super-secure-agent-secret-key-32b";
    let body = br#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let body_hash = hash_payload(body);
    let sig = generate_valid_sig(secret, "POST", now, &body_hash);

    let res = authenticate_agent_request(secret, "POST", &now.to_string(), &sig, body);
    assert!(res.is_ok(), "Valid agent request must authenticate successfully");
    assert_eq!(body_hash.len(), 64, "Body hash hex length must be 64");
}

#[test]
fn test_tampered_payload_fails_signature() {
    let secret = b"super-secure-agent-secret-key-32b";
    let original_body = br#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#;
    let tampered_body = br#"{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x123"],"id":1}"#;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let body_hash = hash_payload(original_body);
    let sig = generate_valid_sig(secret, "POST", now, &body_hash);

    let res = authenticate_agent_request(secret, "POST", &now.to_string(), &sig, tampered_body);
    assert_eq!(res, Err(AuthError::InvalidSignature), "Tampered payload must trigger InvalidSignature");
    assert_ne!(hash_payload(original_body), hash_payload(tampered_body));
}

#[test]
fn test_expired_timestamp_replay_attack_rejected() {
    let secret = b"super-secure-agent-secret-key-32b";
    let body = br#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#;
    let stale_time = 1_000_000_000; // Far in the past
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let body_hash = hash_payload(body);
    let sig = generate_valid_sig(secret, "POST", stale_time, &body_hash);

    let res = authenticate_agent_request(secret, "POST", &stale_time.to_string(), &sig, body);
    assert!(matches!(res, Err(AuthError::TimestampExpired { .. })), "Stale timestamp must be rejected");
    assert!(validate_timestamp(stale_time, now).is_err());
}

#[test]
fn test_constant_time_signature_verification() {
    let secret = b"agent-secret-1234567890123456";
    let body_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let timestamp = 1700000000;

    let valid_sig = generate_valid_sig(secret, "POST", timestamp, body_hash);
    let invalid_sig = format!("00{}", &valid_sig[2..]);

    assert!(verify_hmac_signature(secret, "POST", timestamp, body_hash, &valid_sig).is_ok());
    assert_eq!(
        verify_hmac_signature(secret, "POST", timestamp, body_hash, &invalid_sig),
        Err(AuthError::InvalidSignature)
    );
}
