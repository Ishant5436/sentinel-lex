# BLI Legal Tech Hackathon 2: BUIDL Submission Dossier

**Project Name:** Sentinel-Lex  
**Tagline:** Deterministic Agentic Compliance & Pre-Execution Revert Protection Firewall  
**Tracks:** 
1. `LegalTech & RegTech` (Primary: Pre-Execution Consumer Protection, Automated Revert Decoding, and Regulatory Risk Gates)
2. `AI x Blockchain` (Secondary: Cryptographic Agent Authentication, Replay Guard, and Non-Custodial Policy Enforcement)

**Repository:** https://github.com/Ishant5436/sentinel-lex  
**License:** MIT (Permissive Open Source)  
**Author:** Ishant Panchal (`Ishant5436` / `ishant.p@somaiya.edu`)  

---

## 1. Project Description

### The Problem
As autonomous AI agents and institutional trading bots conduct billions of dollars in automated transactions across EVM networks, failed transactions impose significant financial drag and regulatory ambiguity:
1. **Unbounded Gas Waste:** On EVM networks, transactions that fail on-chain (due to slippage, expired deadlines, or insufficient allowances) burn user gas with zero value delivered.
2. **Regulatory & Compliance Blindspots:** Existing JSON-RPC gateways lack cryptographically verifiable agent attribution and emit raw byte reverts that obscure whether failure stemmed from fraud, technical latency, or insolvency.
3. **Consumer Protection Gap:** Web3 consumers and agents lack pre-execution guarantees that prevent transactions from entering mempools when deterministic execution invariants are breached.

### The Solution: Sentinel-Lex
Sentinel-Lex is a deterministic, high-throughput JSON-RPC compliance proxy written in Rust that sits between automated AI agents (or consumer wallets) and EVM sequencers:
1. **Cryptographic Agent Gate:** Validates HMAC-SHA256 request signatures over canonicalized request bodies with bounded 300s timestamp drift to eliminate replay attacks.
2. **In-Process Pre-Simulation:** Simulates outbound `eth_sendRawTransaction` payloads in-process using `revm` against cached state trie layers before network broadcast.
3. **Deterministic Revert Interception:** If a transaction would revert, Sentinel-Lex preemptively halts execution—saving 100% of on-chain gas fees—and decodes Solidity custom errors (ERC-6093 `ERC20InsufficientBalance`, `ERC20InsufficientAllowance`, DEX `SlippageExceeded`, `DeadlineExpired`) into standard JSON-RPC errors.
4. **Fail-Open Operational Safety:** Strictly differentiates deterministic smart contract reverts from transient RPC sync lag to guarantee user submissions are never dropped by network latency.

---

## 2. Technical Evidence & Standards

- **Core Engine:** Built in Rust using `tokio`, `hyper`, `alloy-sol-types`, and `revm`.
- **Deterministic Safety Invariants:** Functions $\le 60$ lines, assertion density $\ge 2$ per function, bounded allocations on hot paths.
- **Automated Verification:** 47/47 passing tests (43 Rust unit/integration + 4 Node SDK) in 0.12s.
- **Latency Benchmark:** < 12ms simulation latency on warm keep-alive sessions, eliminating middleware drag.

---

## 3. How to Test & Verify

### Build & Run Tests:
```bash
git clone https://github.com/Ishant5436/sentinel-lex.git
cd sentinel-lex
make test
```

### Launch Proxy:
```bash
UPSTREAM_RPC_URL="https://mainnet.optimism.io" PORT=8545 cargo run --release
```

### Query Compliance Telemetry:
```bash
curl http://localhost:8545/health
```
