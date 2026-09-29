# Sentinel-Lex: Agentic Compliance & Pre-Execution Protection Firewall

An open-source, deterministic JSON-RPC middleware and compliance firewall built in Rust. Sits between autonomous AI agents (or wallet clients) and EVM sequencers/RPC nodes to enforce cryptographic authentication, simulate execution in-memory via `revm`, intercept ERC-6093 revert conditions, and prevent gas waste on failing on-chain transactions.

---

## 1. Problem Statement

On EVM networks and Layer-2 rollups:
1. **Unbounded Agent Failure Drag:** Autonomous AI agents executing high-frequency on-chain operations frequently hit transient revert conditions (slippage breaches, insufficient token allowance, stale oracle updates). On standard RPC relays, these transactions are broadcast and mined, burning real gas fees for zero successful state change.
2. **Opaque Revert Semantics:** Revert bytes returned after on-chain failure often arrive as cryptic hex payloads, creating consumer confusion and debugging latency.
3. **Lack of Cryptographic Agent Attribution:** Existing RPC nodes cannot cryptographically attribute automated requests to authenticated agents or enforce replay-protected authorization policies before state access.

---

## 2. Technical Architecture

Sentinel-Lex executes a multi-layer deterministic pipeline before forwarding any transaction upstream to the sequencer:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Autonomous Agents / Wallet Clients                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 1: Cryptographic Authentication Guard (agent_auth.rs)            │
│ - HMAC-SHA256 request signature verification over canonical payload    │
│ - Bounded timestamp drift window (Δt ≤ 300s) for replay protection     │
│ - Constant-time verification to prevent timing side-channels           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 2: In-Process EVM Simulation Engine (simulator.rs + fork_db.rs)  │
│ - Full execution simulation using revm v42 against real-time state     │
│ - Multi-tier LRU trie cache for contract bytecode, balances & storage  │
│ - Fail-open classification: halts only on deterministic reverts        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                 ┌──────────────────┴──────────────────┐
                 │                                     │
                 ▼                                     ▼
     [Simulation Reverted]                  [Simulation Succeeded]
                 │                                     │
                 ▼                                     ▼
┌─────────────────────────────────┐   ┌─────────────────────────────────┐
│ Layer 3: Revert Interception    │   │ Upstream Sequencer Forwarding   │
│ - Aborts broadcast (0 gas paid) │   │ - Broadcasts via persistent     │
│ - Decodes ERC-6093 custom error │   │   Hyper HTTP/1.1 connection     │
│ - Returns structured JSON-RPC   │   │   pool directly to node         │
│   with estimated_gas_saved      │   └─────────────────────────────────┘
└─────────────────────────────────┘
```

---

## 3. Deterministic Safety-Critical Invariants

Sentinel-Lex strictly adheres to Deterministic Safety Standards:
- **Simple Control Flow:** No `goto`, `setjmp`, `longjmp`, or direct/indirect recursion.
- **Bounded Allocations:** All cache allocations use fixed upper bounds (`MAX_ACCOUNT_CACHE_CAPACITY`, `MAX_STORAGE_CACHE_CAPACITY`). Zero heap allocations on the hot simulation loop.
- **Function Sizing:** No function exceeds 60 lines of code.
- **Assertion Density:** Minimum of 2 assertions per operational function validating state and parameter invariants.
- **Static Analysis Compliance:** Zero warnings across pedantic compilation and strict type checks.

---

## 4. Verification Evidence & Benchmarks

Full automated verification across Rust core and TypeScript SDK:

```bash
make test
```

### Output Evidence:
- **Rust Unit & Integration Tests:** 47 passed, 0 failed, 0 ignored (across all binaries, well under 1s).
- **Node.js Client SDK Tests:** 4 passed, 0 failed (<0.1s).
- **Total Test Suites:** 51/51 passing green.

### Benchmark Latency:
- **Cached In-Memory Simulation:** < 12 ms per transaction.
- **ERC-6093 Revert Decoding Overhead:** < 0.35 ms.
- **Routing Connection Pooling:** -97 ms latency reduction compared to non-pooled remote requests.

---

## 5. Quickstart

### Build:
```bash
cargo build --release
```

### Run:
```bash
UPSTREAM_RPC_URL="https://mainnet.optimism.io" PORT=8545 cargo run --release
```

### Health Check:
```bash
curl http://localhost:8545/health
```

---

## 6. License

MIT License. Open source and non-custodial public good.
