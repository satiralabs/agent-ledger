# AgentLedger (MeshVeritas)

> **Cryptographic Action Attestation & Merkle Audit Trail for Autonomous AI Agents.**  
> *Zero-overhead, tamper-evident governance ledger for multi-agent tool execution.*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/downloads/)
[![Zero-Dependency](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)]()
[![Grant-Ready](https://img.shields.io/badge/Grant--Eligible-Mozilla%20%7C%20OpenAI%20Governance-orange.svg)]()

---

## 🎯 Abstract & Problem Statement

Autonomous multi-agent systems (AutoGPT, CrewAI, LangGraph, Anthropic computer-use) execute thousands of arbitrary shell, API, database, and financial actions every minute. When an agent experiences hallucinations, model drift, prompt injection, or accidental data exfiltration, post-incident attribution is currently impossible: standard application logs can be altered, truncated, or forged by the compromised agent itself.

**AgentLedger** solves this by providing a lightweight, append-only, SHA-256 Merkle-linked audit trail and HMAC action attestation engine. Every tool call, prompt hash, model signature, and tool response is mathematically linked to the previous block. Any retrospective manipulation immediately invalidates the cryptographic chain.

---

## ⚡ Key Capabilities

- **Zero-Dependency Core**: Written entirely in standard library Python (`hashlib`, `hmac`, `json`). Works everywhere without `pip install` bloat or C-extension compatibility issues.
- **Append-Only Merkle Hash Chain**: Each action block links to the preceding block hash with canonical JSON serialization.
- **HMAC Action Receipts**: Produces cryptographically signed action receipts validating prompt hash, model ID, tool parameters, and execution output.
- **Zero-Trust Policy Guard**: Real-time evaluation of tool actions (blocking destructive shell commands, parameter injection patterns, and enforcing micro-escrow human approvals).
- **Sub-Millisecond Overhead**: Benchmarked at `< 0.3ms` per recorded action; zero idle memory consumption.

---

## 🚀 Quickstart

### Installation

```bash
git clone https://github.com/abenih/agent-ledger.git
cd agent-ledger
pip install -e .
```

Or run directly without installation:

```bash
./bin/agent-ledger --help
```

---

## 📖 CLI Usage

### 1. Initialize a Ledger
```bash
agent-ledger init
```

### 2. Log an Autonomous Action
```bash
agent-ledger log \
  --agent "coder-agent-01" \
  --action "tool_call" \
  --payload '{"tool": "bash", "cmd": "git status", "status": "success"}'
```

### 3. Verify Entire Ledger Integrity
```bash
agent-ledger verify
# Output: VERIFIED: Ledger is cryptographically valid. Total blocks checked: 42
```

### 4. Generate an Audit Receipt
```bash
agent-ledger receipt \
  --agent "researcher-02" \
  --prompt "Summarize user financial statements" \
  --model "claude-3-5-sonnet" \
  --tool "sql_query" \
  --params '{"query": "SELECT balance FROM accounts"}' \
  --result '{"balance": 15400}'
```

---

## 🛡️ Threat Model & Security Properties

| Attack Vector | Defense Mechanism |
|---|---|
| **Log Forgery / Deletion** | SHA-256 Merkle chain linking prevents silent removal or modification of prior actions. |
| **Prompt Injection Cover-up** | Input prompt hash is recorded before execution and signed with host HMAC key. |
| **Unauthorized Action Execution** | Zero-trust policy guard halts execution if parameters trigger blocked patterns. |
| **Hallucinated State Replay** | Blocks carry strict monotonically increasing indices and timestamp anchors. |

---

## 🏆 Research & Grant Alignment

AgentLedger is architected specifically to align with:
- **Mozilla Technology Fund (AI Accountability & Trust)**
- **OpenAI Democratic Governance / AI Safety Grants**
- **Emergent Ventures Fast Grants**

---

## 📄 License
MIT License. Created by [Susan (Abenezer)](https://satiralabs.com) at SatiraLabs.
