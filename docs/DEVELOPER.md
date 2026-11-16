# AgentLedger — Developer Guide

## Architecture

Zero external dependencies. Python standard library only, Python ≥ 3.8.

| Module | Role |
|---|---|
| `agent_ledger/ledger.py` | Hash chain, Merkle tree/proofs, file locking, verification |
| `agent_ledger/attest.py` | HMAC-SHA256 signer, per-ledger key files, receipts |
| `agent_ledger/policy.py` | Policy rules: blocked tools/patterns, approval gates, cost ceiling |
| `agent_ledger/cli.py` | All CLI commands |
| `agent_ledger/helper.py` | `LedgerSession` / `record_action` Python API (policy integrated) |
| `agent_ledger/mcp_server.py` | Stdio JSON-RPC MCP server, 7 tools |
| `agent_ledger/web_server.py` | GUI HTTP server + JSON API (stdlib `http.server`) |
| `agent_ledger/web/` | Vanilla HTML/CSS/JS single-page GUI, no build step |
| `tools/seed_demo.py` | Fake-data demo ledger for screenshots/demos |
| `assets/` | Logo SVG sources + rendered PNGs |

## File formats

### Ledger file (`ledger.jsonl`)
One canonical-JSON object per line (keys sorted, no spaces). Fields:
`index, timestamp, agent_id, action_type, payload, payload_hash, prev_hash,
signature, block_hash`.

- `block_hash = SHA256(canonical_json({index, timestamp(rounded to 4dp),
  agent_id, action_type, payload_hash, prev_hash, signature}))`
- `payload_hash = SHA256(canonical_json(payload))`
- Genesis `prev_hash` is 64 zero characters.
- `signature = HMAC-SHA256(key, canonical_json(payload))`, or `""` for an
  unsigned block (only when no key was available at append time).

This format is unchanged from v1: v1 ledger files verify with v2.

### Key file (`<ledger>.key`)
Beside the ledger, e.g. `ledger.jsonl.key`. Contains one hex string
(64 chars, 32 random bytes), mode `0600`, created by `init` (and never
overwritten). Resolution order for signing:

1. explicit `secret_key` argument (embedding/tests)
2. `AGENT_LEDGER_KEY` environment variable
3. the per-ledger key file

There is deliberately no default key. `AttestationSigner()` with none of the
above raises `ValueError`.

### Receipt
A dict with SHA-256 digests of prompt, tool params and tool result, the
parent block hash, an HMAC `signature` over those fields, and a 16-char
`receipt_id` derived from the signature. With `--append`, the receipt is
stored as a block of `action_type="receipt"` with payload `{"receipt": …}`
and `parent_block_hash` set to the head block at append time.

## The chain, Merkle tree and proofs

The chain gives order and tamper evidence. The Merkle tree is a second,
independent commitment over the ordered block hashes:

- Leaves are block hashes in index order.
- Parent = `SHA256(left_hex + right_hex)`; an odd node at a level is
  promoted unchanged (same rule as the original v1 `MerkleTree` class).
- `Ledger.merkle_root()`, CLI `root`, MCP `ledger_root`, GUI Verify screen.
- A proof is a list of `{"hash", "position"}` steps (`position` = where the
  sibling sits). `verify_merkle_proof(leaf, proof, root)` folds the leaf up
  and compares. CLI: `prove --block N`, `prove --verify [--proof file|json]`,
  and the `verify-proof` alias.

## Policy

`PolicyRule.evaluate(tool, params) -> (allowed, status, reason)` with status
`PASS | BLOCKED | APPROVAL_REQUIRED`. Order of checks:

1. Blocked tools (normalised name match)
2. Prohibited patterns over tool name + params (normalised: NFKC unicode,
   zero-width characters removed, case folded, whitespace collapsed) → BLOCKED
3. Cost ceiling: a numeric `cost_usd|cost|amount_usd|price_usd` in params
   above `max_cost_usd` → APPROVAL_REQUIRED
4. Approval triggers: substring match in the tool name, **whole-token**
   match in params (so "format" does not trip "rm") → APPROVAL_REQUIRED

CLI `log` behaviour: BLOCKED → refusal appended as a `policy_block` block,
exit 3. APPROVAL_REQUIRED without `--approve` → same, exit 4. With
`--approve`, the stored payload is a wrapper
`{"approved": true, "policy_status": "APPROVAL_REQUIRED", "data": <original>}` —
the caller's payload object is never mutated.

## Concurrency

`Ledger.append()` opens the file `a+`, takes an exclusive `fcntl.flock`
(POSIX; graceful no-op where `fcntl` is unavailable), reads the tail by
seeking from the end of the file (no full scan), writes, flushes and
fsyncs, then unlocks. Two processes appending at once therefore produce a
single linear chain. (On non-POSIX platforms there is no locking — noted
honest limitation.)

## GUI API

Served by `web_server.make_handler(ledger_path)`; binds 127.0.0.1 by
default, no auth (local tool). Endpoints: `GET /api/stats`,
`GET /api/blocks?agent=&action=&limit=`, `GET /api/verify`, `GET /api/root`,
`GET /api/policy`, `POST /api/log`, `POST /api/policy-check`,
`POST /api/receipt`. Blocked GUI logs return 403, approval-required 409,
with `{"blocked": true, "status", "reason"}`.

## MCP server

Newline-delimited JSON-RPC 2.0 on stdio. Handles `initialize`, `ping`,
`tools/list`, `tools/call`; notifications are ignored. Tool results are
returned as a single text content item containing JSON. `ledger_log`
enforces policy via `LedgerSession` and returns
`{"blocked": true, "status", "reason"}` instead of raising.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

No pytest required. Suites: `test_ledger.py` (original v1 tests, unchanged),
`test_v2_core.py`, `test_v2_features.py`, `test_v2_mcp_gui.py`.

## Deliberate v1 → v2 behaviour changes

1. `AttestationSigner()` no longer falls back to a built-in key (raises).
2. `agent-ledger log` enforces policy (v1 never called it).
3. `init` creates a key file as well as the ledger file.
4. `verify` output gained Chain/Signatures lines; exit codes unchanged
   for chain failure (2), new codes 3 (blocked) and 4 (approval) on `log`.
5. README clone URL corrected to `satiralabs/agent-ledger`.
