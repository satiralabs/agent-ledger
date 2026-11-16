#!/usr/bin/env python3
"""
Seed a DEMO ledger with clearly fake data for screenshots and demos.

Usage: python3 tools/seed_demo.py /path/to/demo-ledger.jsonl
Creates the ledger, a per-ledger key file, ~18 actions from 4 fake agents,
signed receipts, and one policy_block refusal (an `rm -rf` attempt).
No real data, no real agents, no real prompts.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_ledger.ledger import Ledger
from agent_ledger.attest import generate_key_file, signer_for_ledger
from agent_ledger.helper import LedgerSession, PolicyBlocked


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join("demo", "demo-ledger.jsonl")
    if os.path.exists(path):
        os.remove(path)
    key_file = path + ".key"
    if os.path.exists(key_file):
        os.remove(key_file)
    Ledger(path)
    generate_key_file(path)
    signer = signer_for_ledger(path, required=True)

    sessions = {name: LedgerSession(path, name) for name in
                ("demo-coder", "demo-researcher", "demo-ops", "demo-writer")}

    sessions["demo-coder"].log("bash", {"cmd": "git status"}, result={"ok": True})
    sessions["demo-coder"].log("read_file", {"path": "src/app.py"}, result={"lines": 212})
    sessions["demo-researcher"].log("web_search", {"query": "merkle tree inclusion proof"}, result={"hits": 8})
    sessions["demo-researcher"].log("sql_query", {"query": "SELECT count(*) FROM demo_accounts"}, result={"rows": 42})
    sessions["demo-writer"].log("write_file", {"path": "drafts/summary.md"}, result={"bytes": 1830})
    sessions["demo-ops"].log("http_get", {"url": "https://example.invalid/health"}, result={"status": 200})
    sessions["demo-coder"].log("bash", {"cmd": "python -m pytest -q"}, result={"passed": 31})
    sessions["demo-researcher"].log("web_search", {"query": "hmac receipt format"}, result={"hits": 5})
    sessions["demo-writer"].log("translate", {"from": "en", "to": "am", "chars": 640}, result={"ok": True})
    sessions["demo-ops"].log("http_get", {"url": "https://example.invalid/metrics"}, result={"status": 200})
    sessions["demo-coder"].log("edit_file", {"path": "src/app.py", "change": "fix typo"}, result={"ok": True})
    sessions["demo-researcher"].log("sql_query", {"query": "SELECT demo balance"}, result={"balance": 15400})

    # One blocked attempt — recorded as a policy_block, never executed.
    try:
        sessions["demo-ops"].log("bash", {"cmd": "rm -rf /tmp/demo"})
    except PolicyBlocked as e:
        print(f"Seeded blocked attempt: {e.status} — {e.reason}")

    # One approved action (transfer trigger, explicitly approved -> wrapped payload).
    sessions["demo-ops"].log("bank_demo", {"op": "transfer demo credits", "amount": 25}, approve=True)

    # Two signed receipts, appended and linked to the head.
    ledger = Ledger(path)
    for agent, prompt, tool, params, result in [
        ("demo-researcher", "Summarise the demo accounts", "sql_query",
         {"query": "SELECT balance FROM demo_accounts"}, {"balance": 15400}),
        ("demo-writer", "Draft a demo release note", "write_file",
         {"path": "drafts/release.md"}, {"bytes": 920}),
    ]:
        last = ledger.get_last_block()
        rc = signer.generate_receipt(agent, "tool_call", prompt, "demo-model-1", tool, params, result,
                                     block_hash=last.block_hash if last else Ledger.GENESIS_PREV_HASH)
        payload = {"receipt": rc}
        ledger.append(agent, "receipt", payload, signature=signer.sign(payload))

    blocks = ledger.all_blocks()
    ok, err, count = ledger.verify()
    print(f"Demo ledger seeded at {path}: {count} blocks, verify={ok}, root={ledger.merkle_root()[:16]}...")


if __name__ == "__main__":
    main()
