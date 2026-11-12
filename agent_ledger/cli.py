"""
AgentLedger CLI: Command-line interface for audit trails, verification, and attestations.
"""

import argparse
import json
import os
import sys
from .ledger import Ledger
from .attest import AttestationSigner
from .policy import PolicyEngine


def get_default_ledger_path() -> str:
    home = os.path.expanduser("~")
    return os.path.join(home, ".agent-ledger", "ledger.jsonl")


def cmd_init(args):
    path = args.path or get_default_ledger_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        print(f"Ledger already exists at: {path}")
    else:
        with open(path, "w", encoding="utf-8") as f:
            pass
        print(f"Initialized new cryptographic AgentLedger at: {path}")


def cmd_log(args):
    path = args.path or get_default_ledger_path()
    ledger = Ledger(path)
    signer = AttestationSigner()

    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError:
        payload = {"raw_payload": args.payload}

    signature = signer.sign(payload)
    block = ledger.append(
        agent_id=args.agent,
        action_type=args.action,
        payload=payload,
        signature=signature,
    )

    print(f"Recorded Block #{block.index}")
    print(f"  Block Hash: {block.block_hash}")
    print(f"  Prev Hash:  {block.prev_hash}")
    print(f"  Signature:  {block.signature[:16]}...")


def cmd_verify(args):
    path = args.path or get_default_ledger_path()
    if not os.path.exists(path):
        print(f"Error: Ledger file does not exist at {path}")
        sys.exit(1)

    ledger = Ledger(path)
    is_valid, err, count = ledger.verify()

    if is_valid:
        print(f"VERIFIED: Ledger at {path} is cryptographically valid.")
        print(f"Total blocks checked: {count}")
    else:
        print(f"FAILED: Ledger validation failed!")
        print(f"Error: {err}")
        sys.exit(2)


def cmd_audit(args):
    path = args.path or get_default_ledger_path()
    ledger = Ledger(path)
    blocks = ledger.all_blocks()

    print(f"--- AgentLedger Audit Report: {len(blocks)} Blocks ---")
    for b in blocks[-args.limit:]:
        print(f"[{b.index}] {b.agent_id} | {b.action_type} | hash:{b.block_hash[:12]} | prev:{b.prev_hash[:12]}")
        print(f"    Payload: {json.dumps(b.payload)[:100]}...")


def cmd_receipt(args):
    signer = AttestationSigner()
    try:
        params = json.loads(args.params)
    except Exception:
        params = {"raw": args.params}

    try:
        result = json.loads(args.result)
    except Exception:
        result = {"raw": args.result}

    rc = signer.generate_receipt(
        agent_id=args.agent,
        action=args.action,
        prompt=args.prompt,
        model=args.model,
        tool_name=args.tool,
        tool_params=params,
        tool_result=result,
        block_hash=args.block_hash or "0" * 64,
    )
    print(json.dumps(rc, indent=2))


def main():
    parser = argparse.ArgumentParser(
        prog="agent-ledger",
        description="AgentLedger: Cryptographic Action Attestation & Governance for AI Agents",
    )
    parser.add_argument("--path", "-p", help="Custom path to ledger.jsonl")

    subparsers = parser.add_subparsers(dest="command")

    # init
    p_init = subparsers.add_parser("init", help="Initialize a new ledger")
    p_init.set_defaults(func=cmd_init)

    # log
    p_log = subparsers.add_parser("log", help="Append an action block to the ledger")
    p_log.add_argument("--agent", "-a", required=True, help="Agent ID")
    p_log.add_argument("--action", "-t", required=True, help="Action type (tool_call, prompt, etc)")
    p_log.add_argument("--payload", "-d", required=True, help="JSON or string payload")
    p_log.set_defaults(func=cmd_log)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify Merkle chain integrity of the ledger")
    p_verify.set_defaults(func=cmd_verify)

    # audit
    p_audit = subparsers.add_parser("audit", help="Inspect recent ledger blocks")
    p_audit.add_argument("--limit", "-n", type=int, default=15, help="Number of blocks to inspect")
    p_audit.set_defaults(func=cmd_audit)

    # receipt
    p_receipt = subparsers.add_parser("receipt", help="Generate an attestation receipt")
    p_receipt.add_argument("--agent", required=True)
    p_receipt.add_argument("--action", default="tool_call")
    p_receipt.add_argument("--prompt", required=True)
    p_receipt.add_argument("--model", default="claude-3-5-sonnet")
    p_receipt.add_argument("--tool", required=True)
    p_receipt.add_argument("--params", default="{}")
    p_receipt.add_argument("--result", default="{}")
    p_receipt.add_argument("--block-hash", default="")
    p_receipt.set_defaults(func=cmd_receipt)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
