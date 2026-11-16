"""
AgentLedger CLI: Command-line interface for audit trails, verification, and attestations.

v2 deliberate changes (see docs/DEVELOPER.md):
- `log` enforces policy: BLOCKED -> exit 3 and the refusal is appended as a
  `policy_block` block; APPROVAL_REQUIRED -> exit 4 unless --approve is given,
  in which case the stored payload is a wrapper {"approved": true,
  "policy_status": ..., "data": <original payload>} (original never mutated).
- `init` also creates a random per-ledger key file (<ledger>.key, 0600).
- --path is accepted before OR after the subcommand.
- New commands: policy-check, root, prove, verify-proof, export, serve.
- `receipt --append` appends the receipt to the ledger, auto-linked to the head.
- `verify` reports chain validity and signature verification separately.
Exit codes: 0 ok, 1 usage/io error, 2 verify failed, 3 policy BLOCKED, 4 approval required.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from .ledger import Ledger, verify_merkle_proof
from .attest import AttestationSigner, generate_key_file, key_path_for_ledger, signer_for_ledger
from .policy import PolicyEngine


def get_default_ledger_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".agent-ledger", "ledger.jsonl")


def _path(args) -> str:
    return getattr(args, "path", None) or get_default_ledger_path()


def _signer_for(path: str, warn: bool = True):
    signer = signer_for_ledger(path)
    if signer is None and warn:
        print("WARNING: no signing key found (no AGENT_LEDGER_KEY, no key file). "
              "This action will be recorded UNSIGNED. Run `agent-ledger init` to create a key.",
              file=sys.stderr)
    return signer


def _sign(signer, payload) -> str:
    return signer.sign(payload) if signer is not None else ""


def _parse_json_or_raw(text, raw_key="raw_payload"):
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {raw_key: value}
    except Exception:
        return {raw_key: text}


def _tool_and_params(payload, explicit_tool=None):
    if isinstance(payload, dict):
        tool = explicit_tool or str(payload.get("tool") or payload.get("tool_name") or "tool_call")
        return tool, payload
    return explicit_tool or "tool_call", {"raw_payload": payload}


# ---------------------------------------------------------------- commands

def cmd_init(args):
    path = _path(args)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    existed = os.path.exists(path)
    Ledger(path)  # creates the file if missing
    kpath = generate_key_file(path)
    if existed:
        print(f"Ledger already exists at: {path}")
    else:
        print(f"Initialized new cryptographic AgentLedger at: {path}")
    print(f"Signing key file: {kpath} (mode 0600, keep it secret)")


def cmd_log(args):
    path = _path(args)
    ledger = Ledger(path)
    signer = _signer_for(path)
    payload = _parse_json_or_raw(args.payload)
    tool, params = _tool_and_params(payload, getattr(args, "tool", None))
    engine = PolicyEngine()
    allowed, status, reason = engine.check(tool, params)

    if not allowed and status == "BLOCKED":
        block_payload = {"tool": tool, "params": params, "policy_status": "BLOCKED",
                         "reason": reason, "original_action": args.action, "original_payload": payload}
        block = ledger.append(args.agent, "policy_block", block_payload, signature=_sign(signer, block_payload))
        print(f"BLOCKED by policy: {reason}", file=sys.stderr)
        print(f"Refusal recorded as Block #{block.index} (policy_block)")
        sys.exit(3)

    if not allowed and status == "APPROVAL_REQUIRED" and not getattr(args, "approve", False):
        block_payload = {"tool": tool, "params": params, "policy_status": "APPROVAL_REQUIRED",
                         "reason": reason, "original_action": args.action, "original_payload": payload}
        block = ledger.append(args.agent, "policy_block", block_payload, signature=_sign(signer, block_payload))
        print(f"APPROVAL REQUIRED: {reason}", file=sys.stderr)
        print(f"Refusal recorded as Block #{block.index} (policy_block). Re-run with --approve to proceed.")
        sys.exit(4)

    stored = payload
    if not allowed and status == "APPROVAL_REQUIRED" and getattr(args, "approve", False):
        stored = {"approved": True, "policy_status": "APPROVAL_REQUIRED", "data": payload}

    signature = _sign(signer, stored)
    block = ledger.append(agent_id=args.agent, action_type=args.action, payload=stored, signature=signature)
    print(f"Recorded Block #{block.index}")
    print(f"  Block Hash: {block.block_hash}")
    print(f"  Prev Hash:  {block.prev_hash}")
    print(f"  Signature:  {block.signature[:16]}..." if block.signature else "  Signature:  (unsigned)")


def cmd_policy_check(args):
    try:
        params = json.loads(args.params)
        if not isinstance(params, dict):
            params = {"value": params}
    except Exception:
        params = {"raw": args.params}
    allowed, status, reason = PolicyEngine().check(args.tool, params)
    if getattr(args, "json", False):
        print(json.dumps({"tool": args.tool, "allowed": allowed, "status": status, "reason": reason}, indent=2))
    else:
        print(f"{status}: {reason}")
    if status == "BLOCKED":
        sys.exit(3)
    if status == "APPROVAL_REQUIRED":
        sys.exit(4)


def cmd_verify(args):
    path = _path(args)
    if not os.path.exists(path):
        print(f"Error: Ledger file does not exist at {path}")
        sys.exit(1)
    ledger = Ledger(path)
    signer = signer_for_ledger(path)
    detail = ledger.verify_detailed(signer=signer)
    if getattr(args, "json", False):
        print(json.dumps(detail, indent=2))
    if detail["chain_valid"]:
        print(f"VERIFIED: Ledger at {path} is cryptographically valid.")
        print(f"Chain: valid — {detail['count']} blocks checked")
    else:
        print("FAILED: Ledger validation failed!")
        print(f"Error: {detail['error']}")
        sys.exit(2)
    if signer is None:
        print("Signatures: not checked (no signing key available)")
    elif detail["signatures_valid"]:
        print(f"Signatures: valid — {detail['signatures_checked']} signed blocks checked, {detail['unsigned_count']} unsigned")
    else:
        print(f"Signatures: FAILED — {detail['signature_error']}")
        sys.exit(2)


def _parse_since(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        pass
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        # date only
        dt = datetime.strptime(text, "%Y-%m-%d")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def cmd_audit(args):
    path = _path(args)
    ledger = Ledger(path)
    blocks = ledger.all_blocks()
    if getattr(args, "agent", None):
        blocks = [b for b in blocks if b.agent_id == args.agent]
    if getattr(args, "action", None):
        blocks = [b for b in blocks if b.action_type == args.action]
    if getattr(args, "since", None):
        since_ts = _parse_since(args.since)
        blocks = [b for b in blocks if b.timestamp >= since_ts]
    total = len(blocks)
    shown = blocks[-args.limit:] if args.limit else blocks
    print(f"--- AgentLedger Audit Report: {total} Blocks (showing {len(shown)}) ---")
    for b in shown:
        print(f"[{b.index}] {b.agent_id} | {b.action_type} | hash:{b.block_hash[:12]} | prev:{b.prev_hash[:12]}")
        print(f"    Payload: {json.dumps(b.payload)[:120]}...")


def cmd_receipt(args):
    path = _path(args)
    signer = signer_for_ledger(path, required=False)
    if signer is None:
        signer = signer_for_ledger(None, required=False)
    if signer is None:
        print("Error: no signing key available. Set AGENT_LEDGER_KEY or run `agent-ledger init` first.", file=sys.stderr)
        sys.exit(1)
    params = _parse_json_or_raw(args.params, raw_key="raw")
    result = _parse_json_or_raw(args.result, raw_key="raw")
    parent = args.block_hash or ""
    ledger = None
    if getattr(args, "append", False):
        ledger = Ledger(path)
        last = ledger.get_last_block()
        parent = last.block_hash if last is not None else Ledger.GENESIS_PREV_HASH
    elif not parent:
        parent = "0" * 64
    rc = signer.generate_receipt(agent_id=args.agent, action=args.action, prompt=args.prompt,
                                 model=args.model, tool_name=args.tool, tool_params=params,
                                 tool_result=result, block_hash=parent)
    print(json.dumps(rc, indent=2))
    if getattr(args, "append", False) and ledger is not None:
        payload = {"receipt": rc}
        block = ledger.append(args.agent, "receipt", payload, signature=_sign(signer, payload))
        print(f"Receipt appended as Block #{block.index} (parent {parent[:12]}...)")


def cmd_root(args):
    path = _path(args)
    ledger = Ledger(path)
    hashes = ledger.block_hashes()
    root = ledger.merkle_root()
    if getattr(args, "json", False):
        print(json.dumps({"root": root, "blocks": len(hashes), "ledger": path}, indent=2))
    else:
        if not hashes:
            print("Merkle root: (empty ledger)")
        else:
            print(f"Merkle root: {root}")
        print(f"Blocks: {len(hashes)}")


def cmd_prove(args):
    path = _path(args)
    ledger = Ledger(path)
    if getattr(args, "verify", False):
        # Verify mode: proof JSON from --proof (file path or inline JSON), else self-check.
        if getattr(args, "proof", None):
            raw = args.proof
            if os.path.exists(raw):
                with open(raw, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = json.loads(raw)
            leaf = data.get("block_hash") or data.get("leaf") or ""
            proof = data.get("proof", [])
            root = getattr(args, "root", None) or data.get("root", "")
            ok = verify_merkle_proof(leaf, proof, root)
            print("PROOF VERIFIED" if ok else "PROOF FAILED")
            sys.exit(0 if ok else 2)
        # self-check against the ledger itself
        data = ledger.merkle_proof(args.block)
        ok = verify_merkle_proof(data["block_hash"], data["proof"], data["root"])
        print(json.dumps(data, indent=2))
        print("PROOF VERIFIED (self-check)" if ok else "PROOF FAILED")
        sys.exit(0 if ok else 2)
    data = ledger.merkle_proof(args.block)
    print(json.dumps(data, indent=2))


def cmd_export(args):
    import shutil
    import zipfile
    from collections import Counter
    path = _path(args)
    ledger = Ledger(path)
    blocks = ledger.all_blocks()
    signer = signer_for_ledger(path)
    detail = ledger.verify_detailed(signer=signer)
    root = ledger.merkle_root()
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    if os.path.exists(path):
        shutil.copyfile(path, os.path.join(out, "ledger.jsonl"))
    receipts = [b.payload.get("receipt") for b in blocks
                if b.action_type == "receipt" and isinstance(b.payload, dict) and "receipt" in b.payload]
    with open(os.path.join(out, "receipts.json"), "w", encoding="utf-8") as f:
        json.dump(receipts, f, indent=2)
    with open(os.path.join(out, "merkle_root.txt"), "w", encoding="utf-8") as f:
        f.write((root or "(empty ledger)") + "\n")
    per_agent = Counter(b.agent_id for b in blocks)
    per_action = Counter(b.action_type for b in blocks)
    blocked = sum(1 for b in blocks if b.action_type == "policy_block")
    lines = [
        "# AgentLedger Audit Report", "",
        "This bundle lets anyone check what a set of AI agents did, without trusting the person who exported it.", "",
        f"- Ledger file: ledger.jsonl ({len(blocks)} blocks)",
        f"- Chain valid: {'YES' if detail['chain_valid'] else 'NO — ' + str(detail['error'])}",
        f"- Signatures checked: {detail['signatures_checked']} (valid: {detail['signatures_valid']})",
        f"- Merkle root: {root or '(empty ledger)'}",
        f"- Blocked / approval-refused actions: {blocked}", "",
        "## Actions per agent",
    ]
    for agent, count in sorted(per_agent.items()):
        lines.append(f"- {agent}: {count}")
    lines.append("")
    lines.append("## Actions per type")
    for action, count in sorted(per_action.items()):
        lines.append(f"- {action}: {count}")
    lines += ["", "## How to verify this bundle", "",
              "1. Install AgentLedger (no third-party dependencies needed).",
              "2. Run: agent-ledger --path ledger.jsonl verify",
              "3. Run: agent-ledger --path ledger.jsonl root — the root must match merkle_root.txt.",
              "4. To check one action is really in the ledger, run: agent-ledger --path ledger.jsonl prove --block N", ""]
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    manifest = {"blocks": len(blocks), "merkle_root": root, "chain_valid": detail["chain_valid"],
                "signatures_checked": detail["signatures_checked"], "receipts": len(receipts),
                "exported_from": path}
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Exported {len(blocks)} blocks to {out}")
    if getattr(args, "zip", False):
        zpath = out + ".zip"
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            for name in sorted(os.listdir(out)):
                z.write(os.path.join(out, name), arcname=os.path.join(os.path.basename(out), name))
        print(f"Zip bundle: {zpath}")


def cmd_serve(args):
    from .web_server import serve
    serve(_path(args), host=args.host, port=args.port)


# ---------------------------------------------------------------- parser

def _add_path(parser):
    parser.add_argument("--path", "-p", default=argparse.SUPPRESS, help="Custom path to ledger.jsonl")


def main():
    parser = argparse.ArgumentParser(prog="agent-ledger",
        description="AgentLedger: Cryptographic Action Attestation & Governance for AI Agents")
    parser.add_argument("--path", "-p", help="Custom path to ledger.jsonl")
    subparsers = parser.add_subparsers(dest="command")

    p = subparsers.add_parser("init", help="Initialize a new ledger (+ per-ledger key file)")
    _add_path(p); p.set_defaults(func=cmd_init)

    p = subparsers.add_parser("log", help="Append an action block (policy enforced)")
    _add_path(p)
    p.add_argument("--agent", "-a", required=True)
    p.add_argument("--action", "-t", required=True)
    p.add_argument("--payload", "-d", required=True)
    p.add_argument("--tool", help="Tool name for the policy check (default: payload.tool)")
    p.add_argument("--approve", action="store_true", help="Approve an APPROVAL_REQUIRED action")
    p.set_defaults(func=cmd_log)

    p = subparsers.add_parser("policy-check", help="Check a tool call against policy")
    _add_path(p)
    p.add_argument("--tool", required=True)
    p.add_argument("--params", default="{}")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_policy_check)

    p = subparsers.add_parser("verify", help="Verify chain integrity (+ signatures when a key is available)")
    _add_path(p); p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_verify)

    p = subparsers.add_parser("audit", help="Inspect ledger blocks, with filters")
    _add_path(p)
    p.add_argument("--limit", "-n", type=int, default=15)
    p.add_argument("--agent", help="Only this agent")
    p.add_argument("--action", help="Only this action type")
    p.add_argument("--since", help="ISO date/datetime or unix timestamp")
    p.set_defaults(func=cmd_audit)

    p = subparsers.add_parser("receipt", help="Generate an attestation receipt")
    _add_path(p)
    p.add_argument("--agent", required=True)
    p.add_argument("--action", default="tool_call")
    p.add_argument("--prompt", required=True)
    p.add_argument("--model", default="claude-3-5-sonnet")
    p.add_argument("--tool", required=True)
    p.add_argument("--params", default="{}")
    p.add_argument("--result", default="{}")
    p.add_argument("--block-hash", default="")
    p.add_argument("--append", action="store_true", help="Append the receipt to the ledger, linked to the head")
    p.set_defaults(func=cmd_receipt)

    p = subparsers.add_parser("root", help="Print the Merkle root over all block hashes")
    _add_path(p); p.add_argument("--json", action="store_true"); p.set_defaults(func=cmd_root)

    p = subparsers.add_parser("prove", help="Inclusion proof for one block (or verify a proof with --verify)")
    _add_path(p)
    p.add_argument("--block", type=int, default=0)
    p.add_argument("--verify", action="store_true")
    p.add_argument("--proof", help="Proof JSON (inline or file path) to verify")
    p.add_argument("--root", help="Expected Merkle root for --verify with --proof")
    p.set_defaults(func=cmd_prove)

    p = subparsers.add_parser("verify-proof", help="Verify an inclusion proof JSON against a root")
    _add_path(p)
    p.add_argument("--block", type=int, default=0)
    p.add_argument("--proof", help="Proof JSON (inline or file path)")
    p.add_argument("--root")
    p.set_defaults(func=lambda a: (setattr(a, "verify", True), cmd_prove(a))[1])

    p = subparsers.add_parser("export", help="Export a verifiable audit bundle")
    _add_path(p)
    p.add_argument("--out", default="agentledger-export")
    p.add_argument("--zip", action="store_true")
    p.set_defaults(func=cmd_export)

    p = subparsers.add_parser("serve", help="Serve the web GUI (localhost by default)")
    _add_path(p)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
