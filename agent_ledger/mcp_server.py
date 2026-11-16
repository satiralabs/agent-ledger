"""
AgentLedger MCP server — stdlib-only, stdio JSON-RPC 2.0 (hand-rolled).

Run:  agent-ledger-mcp [--path /path/to/ledger.jsonl]
Or:   python3 -m agent_ledger.mcp_server --path ...

Tools: ledger_log, ledger_verify, ledger_audit, ledger_receipt,
       ledger_root, ledger_prove, policy_check
Policy is enforced inside ledger_log exactly as in the CLI.
"""

import json
import os
import sys

from .ledger import Ledger, verify_merkle_proof
from .attest import signer_for_ledger
from .policy import PolicyEngine
from .helper import LedgerSession, PolicyBlocked

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {"name": "ledger_log", "description": "Log a tool call to the ledger (policy enforced).",
     "inputSchema": {"type": "object", "properties": {
         "agent": {"type": "string"}, "tool": {"type": "string"},
         "params": {"type": "object"}, "result": {},
         "approve": {"type": "boolean", "default": False}}, "required": ["agent", "tool"]}},
    {"name": "ledger_verify", "description": "Verify chain integrity and signatures.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "ledger_audit", "description": "List recent blocks, optionally filtered.",
     "inputSchema": {"type": "object", "properties": {
         "agent": {"type": "string"}, "action": {"type": "string"}, "limit": {"type": "integer", "default": 15}}}},
    {"name": "ledger_receipt", "description": "Generate a signed attestation receipt.",
     "inputSchema": {"type": "object", "properties": {
         "agent": {"type": "string"}, "prompt": {"type": "string"}, "tool": {"type": "string"},
         "model": {"type": "string", "default": "claude-3-5-sonnet"},
         "params": {"type": "object"}, "result": {}, "append": {"type": "boolean", "default": False}},
         "required": ["agent", "prompt", "tool"]}},
    {"name": "ledger_root", "description": "Merkle root over all block hashes.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "ledger_prove", "description": "Inclusion proof for one block index.",
     "inputSchema": {"type": "object", "properties": {"block": {"type": "integer"}}, "required": ["block"]}},
    {"name": "policy_check", "description": "Check a tool call against policy without logging it.",
     "inputSchema": {"type": "object", "properties": {
         "tool": {"type": "string"}, "params": {"type": "object"}}, "required": ["tool"]}},
]


class MCPServer:
    def __init__(self, ledger_path: str):
        self.ledger_path = ledger_path
        self.ledger = Ledger(ledger_path)

    # -- tool implementations ------------------------------------------------
    def _tool_log(self, args):
        session = LedgerSession(self.ledger_path, args.get("agent", "unknown"))
        try:
            block = session.log(args.get("tool", "tool_call"), args.get("params") or {},
                                result=args.get("result"), approve=bool(args.get("approve", False)))
        except PolicyBlocked as e:
            return {"blocked": True, "status": e.status, "reason": e.reason}
        return {"block_index": block.index, "block_hash": block.block_hash, "prev_hash": block.prev_hash}

    def _tool_verify(self, args):
        signer = signer_for_ledger(self.ledger_path)
        return self.ledger.verify_detailed(signer=signer)

    def _tool_audit(self, args):
        blocks = self.ledger.all_blocks()
        if args.get("agent"):
            blocks = [b for b in blocks if b.agent_id == args["agent"]]
        if args.get("action"):
            blocks = [b for b in blocks if b.action_type == args["action"]]
        limit = int(args.get("limit", 15))
        return {"blocks": [b.to_dict() for b in blocks[-limit:]] if limit else [b.to_dict() for b in blocks],
                "total": len(blocks)}

    def _tool_receipt(self, args):
        signer = signer_for_ledger(self.ledger_path, required=True)
        parent = ""
        if args.get("append"):
            last = self.ledger.get_last_block()
            parent = last.block_hash if last else Ledger.GENESIS_PREV_HASH
        rc = signer.generate_receipt(
            agent_id=args.get("agent", "unknown"), action="tool_call",
            prompt=args.get("prompt", ""), model=args.get("model", "claude-3-5-sonnet"),
            tool_name=args.get("tool", ""), tool_params=args.get("params") or {},
            tool_result=args.get("result") if args.get("result") is not None else {},
            block_hash=parent or "0" * 64)
        if args.get("append"):
            payload = {"receipt": rc}
            block = self.ledger.append(args.get("agent", "unknown"), "receipt", payload,
                                       signature=signer.sign(payload))
            rc = dict(rc)
            rc["appended_block"] = block.index
        return rc

    def _tool_root(self, args):
        return {"root": self.ledger.merkle_root(), "blocks": len(self.ledger.block_hashes())}

    def _tool_prove(self, args):
        data = self.ledger.merkle_proof(int(args["block"]))
        data["verified"] = verify_merkle_proof(data["block_hash"], data["proof"], data["root"])
        return data

    def _tool_policy(self, args):
        allowed, status, reason = PolicyEngine().check(args.get("tool", ""), args.get("params") or {})
        return {"allowed": allowed, "status": status, "reason": reason}

    # -- JSON-RPC ------------------------------------------------------------
    def call_tool(self, name, args):
        dispatch = {
            "ledger_log": self._tool_log, "ledger_verify": self._tool_verify,
            "ledger_audit": self._tool_audit, "ledger_receipt": self._tool_receipt,
            "ledger_root": self._tool_root, "ledger_prove": self._tool_prove,
            "policy_check": self._tool_policy,
        }
        if name not in dispatch:
            raise ValueError(f"unknown tool: {name}")
        return dispatch[name](args or {})

    def handle(self, request):
        method = request.get("method", "")
        req_id = request.get("id")
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agent-ledger", "version": "2.0.0"}}}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
        if method == "tools/call":
            params = request.get("params") or {}
            try:
                result = self.call_tool(params.get("name", ""), params.get("arguments") or {})
                return {"jsonrpc": "2.0", "id": req_id, "result": {
                    "content": [{"type": "text", "text": json.dumps(result)}], "isError": False}}
            except Exception as e:
                return {"jsonrpc": "2.0", "id": req_id, "result": {
                    "content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}}
        if req_id is None:
            return None  # notification
        return {"jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": f"method not found: {method}"}}

    def serve_stdio(self, instream=None, outstream=None):
        instream = instream or sys.stdin
        outstream = outstream or sys.stdout
        for line in instream:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except Exception:
                continue
            response = self.handle(request)
            if response is not None:
                outstream.write(json.dumps(response) + "\n")
                outstream.flush()


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="agent-ledger-mcp", description="AgentLedger MCP server (stdio)")
    parser.add_argument("--path", "-p", default=None, help="Path to ledger.jsonl")
    args = parser.parse_args(argv)
    path = args.path or os.path.join(os.path.expanduser("~"), ".agent-ledger", "ledger.jsonl")
    MCPServer(path).serve_stdio()


if __name__ == "__main__":
    main()
