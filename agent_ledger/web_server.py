"""
AgentLedger web GUI server — stdlib http.server only, no build step.

Binds to 127.0.0.1 by default (local tool, no auth). Pass --host 0.0.0.0
only on a trusted network — anyone who can reach it can read and append
to the ledger.

API:
  GET  /api/stats                 dashboard numbers
  GET  /api/blocks?agent=&action=&limit=
  GET  /api/verify                chain + signature status
  GET  /api/root                  Merkle root
  POST /api/log        {agent, tool, params, result, approve}
  POST /api/policy-check {tool, params}
  POST /api/receipt    {agent, prompt, model, tool, params, result, append}
Static files are served from agent_ledger/web/.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .ledger import Ledger
from .attest import signer_for_ledger
from .policy import PolicyEngine
from .helper import LedgerSession, PolicyBlocked

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")

CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "application/javascript",
                 ".svg": "image/svg+xml", ".png": "image/png", ".json": "application/json"}


def make_handler(ledger_path: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # keep the terminal quiet
            pass

        def _ledger(self):
            return Ledger(ledger_path)

        def _send_json(self, obj, status=200):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self):
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return {}
            try:
                return json.loads(self.rfile.read(length).decode("utf-8"))
            except Exception:
                return {}

        def do_GET(self):
            parsed = urlparse(self.path)
            route = parsed.path
            if route == "/api/stats":
                ledger = self._ledger()
                blocks = ledger.all_blocks()
                signer = signer_for_ledger(ledger_path)
                detail = ledger.verify_detailed(signer=signer)
                agents = sorted(set(b.agent_id for b in blocks))
                self._send_json({
                    "blocks": len(blocks), "agents": len(agents), "agent_list": agents,
                    "chain_valid": detail["chain_valid"],
                    "chain_status": "VERIFIED" if detail["chain_valid"] else "BROKEN",
                    "last_block": blocks[-1].to_dict() if blocks else None,
                    "merkle_root": ledger.merkle_root(),
                    "blocked": sum(1 for b in blocks if b.action_type == "policy_block"),
                })
                return
            if route == "/api/blocks":
                qs = parse_qs(parsed.query)
                blocks = self._ledger().all_blocks()
                agent = (qs.get("agent") or [""])[0]
                action = (qs.get("action") or [""])[0]
                limit = int((qs.get("limit") or ["100"])[0])
                if agent:
                    blocks = [b for b in blocks if b.agent_id == agent]
                if action:
                    blocks = [b for b in blocks if b.action_type == action]
                blocks = list(reversed(blocks[-limit:])) if limit else list(reversed(blocks))
                self._send_json({"blocks": [b.to_dict() for b in blocks], "total": len(blocks)})
                return
            if route == "/api/verify":
                signer = signer_for_ledger(ledger_path)
                self._send_json(self._ledger().verify_detailed(signer=signer))
                return
            if route == "/api/root":
                ledger = self._ledger()
                self._send_json({"root": ledger.merkle_root(), "blocks": len(ledger.block_hashes())})
                return
            if route == "/api/policy":
                self._send_json(PolicyEngine().policy.to_dict())
                return
            # static
            if route in ("/", ""):
                route = "/index.html"
            if route == "/logo.svg":
                return self._serve_file(os.path.join(ASSETS_DIR, "logo.svg"))
            safe = os.path.normpath(route.lstrip("/"))
            if safe.startswith(".."):
                self.send_error(404)
                return
            self._serve_file(os.path.join(WEB_DIR, safe))

        def _serve_file(self, filepath):
            if not os.path.isfile(filepath):
                self.send_error(404)
                return
            ext = os.path.splitext(filepath)[1].lower()
            with open(filepath, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPES.get(ext, "application/octet-stream"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            route = urlparse(self.path).path
            data = self._read_json()
            if route == "/api/policy-check":
                allowed, status, reason = PolicyEngine().check(data.get("tool", ""), data.get("params") or {})
                self._send_json({"allowed": allowed, "status": status, "reason": reason})
                return
            if route == "/api/log":
                session = LedgerSession(ledger_path, data.get("agent") or "gui-agent")
                try:
                    block = session.log(data.get("tool") or "tool_call", data.get("params") or {},
                                        result=data.get("result"), approve=bool(data.get("approve")))
                except PolicyBlocked as e:
                    self._send_json({"blocked": True, "status": e.status, "reason": e.reason},
                                    status=403 if e.status == "BLOCKED" else 409)
                    return
                self._send_json({"block_index": block.index, "block_hash": block.block_hash})
                return
            if route == "/api/receipt":
                signer = signer_for_ledger(ledger_path)
                if signer is None:
                    self._send_json({"error": "no signing key available"}, status=500)
                    return
                ledger = self._ledger()
                parent = ""
                if data.get("append"):
                    last = ledger.get_last_block()
                    parent = last.block_hash if last else Ledger.GENESIS_PREV_HASH
                rc = signer.generate_receipt(
                    agent_id=data.get("agent") or "gui-agent", action="tool_call",
                    prompt=data.get("prompt") or "", model=data.get("model") or "claude-3-5-sonnet",
                    tool_name=data.get("tool") or "", tool_params=data.get("params") or {},
                    tool_result=data.get("result") if data.get("result") is not None else {},
                    block_hash=parent or "0" * 64)
                if data.get("append"):
                    payload = {"receipt": rc}
                    block = ledger.append(data.get("agent") or "gui-agent", "receipt", payload,
                                          signature=signer.sign(payload))
                    rc = dict(rc)
                    rc["appended_block"] = block.index
                self._send_json(rc)
                return
            self.send_error(404)

    return Handler


def serve(ledger_path: str, host: str = "127.0.0.1", port: int = 8765):
    server = ThreadingHTTPServer((host, port), make_handler(ledger_path))
    print(f"AgentLedger GUI: http://{host}:{port}  (ledger: {os.path.abspath(ledger_path)})")
    print("Local tool with no login — keep it on localhost unless your network is trusted.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
