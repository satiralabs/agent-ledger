"""v2 MCP + GUI tests: JSON-RPC round-trip and HTTP API smoke tests (no browser)."""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_ledger.ledger import Ledger
from agent_ledger.attest import generate_key_file
from agent_ledger.mcp_server import MCPServer
from agent_ledger.web_server import make_handler


class TestMCP(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.td.name, "l.jsonl")
        Ledger(self.path)
        generate_key_file(self.path)
        self.server = MCPServer(self.path)

    def tearDown(self):
        self.td.cleanup()

    def _call(self, name, args):
        resp = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": name, "arguments": args}})
        return json.loads(resp["result"]["content"][0]["text"])

    def test_initialize_and_tool_list(self):
        resp = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(resp["result"]["serverInfo"]["name"], "agent-ledger")
        resp = self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [t["name"] for t in resp["result"]["tools"]]
        self.assertEqual(len(names), 7)
        for expected in ("ledger_log", "ledger_verify", "ledger_audit", "ledger_receipt",
                         "ledger_root", "ledger_prove", "policy_check"):
            self.assertIn(expected, names)

    def test_tool_round_trip_and_policy(self):
        out = self._call("ledger_log", {"agent": "mcp-a", "tool": "bash", "params": {"cmd": "git status"}})
        self.assertEqual(out["block_index"], 0)
        blocked = self._call("ledger_log", {"agent": "mcp-a", "tool": "bash", "params": {"cmd": "rm -rf /"}})
        self.assertTrue(blocked["blocked"])
        self.assertEqual(blocked["status"], "BLOCKED")
        verify = self._call("ledger_verify", {})
        self.assertTrue(verify["chain_valid"])
        self.assertEqual(verify["count"], 2)  # the refusal was recorded too
        root = self._call("ledger_root", {})
        self.assertTrue(root["root"])
        proof = self._call("ledger_prove", {"block": 0})
        self.assertTrue(proof["verified"])
        audit = self._call("ledger_audit", {"agent": "mcp-a"})
        self.assertEqual(audit["total"], 2)
        receipt = self._call("ledger_receipt", {"agent": "mcp-a", "prompt": "hi", "tool": "sql_query", "append": True})
        self.assertIn("receipt_id", receipt)
        self.assertEqual(receipt["appended_block"], 2)
        policy = self._call("policy_check", {"tool": "bash", "params": {"cmd": "ls"}})
        self.assertEqual(policy["status"], "PASS")


class TestGUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.TemporaryDirectory()
        cls.path = os.path.join(cls.td.name, "l.jsonl")
        Ledger(cls.path)
        generate_key_file(cls.path)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.path))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.td.cleanup()

    def _get(self, route):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{route}", timeout=5) as r:
            return r.status, r.read().decode("utf-8")

    def _post(self, route, obj):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{route}",
                                     data=json.dumps(obj).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def test_pages_and_static(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("AgentLedger", body)
        status, body = self._get("/logo.svg")
        self.assertEqual(status, 200)
        self.assertIn("<svg", body)

    def test_api_flow(self):
        status, stats = self._get("/api/stats")
        data = json.loads(stats)
        self.assertEqual(data["blocks"], 0)
        status, out = self._post("/api/log", {"agent": "gui-a", "tool": "bash", "params": {"cmd": "ls"}})
        self.assertEqual(status, 200)
        self.assertEqual(out["block_index"], 0)
        status, out = self._post("/api/log", {"agent": "gui-a", "tool": "bash", "params": {"cmd": "rm -rf /"}})
        self.assertEqual(status, 403)
        self.assertTrue(out["blocked"])
        status, out = self._post("/api/policy-check", {"tool": "bash", "params": {"cmd": "ls"}})
        self.assertEqual(out["status"], "PASS")
        status, body = self._get("/api/verify")
        self.assertTrue(json.loads(body)["chain_valid"])
        status, body = self._get("/api/blocks")
        self.assertEqual(json.loads(body)["total"], 2)


if __name__ == "__main__":
    unittest.main()
