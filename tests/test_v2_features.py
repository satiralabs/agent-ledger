"""v2 feature tests: Merkle root/proofs, receipt --append, audit filters, export, helper API."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_ledger.ledger import Ledger, merkle_root, verify_merkle_proof
from agent_ledger.attest import generate_key_file
from agent_ledger.helper import LedgerSession, PolicyBlocked, record_action

BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "agent-ledger")


def run_cli(args):
    env = dict(os.environ)
    env.pop("AGENT_LEDGER_KEY", None)
    return subprocess.run([sys.executable, BIN] + args, capture_output=True, text=True, env=env)


class TestMerkle(unittest.TestCase):
    def _ledger(self, td, n=7):
        path = os.path.join(td, "l.jsonl")
        led = Ledger(path)
        for i in range(n):
            led.append("a", "tool_call", {"i": i})
        return led

    def test_empty_and_single(self):
        self.assertEqual(merkle_root([]), "")
        with tempfile.TemporaryDirectory() as td:
            led = self._ledger(td, 1)
            self.assertEqual(led.merkle_root(), led.all_blocks()[0].block_hash)
            data = led.merkle_proof(0)
            self.assertEqual(data["proof"], [])
            self.assertTrue(verify_merkle_proof(data["block_hash"], data["proof"], data["root"]))

    def test_proofs_verify_for_all_indices(self):
        with tempfile.TemporaryDirectory() as td:
            led = self._ledger(td, 7)
            root = led.merkle_root()
            self.assertTrue(root)
            for i in range(7):
                data = led.merkle_proof(i)
                self.assertTrue(verify_merkle_proof(data["block_hash"], data["proof"], root), i)

    def test_tampered_leaf_and_wrong_root_fail(self):
        with tempfile.TemporaryDirectory() as td:
            led = self._ledger(td, 5)
            data = led.merkle_proof(2)
            self.assertFalse(verify_merkle_proof("0" * 64, data["proof"], data["root"]))
            self.assertFalse(verify_merkle_proof(data["block_hash"], data["proof"], "f" * 64))

    def test_prove_cli_self_check(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "l.jsonl")
            run_cli(["--path", path, "init"])
            run_cli(["log", "--path", path, "--agent", "a", "--action", "tool_call", "--payload", '{"tool":"bash","cmd":"ls"}'])
            r = run_cli(["--path", path, "prove", "--block", "0", "--verify"])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("PROOF VERIFIED", r.stdout)


class TestReceiptAppend(unittest.TestCase):
    def test_append_links_to_head_and_default_does_not(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "l.jsonl")
            run_cli(["--path", path, "init"])
            run_cli(["log", "--path", path, "--agent", "a", "--action", "tool_call", "--payload", '{"tool":"bash","cmd":"ls"}'])
            head = Ledger(path).get_last_block().block_hash
            base = ["receipt", "--path", path, "--agent", "r", "--prompt", "p", "--tool", "sql_query"]
            r = run_cli(base)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(len(Ledger(path).all_blocks()), 1)  # print-only by default
            r2 = run_cli(base + ["--append"])
            self.assertEqual(r2.returncode, 0, r2.stderr)
            blocks = Ledger(path).all_blocks()
            self.assertEqual(len(blocks), 2)
            self.assertEqual(blocks[-1].action_type, "receipt")
            self.assertEqual(blocks[-1].payload["receipt"]["parent_block_hash"], head)


class TestAuditAndExport(unittest.TestCase):
    def _seed(self, td):
        path = os.path.join(td, "l.jsonl")
        run_cli(["--path", path, "init"])
        run_cli(["log", "--path", path, "--agent", "alice", "--action", "tool_call", "--payload", '{"tool":"bash","cmd":"ls"}'])
        run_cli(["log", "--path", path, "--agent", "bob", "--action", "tool_call", "--payload", '{"tool":"read_file","path":"x"}'])
        return path

    def test_audit_agent_filter(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._seed(td)
            r = run_cli(["audit", "--path", path, "--agent", "alice"])
            self.assertIn("1 Blocks", r.stdout)
            self.assertIn("alice", r.stdout)
            self.assertNotIn("bob", r.stdout)

    def test_export_bundle_contents(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._seed(td)
            out = os.path.join(td, "bundle")
            r = run_cli(["export", "--path", path, "--out", out, "--zip"])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            for name in ("ledger.jsonl", "receipts.json", "merkle_root.txt", "report.md", "manifest.json"):
                self.assertTrue(os.path.isfile(os.path.join(out, name)), name)
            with open(os.path.join(out, "report.md")) as f:
                self.assertIn("How to verify", f.read())
            self.assertTrue(zipfile.is_zipfile(out + ".zip"))


class TestHelper(unittest.TestCase):
    def test_session_log_and_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "l.jsonl")
            Ledger(path)
            generate_key_file(path)
            s = LedgerSession(path, "helper-agent")
            block = s.log("bash", {"cmd": "git status"}, result={"ok": True})
            self.assertEqual(block.index, 0)
            with self.assertRaises(PolicyBlocked):
                s.log("bash", {"cmd": "rm -rf /"})
            blocks = Ledger(path).all_blocks()
            self.assertEqual(blocks[-1].action_type, "policy_block")
            ok, _, _ = Ledger(path).verify()
            self.assertTrue(ok)

    def test_record_action_and_context_manager(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "l.jsonl")
            Ledger(path)
            generate_key_file(path)
            record_action(path, "one-shot", "read_file", {"path": "README.md"})
            s = LedgerSession(path, "ctx-agent")
            with s.action("web_search", {"query": "merkle trees"}) as act:
                act["result"] = {"hits": 3}
            blocks = Ledger(path).all_blocks()
            self.assertEqual(len(blocks), 2)
            self.assertEqual(blocks[-1].payload["result"], {"hits": 3})


if __name__ == "__main__":
    unittest.main()
