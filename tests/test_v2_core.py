"""v2 core-fix tests: keys, policy-in-CLI, signatures, --path, locking, policy hardening."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_ledger.ledger import Ledger
from agent_ledger.attest import AttestationSigner, generate_key_file, key_path_for_ledger, signer_for_ledger
from agent_ledger.policy import PolicyEngine

BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "agent-ledger")


def run_cli(args, ledger_path=None):
    env = dict(os.environ)
    env.pop("AGENT_LEDGER_KEY", None)
    return subprocess.run([sys.executable, BIN] + args, capture_output=True, text=True, env=env)


class TestKeys(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.td.name, "ledger.jsonl")
        self._env = os.environ.pop("AGENT_LEDGER_KEY", None)

    def tearDown(self):
        if self._env is not None:
            os.environ["AGENT_LEDGER_KEY"] = self._env
        self.td.cleanup()

    def test_no_default_key_raises(self):
        with self.assertRaises(ValueError):
            AttestationSigner()

    def test_key_file_generated_0600_and_loads(self):
        Ledger(self.path)
        kpath = generate_key_file(self.path)
        self.assertEqual(kpath, key_path_for_ledger(self.path))
        mode = stat.S_IMODE(os.stat(kpath).st_mode)
        self.assertEqual(mode, 0o600)
        signer = signer_for_ledger(self.path, required=True)
        sig = signer.sign({"a": 1})
        self.assertTrue(signer.verify({"a": 1}, sig))
        # generating again must not rotate the key
        generate_key_file(self.path)
        signer2 = signer_for_ledger(self.path, required=True)
        self.assertTrue(signer2.verify({"a": 1}, sig))

    def test_env_key_takes_precedence(self):
        os.environ["AGENT_LEDGER_KEY"] = "env-secret"
        try:
            signer = AttestationSigner()
            self.assertTrue(signer.verify({"x": 2}, signer.sign({"x": 2})))
        finally:
            os.environ.pop("AGENT_LEDGER_KEY", None)


class TestSignatureVerify(unittest.TestCase):
    def test_wrong_key_signatures_fail_but_chain_holds(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "l.jsonl")
            ledger = Ledger(path)
            good = AttestationSigner(b"good-key")
            bad = AttestationSigner(b"bad-key")
            p1 = {"tool": "read_file"}
            ledger.append("a", "tool_call", p1, signature=good.sign(p1))
            p2 = {"tool": "write_file"}
            ledger.append("a", "tool_call", p2, signature=bad.sign(p2))  # signed with wrong key
            detail = ledger.verify_detailed(signer=good)
            self.assertTrue(detail["chain_valid"])
            self.assertEqual(detail["signatures_checked"], 2)
            self.assertFalse(detail["signatures_valid"])
            ok, err, n = ledger.verify()  # original contract still chain-only
            self.assertTrue(ok)
            self.assertEqual(n, 2)


class TestPolicyHardening(unittest.TestCase):
    def setUp(self):
        self.e = PolicyEngine()

    def test_case_and_whitespace_variants_blocked(self):
        for cmd in ("rm -rf /", "RM  -RF /tmp", "Rm -Rf .", "rm\t-rf /"):
            ok, status, _ = self.e.check("bash", {"cmd": cmd})
            self.assertEqual(status, "BLOCKED", cmd)

    def test_approval_scans_params_by_token(self):
        ok, status, _ = self.e.check("bank", {"op": "transfer 100"})
        self.assertEqual(status, "APPROVAL_REQUIRED")

    def test_innocent_substring_not_flagged(self):
        ok, status, _ = self.e.check("web_search", {"query": "hmac receipt format"})
        self.assertEqual(status, "PASS")

    def test_cost_ceiling_needs_approval(self):
        ok, status, _ = self.e.check("api_call", {"cost_usd": 42})
        self.assertEqual(status, "APPROVAL_REQUIRED")
        ok, status, _ = self.e.check("api_call", {"cost_usd": 1})
        self.assertEqual(status, "PASS")


class TestCliPolicy(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.td.name, "ledger.jsonl")
        r = run_cli(["--path", self.path, "init"])
        self.assertEqual(r.returncode, 0, r.stderr)

    def tearDown(self):
        self.td.cleanup()

    def test_blocked_refused_logged_and_exit3(self):
        r = run_cli(["log", "--path", self.path, "--agent", "ops", "--action", "tool_call",
                     "--payload", '{"tool": "bash", "cmd": "rm -rf /"}'])
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        blocks = Ledger(self.path).all_blocks()
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].action_type, "policy_block")
        ok, _, n = Ledger(self.path).verify()
        self.assertTrue(ok)

    def test_approval_flow_and_wrapper(self):
        args = ["log", "--path", self.path, "--agent", "ops", "--action", "tool_call",
                "--payload", '{"tool": "bank", "op": "transfer 50"}']
        r = run_cli(args)
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        r2 = run_cli(args + ["--approve"])
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        blocks = Ledger(self.path).all_blocks()
        last = blocks[-1]
        self.assertTrue(last.payload.get("approved"))
        self.assertEqual(last.payload.get("data", {}).get("op"), "transfer 50")

    def test_path_after_subcommand(self):
        r = run_cli(["verify", "--path", self.path])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("VERIFIED", r.stdout)


class TestConcurrentAppend(unittest.TestCase):
    def test_threads_produce_one_valid_chain(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "l.jsonl")
            Ledger(path)

            def worker(n):
                led = Ledger(path)
                for i in range(10):
                    led.append(f"agent-{n}", "tool_call", {"n": n, "i": i})

            with ThreadPoolExecutor(max_workers=4) as ex:
                list(ex.map(worker, range(4)))
            ok, err, count = Ledger(path).verify()
            self.assertTrue(ok, err)
            self.assertEqual(count, 40)


if __name__ == "__main__":
    unittest.main()
