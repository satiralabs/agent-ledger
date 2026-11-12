"""
Tests for AgentLedger: Hash chain integrity, tamper detection, and attestation.
"""

import json
import os
import tempfile
import unittest
from agent_ledger.ledger import Ledger, LedgerBlock, sha256_hash
from agent_ledger.attest import AttestationSigner
from agent_ledger.policy import PolicyEngine, PolicyRule


class TestAgentLedger(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ledger_path = os.path.join(self.temp_dir.name, "test_ledger.jsonl")
        self.ledger = Ledger(self.ledger_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_empty_ledger_is_valid(self):
        is_valid, err, count = self.ledger.verify()
        self.assertTrue(is_valid)
        self.assertIsNone(err)
        self.assertEqual(count, 0)

    def test_append_and_verify(self):
        b0 = self.ledger.append("agent-1", "init", {"status": "started"})
        self.assertEqual(b0.index, 0)
        self.assertEqual(b0.prev_hash, "0" * 64)

        b1 = self.ledger.append("agent-1", "tool_call", {"tool": "read_file", "path": "/etc/hosts"})
        self.assertEqual(b1.index, 1)
        self.assertEqual(b1.prev_hash, b0.block_hash)

        is_valid, err, count = self.ledger.verify()
        self.assertTrue(is_valid)
        self.assertEqual(count, 2)

    def test_tamper_detection(self):
        self.ledger.append("agent-1", "action1", {"amount": 100})
        self.ledger.append("agent-2", "action2", {"amount": 200})

        # Read file, tamper second block's amount, write back
        blocks = []
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                blocks.append(json.loads(line))

        # Modify payload without updating block_hash
        blocks[0]["payload"]["amount"] = 999999
        with open(self.ledger_path, "w", encoding="utf-8") as f:
            for b in blocks:
                f.write(json.dumps(b) + "\n")

        is_valid, err, count = self.ledger.verify()
        self.assertFalse(is_valid)
        self.assertIn("Hash tampering detected", err)

    def test_attestation_signing(self):
        signer = AttestationSigner(b"secret-key-123")
        payload = {"agent": "worker-1", "status": "done"}
        sig = signer.sign(payload)
        self.assertTrue(signer.verify(payload, sig))
        self.assertFalse(signer.verify({"agent": "worker-1", "status": "tampered"}, sig))

    def test_policy_engine(self):
        policy = PolicyEngine(PolicyRule("strict-guard", blocked_tools=["eval_python"]))
        ok, status, _ = policy.check("read_file", {"path": "safe.txt"})
        self.assertTrue(ok)
        self.assertEqual(status, "PASS")

        ok2, status2, _ = policy.check("eval_python", {"code": "print(1)"})
        self.assertFalse(ok2)
        self.assertEqual(status2, "BLOCKED")

        ok3, status3, _ = policy.check("bash", {"cmd": "rm -rf /tmp"})
        self.assertFalse(ok3)
        self.assertEqual(status3, "BLOCKED")


if __name__ == "__main__":
    unittest.main()
