"""
AgentLedger Attestation Engine: HMAC and signature verification for autonomous agents.
Generates cryptographic receipts proving prompt, model, parameters, and output.
"""

import hmac
import hashlib
import json
import os
from typing import Any, Dict, Optional
from .ledger import canonical_json, sha256_hash


class AttestationSigner:
    """Signs and verifies agent action receipts using HMAC-SHA256."""

    def __init__(self, secret_key: Optional[bytes] = None):
        if secret_key is None:
            # Check environment or default to local host token
            env_key = os.environ.get("AGENT_LEDGER_KEY")
            if env_key:
                self.secret_key = env_key.encode("utf-8")
            else:
                self.secret_key = b"agent-ledger-default-local-audit-key"
        else:
            self.secret_key = secret_key

    def sign(self, payload: Dict[str, Any]) -> str:
        """Sign canonical payload representation."""
        message = canonical_json(payload).encode("utf-8")
        return hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()

    def verify(self, payload: Dict[str, Any], signature: str) -> bool:
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature)

    def generate_receipt(
        self,
        agent_id: str,
        action: str,
        prompt: str,
        model: str,
        tool_name: str,
        tool_params: Dict[str, Any],
        tool_result: Any,
        block_hash: str = "",
    ) -> Dict[str, Any]:
        """Generate a complete cryptographic audit receipt."""
        prompt_digest = sha256_hash(prompt)
        params_digest = sha256_hash(canonical_json(tool_params))
        result_digest = sha256_hash(canonical_json(tool_result))

        receipt_data = {
            "agent_id": agent_id,
            "action": action,
            "model": model,
            "prompt_sha256": prompt_digest,
            "tool_name": tool_name,
            "tool_params_sha256": params_digest,
            "tool_result_sha256": result_digest,
            "parent_block_hash": block_hash,
        }

        signature = self.sign(receipt_data)
        receipt_data["signature"] = signature
        receipt_data["receipt_id"] = sha256_hash(signature)[:16]
        return receipt_data
