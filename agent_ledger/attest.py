"""
AgentLedger Attestation Engine: HMAC and signature verification for autonomous agents.
Generates cryptographic receipts proving prompt, model, parameters, and output.

v2: the hardcoded fallback key from v1 is REMOVED. Key resolution order:
  1. explicit secret_key argument (tests / embedding)
  2. AGENT_LEDGER_KEY environment variable
  3. explicit key_file argument
  4. per-ledger key file "<ledger>.key" beside the ledger (created by `init`)
If none is available, construction raises ValueError — AgentLedger never
silently signs with a publicly known key.
"""

import hmac
import hashlib
import os
import secrets
import stat
from typing import Any, Dict, Optional
from .ledger import canonical_json, sha256_hash


def key_path_for_ledger(ledger_path: str) -> str:
    """Per-ledger key file lives beside the ledger: <ledger>.key"""
    return os.path.abspath(ledger_path) + ".key"


def generate_key_file(ledger_path: str) -> str:
    """Create a random per-ledger key file (0600) if one does not exist. Returns its path."""
    kpath = key_path_for_ledger(ledger_path)
    if os.path.exists(kpath):
        return kpath
    parent = os.path.dirname(kpath)
    if parent:
        os.makedirs(parent, exist_ok=True)
    key_hex = secrets.token_hex(32)
    # O_EXCL avoids clobbering a key created by a concurrent init.
    fd = os.open(kpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (key_hex + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(kpath, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return kpath


def _read_key_file(kpath: str) -> Optional[bytes]:
    try:
        with open(kpath, "r", encoding="utf-8") as f:
            value = f.read().strip()
        return value.encode("utf-8") if value else None
    except OSError:
        return None


def signer_for_ledger(ledger_path: Optional[str] = None, required: bool = False):
    """
    Best-effort signer for a ledger: env key first, then the per-ledger
    key file. Returns an AttestationSigner or None (raises if required).
    """
    env_key = os.environ.get("AGENT_LEDGER_KEY")
    if env_key:
        return AttestationSigner(env_key.encode("utf-8"))
    if ledger_path:
        kpath = key_path_for_ledger(ledger_path)
        if os.path.exists(kpath):
            data = _read_key_file(kpath)
            if data:
                return AttestationSigner(data)
    if required:
        raise ValueError(
            "No AgentLedger signing key available: set AGENT_LEDGER_KEY or run "
            "`agent-ledger init` to create a per-ledger key file."
        )
    return None


class AttestationSigner:
    """Signs and verifies agent action receipts using HMAC-SHA256."""

    def __init__(self, secret_key: Optional[bytes] = None, key_file: Optional[str] = None,
                 ledger_path: Optional[str] = None):
        if secret_key is not None:
            self.secret_key = secret_key if isinstance(secret_key, bytes) else str(secret_key).encode("utf-8")
            return
        env_key = os.environ.get("AGENT_LEDGER_KEY")
        if env_key:
            self.secret_key = env_key.encode("utf-8")
            return
        candidate = key_file
        if candidate is None and ledger_path is not None:
            candidate = key_path_for_ledger(ledger_path)
        if candidate and os.path.exists(candidate):
            data = _read_key_file(candidate)
            if data:
                self.secret_key = data
                return
        raise ValueError(
            "No signing key available. Pass secret_key explicitly, set the "
            "AGENT_LEDGER_KEY environment variable, or run `agent-ledger init` "
            "to generate a per-ledger key file (<ledger>.key). AgentLedger v2 "
            "never signs with a built-in default key."
        )

    def sign(self, payload: Dict[str, Any]) -> str:
        message = canonical_json(payload).encode("utf-8")
        return hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()

    def verify(self, payload: Dict[str, Any], signature: str) -> bool:
        if not signature:
            return False
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature)

    def generate_receipt(self, agent_id: str, action: str, prompt: str, model: str,
                         tool_name: str, tool_params: Dict[str, Any], tool_result: Any,
                         block_hash: str = "") -> Dict[str, Any]:
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
