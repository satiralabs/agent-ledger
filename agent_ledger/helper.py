"""
AgentLedger helper API — log a tool call in ~3 lines, with policy enforced.

Example:
    from agent_ledger.helper import LedgerSession
    session = LedgerSession("~/.agent-ledger/ledger.jsonl", agent_id="coder-01")
    block = session.log("bash", {"cmd": "git status"}, result={"ok": True})

Or as a context manager:
    with session.action("sql_query", {"query": "SELECT 1"}) as act:
        act["result"] = {"rows": 1}

Or one-shot:
    from agent_ledger.helper import record_action
    record_action(path, "coder-01", "read_file", {"path": "README.md"})
"""

from contextlib import contextmanager
from typing import Any, Dict, Optional

from .ledger import Ledger
from .attest import signer_for_ledger
from .policy import PolicyEngine


class PolicyBlocked(Exception):
    def __init__(self, status: str, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class LedgerSession:
    def __init__(self, ledger_path: str, agent_id: str, signer=None, policy: Optional[PolicyEngine] = None):
        self.ledger = Ledger(ledger_path)
        self.agent_id = agent_id
        self.signer = signer if signer is not None else signer_for_ledger(ledger_path)
        self.policy = policy or PolicyEngine()

    def _sign(self, payload: Dict[str, Any]) -> str:
        return self.signer.sign(payload) if self.signer is not None else ""

    def log(self, tool: str, params: Optional[Dict[str, Any]] = None, result: Any = None,
            action_type: str = "tool_call", approve: bool = False):
        params = params or {}
        allowed, status, reason = self.policy.check(tool, params)
        payload: Dict[str, Any] = {"tool": tool, "params": params}
        if result is not None:
            payload["result"] = result
        if not allowed and status == "BLOCKED":
            block_payload = {
                "tool": tool, "params": params,
                "policy_status": "BLOCKED", "reason": reason, "original_action": action_type,
            }
            self.ledger.append(self.agent_id, "policy_block", block_payload, signature=self._sign(block_payload))
            raise PolicyBlocked(status, reason)
        if not allowed and status == "APPROVAL_REQUIRED":
            if not approve:
                block_payload = {
                    "tool": tool, "params": params,
                    "policy_status": "APPROVAL_REQUIRED", "reason": reason, "original_action": action_type,
                }
                self.ledger.append(self.agent_id, "policy_block", block_payload, signature=self._sign(block_payload))
                raise PolicyBlocked(status, reason)
            # Approved: wrap, never silently mutate the caller's payload.
            payload = {"approved": True, "policy_status": "APPROVAL_REQUIRED", "data": payload}
        return self.ledger.append(self.agent_id, action_type, payload, signature=self._sign(payload))

    @contextmanager
    def action(self, tool: str, params: Optional[Dict[str, Any]] = None, approve: bool = False):
        holder: Dict[str, Any] = {}
        yield holder
        self.log(tool, params or {}, result=holder.get("result"), approve=approve)


def record_action(ledger_path: str, agent_id: str, tool: str, params: Optional[Dict[str, Any]] = None,
                  result: Any = None, approve: bool = False):
    """One-shot helper: open a session and log a single tool call."""
    return LedgerSession(ledger_path, agent_id).log(tool, params, result=result, approve=approve)
