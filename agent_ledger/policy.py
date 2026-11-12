"""
AgentLedger Policy Guard: Zero-Trust Governance and Action Risk Evaluation.
Enforces limits, checks dangerous parameters, and raises micro-escrow challenges.
"""

from typing import Any, Dict, List, Optional, Tuple


class PolicyRule:
    def __init__(
        self,
        name: str,
        blocked_tools: Optional[List[str]] = None,
        max_cost_usd: float = 5.0,
        require_approval_for: Optional[List[str]] = None,
        prohibited_params: Optional[List[str]] = None,
    ):
        self.name = name
        self.blocked_tools = set(blocked_tools or [])
        self.max_cost_usd = max_cost_usd
        self.require_approval_for = set(require_approval_for or ["rm", "delete", "transfer", "sudo"])
        self.prohibited_params = prohibited_params or ["rm -rf", "DROP TABLE", "DELETE FROM", "--no-preserve-root"]

    def evaluate(self, tool_name: str, params: Dict[str, Any]) -> Tuple[bool, str, str]:
        """
        Evaluate tool execution against policy.
        Returns: (allowed, status, reason)
        status: "PASS", "BLOCKED", "APPROVAL_REQUIRED"
        """
        # 1. Blocked tools check
        if tool_name in self.blocked_tools:
            return False, "BLOCKED", f"Tool '{tool_name}' is explicitly forbidden by policy '{self.name}'"

        # 2. Dangerous string pattern check
        param_str = str(params)
        for pattern in self.prohibited_params:
            if pattern in param_str:
                return False, "BLOCKED", f"Prohibited dangerous pattern '{pattern}' detected in parameters"

        # 3. High-risk approval gate
        for trigger in self.require_approval_for:
            if trigger in tool_name.lower():
                return False, "APPROVAL_REQUIRED", f"Tool '{tool_name}' touches sensitive domain ({trigger}); human approval required"

        return True, "PASS", "Action authorized under policy"


class PolicyEngine:
    def __init__(self, default_policy: Optional[PolicyRule] = None):
        self.policy = default_policy or PolicyRule("default-zero-trust")

    def check(self, tool_name: str, params: Dict[str, Any]) -> Tuple[bool, str, str]:
        return self.policy.evaluate(tool_name, params)
