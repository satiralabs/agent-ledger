"""
AgentLedger Policy Guard: Zero-Trust Governance and Action Risk Evaluation.

v2 hardening:
- Matching is normalised: case-insensitive, whitespace collapsed, unicode
  normalised — "RM  -RF", "rm -rf" and "Rm -Rf" are the same pattern.
- Approval triggers are scanned in BOTH the tool name and the parameters
  (v1 only scanned the tool name).
- max_cost_usd is ENFORCED: if params carry a numeric cost field
  (cost_usd / cost / amount_usd / price_usd) above the limit, the action
  returns APPROVAL_REQUIRED instead of passing silently.
"""

import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

_COST_FIELDS = ("cost_usd", "cost", "amount_usd", "price_usd", "usd")


def _normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", str(text))
    text = text.replace("​", "").replace("﻿", "")
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def _params_text(params: Any) -> str:
    try:
        import json
        raw = json.dumps(params, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:
        raw = str(params)
    return _normalise(raw + " " + str(params))


def _find_cost(params: Any) -> Optional[float]:
    if isinstance(params, dict):
        for key, value in params.items():
            if _normalise(str(key)) in _COST_FIELDS:
                try:
                    return float(value)
                except (TypeError, ValueError):
                    continue
            found = _find_cost(value)
            if found is not None:
                return found
    elif isinstance(params, (list, tuple)):
        for item in params:
            found = _find_cost(item)
            if found is not None:
                return found
    return None


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
        self.blocked_tools = set(_normalise(t) for t in (blocked_tools or []))
        self.max_cost_usd = max_cost_usd
        self.require_approval_for = list(require_approval_for or ["rm", "delete", "transfer", "sudo"])
        self.prohibited_params = list(prohibited_params or ["rm -rf", "DROP TABLE", "DELETE FROM", "--no-preserve-root"])

    def evaluate(self, tool_name: str, params: Dict[str, Any]) -> Tuple[bool, str, str]:
        """
        Returns: (allowed, status, reason)
        status: "PASS", "BLOCKED", "APPROVAL_REQUIRED"
        """
        tool_n = _normalise(tool_name)
        param_text = _params_text(params)

        # 1. Blocked tools check (normalised)
        if tool_n in self.blocked_tools:
            return False, "BLOCKED", f"Tool '{tool_name}' is explicitly forbidden by policy '{self.name}'"

        # 2. Dangerous pattern check over tool name + params (normalised)
        haystack = tool_n + " " + param_text
        for pattern in self.prohibited_params:
            if _normalise(pattern) in haystack:
                return False, "BLOCKED", f"Prohibited dangerous pattern '{pattern}' detected in parameters"

        # 3. Cost ceiling: a cost above max_cost_usd needs human approval
        cost = _find_cost(params)
        if cost is not None and self.max_cost_usd is not None and cost > self.max_cost_usd:
            return False, "APPROVAL_REQUIRED", (
                f"Cost ${cost:.2f} exceeds policy limit ${self.max_cost_usd:.2f}; human approval required"
            )

        # 4. High-risk approval gate — tool name AND params.
        # Params use whole-token matching: a plain substring scan flags
        # innocent words ("format" contains "rm"), which the seed demo
        # proved in practice. The tool name keeps substring matching
        # ("sudo_bash" should trip "sudo").
        param_tokens = set(re.findall(r"[a-z0-9]+", param_text))
        for trigger in self.require_approval_for:
            trig_n = _normalise(trigger)
            if not trig_n:
                continue
            if trig_n in tool_n:
                return False, "APPROVAL_REQUIRED", (
                    f"Action touches sensitive domain ({trigger}) in tool name; human approval required"
                )
            trig_tokens = re.findall(r"[a-z0-9]+", trig_n)
            if len(trig_tokens) == 1 and trig_tokens[0] in param_tokens:
                return False, "APPROVAL_REQUIRED", (
                    f"Action touches sensitive domain ({trigger}) in parameters; human approval required"
                )
            if len(trig_tokens) > 1 and trig_n in param_text:
                return False, "APPROVAL_REQUIRED", (
                    f"Action touches sensitive domain ({trigger}) in parameters; human approval required"
                )

        return True, "PASS", "Action authorized under policy"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "blocked_tools": sorted(self.blocked_tools),
            "max_cost_usd": self.max_cost_usd,
            "require_approval_for": list(self.require_approval_for),
            "prohibited_params": list(self.prohibited_params),
        }


class PolicyEngine:
    def __init__(self, default_policy: Optional[PolicyRule] = None):
        self.policy = default_policy or PolicyRule("default-zero-trust")

    def check(self, tool_name: str, params: Dict[str, Any]) -> Tuple[bool, str, str]:
        return self.policy.evaluate(tool_name, params)
