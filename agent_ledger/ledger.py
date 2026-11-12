"""
AgentLedger Core: Merkle Hash Chain and Append-Only Audit Trail.
Zero-dependency, tamper-evident cryptographic logging for AI agent actions.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple


def canonical_json(obj: Any) -> str:
    """Produce deterministic, sort-keyed JSON string without whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hash(data: str) -> str:
    """Calculate SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class MerkleNode:
    def __init__(self, left: Optional["MerkleNode"], right: Optional["MerkleNode"], value: str):
        self.left = left
        self.right = right
        self.value = value


class MerkleTree:
    """In-memory Merkle Tree for batch attestation verification."""

    def __init__(self, leaf_hashes: List[str]):
        if not leaf_hashes:
            self.root: Optional[MerkleNode] = None
            return

        leaves = [MerkleNode(None, None, h) for h in leaf_hashes]
        self.root = self._build_tree(leaves)

    def _build_tree(self, nodes: List[MerkleNode]) -> MerkleNode:
        if len(nodes) == 1:
            return nodes[0]

        next_level: List[MerkleNode] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            if i + 1 < len(nodes):
                right = nodes[i + 1]
                combined = sha256_hash(left.value + right.value)
                next_level.append(MerkleNode(left, right, combined))
            else:
                next_level.append(left)

        return self._build_tree(next_level)

    @property
    def root_hash(self) -> str:
        return self.root.value if self.root else ""


class LedgerBlock:
    """A single verifiable block in the AgentLedger chain."""

    def __init__(
        self,
        index: int,
        timestamp: float,
        agent_id: str,
        action_type: str,
        payload: Dict[str, Any],
        prev_hash: str,
        signature: str = "",
        block_hash: str = "",
    ):
        self.index = index
        self.timestamp = timestamp
        self.agent_id = agent_id
        self.action_type = action_type  # e.g. "prompt", "tool_call", "handover", "decision"
        self.payload = payload
        self.prev_hash = prev_hash
        self.signature = signature
        self.block_hash = block_hash or self.compute_hash()

    def payload_hash(self) -> str:
        return sha256_hash(canonical_json(self.payload))

    def compute_hash(self) -> str:
        fields = {
            "index": self.index,
            "timestamp": round(self.timestamp, 4),
            "agent_id": self.agent_id,
            "action_type": self.action_type,
            "payload_hash": self.payload_hash(),
            "prev_hash": self.prev_hash,
            "signature": self.signature,
        }
        return sha256_hash(canonical_json(fields))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "action_type": self.action_type,
            "payload": self.payload,
            "payload_hash": self.payload_hash(),
            "prev_hash": self.prev_hash,
            "signature": self.signature,
            "block_hash": self.block_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LedgerBlock":
        return cls(
            index=data["index"],
            timestamp=data["timestamp"],
            agent_id=data["agent_id"],
            action_type=data["action_type"],
            payload=data["payload"],
            prev_hash=data["prev_hash"],
            signature=data.get("signature", ""),
            block_hash=data.get("block_hash", ""),
        )


class Ledger:
    """Persistent append-only verifiable cryptographic ledger."""

    GENESIS_PREV_HASH = "0" * 64

    def __init__(self, ledger_path: str):
        self.ledger_path = os.path.abspath(ledger_path)
        os.makedirs(os.path.dirname(self.ledger_path), exist_ok=True)
        if not os.path.exists(self.ledger_path):
            with open(self.ledger_path, "w", encoding="utf-8") as f:
                pass  # create empty file

    def get_last_block(self) -> Optional[LedgerBlock]:
        if not os.path.exists(self.ledger_path) or os.path.getsize(self.ledger_path) == 0:
            return None

        last_line = ""
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if not last_line:
            return None
        return LedgerBlock.from_dict(json.loads(last_line))

    def append(
        self,
        agent_id: str,
        action_type: str,
        payload: Dict[str, Any],
        signature: str = "",
    ) -> LedgerBlock:
        last = self.get_last_block()
        if last is None:
            index = 0
            prev_hash = self.GENESIS_PREV_HASH
        else:
            index = last.index + 1
            prev_hash = last.block_hash

        block = LedgerBlock(
            index=index,
            timestamp=time.time(),
            agent_id=agent_id,
            action_type=action_type,
            payload=payload,
            prev_hash=prev_hash,
            signature=signature,
        )

        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(canonical_json(block.to_dict()) + "\n")

        return block

    def verify(self) -> Tuple[bool, Optional[str], int]:
        """
        Verify cryptographic integrity of the entire ledger.
        Returns: (is_valid, error_message, block_count)
        """
        if not os.path.exists(self.ledger_path) or os.path.getsize(self.ledger_path) == 0:
            return True, None, 0

        expected_prev = self.GENESIS_PREV_HASH
        expected_index = 0

        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    block = LedgerBlock.from_dict(data)
                except Exception as e:
                    return False, f"Malformed JSON on line {line_no}: {e}", line_no - 1

                if block.index != expected_index:
                    return (
                        False,
                        f"Index mismatch at block {block.index}: expected {expected_index}",
                        expected_index,
                    )

                if block.prev_hash != expected_prev:
                    return (
                        False,
                        f"Broken chain link at block {block.index}: expected prev_hash {expected_prev}, got {block.prev_hash}",
                        expected_index,
                    )

                recomputed = block.compute_hash()
                if block.block_hash != recomputed:
                    return (
                        False,
                        f"Hash tampering detected at block {block.index}: stored {block.block_hash}, computed {recomputed}",
                        expected_index,
                    )

                expected_prev = block.block_hash
                expected_index += 1

        return True, None, expected_index

    def all_blocks(self) -> List[LedgerBlock]:
        blocks = []
        if not os.path.exists(self.ledger_path):
            return blocks
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    blocks.append(LedgerBlock.from_dict(json.loads(line)))
        return blocks
