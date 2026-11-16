"""
AgentLedger Core: Merkle Hash Chain and Append-Only Audit Trail.
Zero-dependency, tamper-evident cryptographic logging for AI agent actions.

v2 changes:
- append() no longer scans the whole file: the last line is read by seeking
  from the end of the file.
- append() holds an exclusive file lock (fcntl on POSIX, graceful no-op
  fallback elsewhere) so concurrent agents cannot interleave writes.
- Real Merkle root + inclusion proofs over block hashes (MerkleTree was
  previously dead code).
- verify_detailed() optionally verifies block HMAC signatures and reports
  chain validity and signature results separately. verify() keeps its
  original (bool, error, count) contract for backwards compatibility.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None  # type: ignore


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _merkle_levels(leaf_hashes: List[str]) -> List[List[str]]:
    if not leaf_hashes:
        return []
    levels = [list(leaf_hashes)]
    current = list(leaf_hashes)
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            left = current[i]
            if i + 1 < len(current):
                nxt.append(sha256_hash(left + current[i + 1]))
            else:
                nxt.append(left)
        levels.append(nxt)
        current = nxt
    return levels


def merkle_root(leaf_hashes: List[str]) -> str:
    if not leaf_hashes:
        return ""
    return _merkle_levels(leaf_hashes)[-1][0]


def merkle_proof(leaf_hashes: List[str], index: int) -> List[Dict[str, str]]:
    if index < 0 or index >= len(leaf_hashes):
        raise IndexError("leaf index out of range")
    levels = _merkle_levels(leaf_hashes)
    proof: List[Dict[str, str]] = []
    idx = index
    for level in levels[:-1]:
        if idx % 2 == 1:
            proof.append({"hash": level[idx - 1], "position": "left"})
        elif idx + 1 < len(level):
            proof.append({"hash": level[idx + 1], "position": "right"})
        idx //= 2
    return proof


def verify_merkle_proof(leaf_hash: str, proof: List[Dict[str, str]], root: str) -> bool:
    current = leaf_hash
    for step in proof:
        sibling = step.get("hash", "")
        if step.get("position") == "left":
            current = sha256_hash(sibling + current)
        elif step.get("position") == "right":
            current = sha256_hash(current + sibling)
        else:
            return False
    return current == root


class MerkleNode:
    def __init__(self, left: Optional["MerkleNode"], right: Optional["MerkleNode"], value: str):
        self.left = left
        self.right = right
        self.value = value


class MerkleTree:
    """In-memory Merkle Tree for batch attestation verification."""

    def __init__(self, leaf_hashes: List[str]):
        self._leaf_hashes = list(leaf_hashes)
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

    def proof(self, index: int) -> List[Dict[str, str]]:
        return merkle_proof(self._leaf_hashes, index)

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Dict[str, str]], root: str) -> bool:
        return verify_merkle_proof(leaf_hash, proof, root)


class LedgerBlock:
    """A single verifiable block in the AgentLedger chain."""

    def __init__(self, index: int, timestamp: float, agent_id: str, action_type: str,
                 payload: Dict[str, Any], prev_hash: str, signature: str = "", block_hash: str = ""):
        self.index = index
        self.timestamp = timestamp
        self.agent_id = agent_id
        self.action_type = action_type
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
            index=data["index"], timestamp=data["timestamp"], agent_id=data["agent_id"],
            action_type=data["action_type"], payload=data["payload"], prev_hash=data["prev_hash"],
            signature=data.get("signature", ""), block_hash=data.get("block_hash", ""),
        )


def _read_last_line(path: str) -> str:
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        if pos == 0:
            return ""
        buffer = b""
        chunk = 8192
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            f.seek(pos)
            buffer = f.read(step) + buffer
            stripped = buffer.rstrip(b"\n")
            idx = stripped.rfind(b"\n")
            if idx != -1:
                return stripped[idx + 1:].decode("utf-8", errors="replace")
            if pos == 0:
                return stripped.decode("utf-8", errors="replace")
    return ""


class Ledger:
    """Persistent append-only verifiable cryptographic ledger."""

    GENESIS_PREV_HASH = "0" * 64

    def __init__(self, ledger_path: str):
        self.ledger_path = os.path.abspath(ledger_path)
        parent = os.path.dirname(self.ledger_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        if not os.path.exists(self.ledger_path):
            with open(self.ledger_path, "w", encoding="utf-8") as f:
                pass

    def get_last_block(self) -> Optional[LedgerBlock]:
        if not os.path.exists(self.ledger_path) or os.path.getsize(self.ledger_path) == 0:
            return None
        last_line = _read_last_line(self.ledger_path)
        if not last_line.strip():
            return None
        return LedgerBlock.from_dict(json.loads(last_line))

    def append(self, agent_id: str, action_type: str, payload: Dict[str, Any], signature: str = "") -> LedgerBlock:
        with open(self.ledger_path, "a+", encoding="utf-8") as f:
            locked = False
            if fcntl is not None:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    locked = True
                except OSError:
                    locked = False
            try:
                last = self.get_last_block()
                if last is None:
                    index = 0
                    prev_hash = self.GENESIS_PREV_HASH
                else:
                    index = last.index + 1
                    prev_hash = last.block_hash
                block = LedgerBlock(index=index, timestamp=time.time(), agent_id=agent_id,
                                    action_type=action_type, payload=payload, prev_hash=prev_hash,
                                    signature=signature)
                f.seek(0, os.SEEK_END)
                f.write(canonical_json(block.to_dict()) + "\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
                return block
            finally:
                if locked and fcntl is not None:
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        pass

    def verify(self) -> Tuple[bool, Optional[str], int]:
        detail = self.verify_detailed()
        return detail["chain_valid"], detail["error"], detail["count"]

    def verify_detailed(self, signer=None) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "chain_valid": True, "error": None, "count": 0,
            "signatures_checked": 0, "signatures_valid": None,
            "signature_error": None, "unsigned_count": 0,
        }
        if not os.path.exists(self.ledger_path) or os.path.getsize(self.ledger_path) == 0:
            if signer is not None:
                result["signatures_valid"] = True
            return result
        expected_prev = self.GENESIS_PREV_HASH
        expected_index = 0
        sig_failures = []
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    block = LedgerBlock.from_dict(data)
                except Exception as e:
                    result["chain_valid"] = False
                    result["error"] = f"Malformed JSON on line {line_no}: {e}"
                    result["count"] = line_no - 1
                    return result
                if block.index != expected_index:
                    result["chain_valid"] = False
                    result["error"] = f"Index mismatch at block {block.index}: expected {expected_index}"
                    result["count"] = expected_index
                    return result
                if block.prev_hash != expected_prev:
                    result["chain_valid"] = False
                    result["error"] = f"Broken chain link at block {block.index}: expected prev_hash {expected_prev}, got {block.prev_hash}"
                    result["count"] = expected_index
                    return result
                recomputed = block.compute_hash()
                if block.block_hash != recomputed:
                    result["chain_valid"] = False
                    result["error"] = f"Hash tampering detected at block {block.index}: stored {block.block_hash}, computed {recomputed}"
                    result["count"] = expected_index
                    return result
                if signer is not None:
                    if block.signature:
                        result["signatures_checked"] += 1
                        if not signer.verify(block.payload, block.signature):
                            sig_failures.append(block.index)
                    else:
                        result["unsigned_count"] += 1
                expected_prev = block.block_hash
                expected_index += 1
        result["count"] = expected_index
        if signer is not None:
            if sig_failures:
                result["signatures_valid"] = False
                result["signature_error"] = f"Signature verification failed at block(s): {sig_failures}"
            else:
                result["signatures_valid"] = True
        return result

    def all_blocks(self) -> List[LedgerBlock]:
        blocks = []
        if not os.path.exists(self.ledger_path):
            return blocks
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    blocks.append(LedgerBlock.from_dict(json.loads(line)))
        return blocks

    def block_hashes(self) -> List[str]:
        return [b.block_hash for b in self.all_blocks()]

    def merkle_root(self) -> str:
        return merkle_root(self.block_hashes())

    def merkle_proof(self, index: int) -> Dict[str, Any]:
        hashes = self.block_hashes()
        proof = merkle_proof(hashes, index)
        return {"block_index": index, "block_hash": hashes[index], "root": merkle_root(hashes), "proof": proof}
