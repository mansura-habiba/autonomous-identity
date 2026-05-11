from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON for hashing (sorted keys, no ASCII-only escape)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_canonical(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))
