from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any

from autonomous_identity.core.envelope import IdentityEnvelope


def _json_safe(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    return obj


def envelope_commitment_payload(envelope: IdentityEnvelope) -> dict[str, Any]:
    """Stable dict for hashing/signing (excludes volatile proof fields)."""
    d = asdict(envelope)
    d.pop("signature_chain", None)
    d.pop("audit_ref", None)
    d.pop("verified_at", None)
    return _json_safe(d)


def envelope_commitment_hash(envelope: IdentityEnvelope) -> str:
    from autonomous_identity.core.hashing import hash_canonical

    return hash_canonical(envelope_commitment_payload(envelope))
