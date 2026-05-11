"""Helpers for delegation scope and expiry (Phase 2)."""

from __future__ import annotations

from datetime import datetime, timezone

from autonomous_identity.core.envelope import IdentityEnvelope
from autonomous_identity.core.exceptions import VerificationError


def effective_scopes_for_actor(envelope: IdentityEnvelope) -> set[str]:
    """Authorization strings this actor may exercise (optional layer; not part of strict identity).

    1. Union of ``allowed_scopes`` on every ``Delegation`` whose ``child_subject`` matches
       ``envelope.system_identifier`` (may be empty for identity-only grants).
    2. If that union is non-empty, return it. **Delegated** envelopes have ``issuer_scopes``
       stripped by the adapter so grants do not fall through from the parent root.
    3. Otherwise, if this is a **root** envelope (never delegated), fall back to
       ``metadata["issuer_scopes"]`` when present — optional issuer grant on issue only.
    """
    scopes: set[str] = set()
    for d in envelope.delegations:
        if d.child_subject == envelope.system_identifier:
            scopes.update(d.allowed_scopes)
    if scopes:
        return scopes
    raw = envelope.metadata.get("issuer_scopes")
    if isinstance(raw, list) and raw:
        return {str(x) for x in raw}
    return set()


def ensure_delegations_not_expired(envelope: IdentityEnvelope) -> None:
    """Fail if any delegation granting this actor has expired."""
    now = datetime.now(timezone.utc)
    for d in envelope.delegations:
        if d.child_subject != envelope.system_identifier:
            continue
        if d.expires_at is not None and d.expires_at <= now:
            raise VerificationError(
                f"Delegation from {d.parent_subject!r} to {d.child_subject!r} has expired"
            )
