"""Build an envelope tree at runtime from plain data (API, LangGraph state, config).

If you persist LangGraph state (checkpointer), ``IdentityEnvelope`` objects need a
custom serializer or you should store specs and call :func:`issue_and_delegate_tree`
again on resume instead of checkpointing raw envelopes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from autonomous_identity.application.facade import AutonomousIdentity
from autonomous_identity.core.envelope import IdentityEnvelope


def _parse_expires(edge: dict[str, Any]) -> datetime | None:
    if "expires_at" in edge and edge["expires_at"] is not None:
        raw = edge["expires_at"]
        if isinstance(raw, datetime):
            return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        if isinstance(raw, str):
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    hours = edge.get("expires_in_hours")
    if hours is not None:
        return datetime.now(timezone.utc) + timedelta(hours=float(hours))
    return None


def issue_and_delegate_tree(
    identity: AutonomousIdentity,
    *,
    issue_context: dict[str, Any],
    edges: list[dict[str, Any]],
    root_role: str = "platform",
) -> dict[str, IdentityEnvelope]:
    """Issue the root envelope, then apply each delegation edge in order.

    ``edges`` must be ordered **parent before child** (any order is fine among
    siblings that share the same parent). Each edge is a dict with:

    - ``role`` — key used in the returned map for this child envelope
    - ``parent_role`` — key of an envelope already in the map (typically
      ``root_role`` for the first row)
    - ``child_subject`` — URI for the child ``system_identifier``
    - ``allowed_scopes`` — list of authorization scope strings, subset of the parent's
      effective scopes when non-empty; use ``[]`` for an **identity-only** edge (no
      capability strings on the credential for this hop)
    - ``caveats`` — optional dict
    - ``expires_at`` — optional ``datetime`` or ISO-8601 string (timezone-aware preferred)
    - ``expires_in_hours`` — optional float; used if ``expires_at`` is absent

    ``issue_context`` is passed to :meth:`AutonomousIdentity.issue_envelope` unchanged
    (include ``issuer_scopes`` when the root must delegate).

    Returns a map ``role -> IdentityEnvelope`` including ``root_role`` for the issuer.
    """
    envelopes: dict[str, IdentityEnvelope] = {}
    root = identity.issue_envelope(issue_context)
    envelopes[root_role] = root

    for i, edge in enumerate(edges):
        try:
            role = str(edge["role"])
            parent_role = str(edge["parent_role"])
            child_subject = str(edge["child_subject"])
            allowed = list(edge["allowed_scopes"])
        except KeyError as e:
            raise KeyError(f"delegation edge[{i}] missing required field: {e}") from e

        if parent_role not in envelopes:
            raise ValueError(
                f"delegation edge[{i}] parent_role {parent_role!r} not built yet; "
                "order edges parent-before-child"
            )
        parent = envelopes[parent_role]
        caveats = edge.get("caveats") if isinstance(edge.get("caveats"), dict) else {}
        child = identity.delegate(
            parent,
            child_subject,
            allowed,
            caveats,
            expires_at=_parse_expires(edge),
        )
        envelopes[role] = child

    return envelopes
