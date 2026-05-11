"""Optional **asid scope v1** grammar for **authorization** metadata (not strict identity).

``issuer_scopes`` (root issue only) and ``Delegation.allowed_scopes`` carry optional
capability strings; the envelope core (subject, bindings, provenance, signatures) stands
alone without them. When enforcement is off (default), scopes remain opaque strings.
When on, every non-empty scope must match :data:`SCOPE_V1_PATTERN`. See ``docs/SCOPE_CONVENTION.md``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from autonomous_identity.core.envelope import IdentityEnvelope
from autonomous_identity.core.exceptions import ValidationError

_MAX_SCOPE_LEN = 512

# Namespace / service: hyphen slug (no underscore) for collision-safe partition IDs.
# Single-character labels allowed (e.g. asid:ns:s:a); interior ≤61 so total length ≤63.
_slug = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# Capability segment: dot-separated; underscores allowed (e.g. tool_invoke).
_seg = r"[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?"
SCOPE_V1_PATTERN = re.compile(
    rf"^asid:({_slug}):({_slug}):({_seg}(?:\.{_seg})*)$",
    re.IGNORECASE,
)


def build_scope_v1(namespace: str, service: str, capability: str) -> str:
    """Build a canonical **lowercase** ``asid:`` scope string.

    ``namespace`` and ``service`` are normalized to slug form. ``capability`` is either
    a single slug or dot-separated slugs (e.g. ``orders.read``).
    """
    ns = _slugify(namespace, "namespace")
    svc = _slugify(service, "service")
    cap = _capability_path(capability)
    s = f"asid:{ns}:{svc}:{cap}"
    if len(s) > _MAX_SCOPE_LEN:
        raise ValidationError(f"Built scope exceeds max length ({_MAX_SCOPE_LEN}): {len(s)}")
    if not SCOPE_V1_PATTERN.match(s):
        raise ValidationError(f"Built scope failed v1 pattern check: {s!r}")
    return s


def is_valid_scope_v1(scope: str) -> bool:
    """Return True if ``scope`` matches **asid** v1 grammar (case-insensitive ``asid`` prefix)."""
    if not scope or len(scope) > _MAX_SCOPE_LEN:
        return False
    return bool(SCOPE_V1_PATTERN.match(scope.strip()))


def validate_scope_strings(scopes: Iterable[str], *, label: str = "scope") -> None:
    """Raise :class:`ValidationError` if any string is non-empty and not v1-shaped."""
    for s in scopes:
        if s is None or not str(s).strip():
            raise ValidationError(f"Empty {label} is not allowed when scope convention is enforced")
        if not is_valid_scope_v1(str(s).strip()):
            raise ValidationError(
                f"Invalid {label} {s!r}: expected asid v1 "
                "(see docs/SCOPE_CONVENTION.md: asid:<namespace>:<service>:<capability>)"
            )


def validate_required_scope(required_scope: str | None) -> None:
    """Validate a single ``required_scope`` for material actions (skip if None/empty)."""
    if required_scope is None or not str(required_scope).strip():
        return
    validate_scope_strings([str(required_scope).strip()], label="required_scope")


def validate_envelope_scope_strings(envelope: IdentityEnvelope) -> None:
    """Validate ``issuer_scopes`` and every delegation's ``allowed_scopes``."""
    raw = envelope.metadata.get("issuer_scopes")
    if isinstance(raw, list) and raw:
        validate_scope_strings((str(x) for x in raw), label="issuer_scope")
    for d in envelope.delegations:
        validate_scope_strings(d.allowed_scopes, label="delegation.allowed_scope")


def _slugify(value: str, name: str) -> str:
    t = str(value).strip().lower()
    if not t:
        raise ValidationError(f"Empty {name} in scope builder")
    buf: list[str] = []
    for ch in t:
        if ch.isalnum():
            buf.append(ch)
        elif ch in " -_":
            buf.append("-")
        else:
            raise ValidationError(f"Invalid character in {name} {value!r}")
    s = "".join(buf).strip("-")
    while "--" in s:
        s = s.replace("--", "-")
    if not s or len(s) > 63:
        raise ValidationError(f"Invalid {name} slug {value!r} (length 1–63 after normalization)")
    if not s[0].isalnum() or not s[-1].isalnum():
        raise ValidationError(f"{name} slug must start and end with alphanumeric: {s!r}")
    return s


def _capability_path(value: str) -> str:
    t = str(value).strip().lower()
    if not t:
        raise ValidationError("Empty capability in scope builder")
    parts = [p for p in t.split(".") if p]
    if not parts:
        raise ValidationError("Capability must have at least one segment")
    return ".".join(_cap_segment(p, "capability segment") for p in parts)


def _cap_segment(value: str, name: str) -> str:
    t = str(value).strip().lower()
    if not t:
        raise ValidationError(f"Empty {name}")
    buf: list[str] = []
    for ch in t:
        if ch.isalnum():
            buf.append(ch)
        elif ch in " -":
            buf.append("-")
        elif ch == "_":
            buf.append("_")
        elif ch == ".":
            raise ValidationError(f"Nested dot not allowed inside {name} {value!r}")
        else:
            raise ValidationError(f"Invalid character in {name} {value!r}")
    s = "".join(buf).strip("-").strip("_")
    while "__" in s:
        s = s.replace("__", "_")
    while "--" in s:
        s = s.replace("--", "-")
    if not s or len(s) > 63:
        raise ValidationError(f"Invalid {name} {value!r} (length 1–63 after normalization)")
    if not s[0].isalnum() or not s[-1].isalnum():
        raise ValidationError(f"{name} must start and end with alphanumeric: {s!r}")
    return s
