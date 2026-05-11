from __future__ import annotations

from typing import Any, Protocol

from autonomous_identity.core.envelope import LifecycleState


class LifecycleStore(Protocol):
    def get_lifecycle(self, system_identifier: str) -> LifecycleState | None:
        """Return None if unknown."""

    def set_lifecycle(self, system_identifier: str, state: LifecycleState, *, reason: str | None = None) -> None:
        ...

    def ensure_active_or_raise(self, system_identifier: str) -> None:
        """Raise LifecycleError if not active or restricted."""


class AuditStore(Protocol):
    def append(self, event: dict[str, Any]) -> str:
        """Append-only; return stable audit reference."""

    def get(self, audit_ref: str) -> dict[str, Any] | None:
        ...
