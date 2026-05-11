from __future__ import annotations

import uuid
from typing import Any

from autonomous_identity.core.envelope import LifecycleState
from autonomous_identity.core.exceptions import LifecycleError


class MemoryLifecycleStore:
    def __init__(self) -> None:
        self._state: dict[str, LifecycleState] = {}
        self._reasons: dict[str, str | None] = {}

    def get_lifecycle(self, system_identifier: str) -> LifecycleState | None:
        return self._state.get(system_identifier)

    def set_lifecycle(
        self, system_identifier: str, state: LifecycleState, *, reason: str | None = None
    ) -> None:
        self._state[system_identifier] = state
        self._reasons[system_identifier] = reason

    def ensure_active_or_raise(self, system_identifier: str) -> None:
        st = self._state.get(system_identifier)
        if st is None:
            raise LifecycleError(f"No lifecycle record for {system_identifier!r}")
        if st not in ("active", "restricted"):
            reason = self._reasons.get(system_identifier)
            msg = f"Identity not valid for action: {st}"
            if reason:
                msg += f" ({reason})"
            raise LifecycleError(msg)


class MemoryAuditStore:
    def __init__(self) -> None:
        self._events: dict[str, dict[str, Any]] = {}

    def append(self, event: dict[str, Any]) -> str:
        ref = f"audit://memory/{uuid.uuid4().hex}"
        self._events[ref] = dict(event)
        return ref

    def get(self, audit_ref: str) -> dict[str, Any] | None:
        return self._events.get(audit_ref)
