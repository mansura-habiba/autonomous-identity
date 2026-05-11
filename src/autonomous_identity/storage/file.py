from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path
from typing import Any

from autonomous_identity.core.envelope import LifecycleState
from autonomous_identity.core.exceptions import LifecycleError


class FileLifecycleStore:
    """JSON map of system_identifier -> {state, reason}."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        if not self._path.exists():
            self._path.write_text("{}\n")

    def _read_all(self) -> dict[str, Any]:
        raw = self._path.read_text(encoding="utf-8").strip()
        if not raw:
            return {}
        return json.loads(raw)

    def _write_all(self, data: dict[str, Any]) -> None:
        self._path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def get_lifecycle(self, system_identifier: str) -> LifecycleState | None:
        with self._lock:
            data = self._read_all()
            rec = data.get(system_identifier)
            if not rec:
                return None
            return rec["state"]  # type: ignore[no-any-return]

    def set_lifecycle(
        self, system_identifier: str, state: LifecycleState, *, reason: str | None = None
    ) -> None:
        with self._lock:
            data = self._read_all()
            data[system_identifier] = {"state": state, "reason": reason}
            self._write_all(data)

    def ensure_active_or_raise(self, system_identifier: str) -> None:
        st = self.get_lifecycle(system_identifier)
        if st is None:
            raise LifecycleError(f"No lifecycle record for {system_identifier!r}")
        if st not in ("active", "restricted"):
            with self._lock:
                rec = self._read_all().get(system_identifier, {})
            reason = rec.get("reason")
            msg = f"Identity not valid for action: {st}"
            if reason:
                msg += f" ({reason})"
            raise LifecycleError(msg)


class FileAuditStore:
    """Append-only JSONL audit log."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        if not self._path.exists():
            self._path.touch()

    def append(self, event: dict[str, Any]) -> str:
        ref = f"audit://file/{uuid.uuid4().hex}"
        row = {"audit_ref": ref, **event}
        line = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line)
        return ref

    def get(self, audit_ref: str) -> dict[str, Any] | None:
        with self._lock:
            with self._path.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    if obj.get("audit_ref") == audit_ref:
                        return obj
        return None
