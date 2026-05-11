from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from autonomous_identity.core.envelope import LifecycleState
from autonomous_identity.core.exceptions import LifecycleError


class SQLiteLifecycleStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS lifecycle (system_id TEXT PRIMARY KEY, state TEXT, reason TEXT)"
        )
        self._conn.commit()

    def get_lifecycle(self, system_identifier: str) -> LifecycleState | None:
        cur = self._conn.execute(
            "SELECT state FROM lifecycle WHERE system_id = ?", (system_identifier,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return row[0]  # type: ignore[no-any-return]

    def set_lifecycle(
        self, system_identifier: str, state: LifecycleState, *, reason: str | None = None
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO lifecycle (system_id, state, reason) VALUES (?, ?, ?)
                ON CONFLICT(system_id) DO UPDATE SET state = excluded.state, reason = excluded.reason
                """,
                (system_identifier, state, reason),
            )
            self._conn.commit()

    def ensure_active_or_raise(self, system_identifier: str) -> None:
        cur = self._conn.execute(
            "SELECT state, reason FROM lifecycle WHERE system_id = ?", (system_identifier,)
        )
        row = cur.fetchone()
        if not row:
            raise LifecycleError(f"No lifecycle record for {system_identifier!r}")
        st, reason = row[0], row[1]
        if st not in ("active", "restricted"):
            msg = f"Identity not valid for action: {st}"
            if reason:
                msg += f" ({reason})"
            raise LifecycleError(msg)


class SQLiteAuditStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_ref TEXT UNIQUE NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def append(self, event: dict[str, Any]) -> str:
        ref = f"audit://sqlite/{uuid.uuid4().hex}"
        payload = json.dumps({"audit_ref": ref, **event}, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit (audit_ref, payload) VALUES (?, ?)", (ref, payload)
            )
            self._conn.commit()
        return ref

    def get(self, audit_ref: str) -> dict[str, Any] | None:
        cur = self._conn.execute("SELECT payload FROM audit WHERE audit_ref = ?", (audit_ref,))
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row[0])
