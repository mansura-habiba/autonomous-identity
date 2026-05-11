from __future__ import annotations

import json
import uuid
from typing import Any

from autonomous_identity.core.envelope import LifecycleState
from autonomous_identity.core.exceptions import LifecycleError


class PostgresLifecycleStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._dsn = dsn
        self._psycopg = psycopg
        self._ensure_schema()

    def _connect(self):
        return self._psycopg.connect(self._dsn)

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS autonomous_identity_lifecycle (
                    system_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    reason TEXT
                )
                """
            )

    def get_lifecycle(self, system_identifier: str) -> LifecycleState | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state FROM autonomous_identity_lifecycle WHERE system_id = %s",
                (system_identifier,),
            ).fetchone()
        if not row:
            return None
        return row[0]  # type: ignore[no-any-return]

    def set_lifecycle(
        self, system_identifier: str, state: LifecycleState, *, reason: str | None = None
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO autonomous_identity_lifecycle (system_id, state, reason)
                VALUES (%s, %s, %s)
                ON CONFLICT (system_id) DO UPDATE
                SET state = EXCLUDED.state, reason = EXCLUDED.reason
                """,
                (system_identifier, state, reason),
            )

    def ensure_active_or_raise(self, system_identifier: str) -> None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state, reason FROM autonomous_identity_lifecycle WHERE system_id = %s",
                (system_identifier,),
            ).fetchone()
        if not row:
            raise LifecycleError(f"No lifecycle record for {system_identifier!r}")
        st, reason = row[0], row[1]
        if st not in ("active", "restricted"):
            msg = f"Identity not valid for action: {st}"
            if reason:
                msg += f" ({reason})"
            raise LifecycleError(msg)


class PostgresAuditStore:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self._dsn = dsn
        self._psycopg = psycopg
        self._ensure_schema()

    def _connect(self):
        return self._psycopg.connect(self._dsn)

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS autonomous_identity_audit (
                    id BIGSERIAL PRIMARY KEY,
                    audit_ref TEXT UNIQUE NOT NULL,
                    payload JSONB NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS autonomous_identity_audit_ref_idx
                ON autonomous_identity_audit (audit_ref)
                """
            )

    def append(self, event: dict[str, Any]) -> str:
        ref = f"audit://postgres/{uuid.uuid4().hex}"
        payload = {"audit_ref": ref, **event}
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO autonomous_identity_audit (audit_ref, payload) VALUES (%s, %s::jsonb)",
                (ref, json.dumps(payload, sort_keys=True)),
            )
        return ref

    def get(self, audit_ref: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM autonomous_identity_audit WHERE audit_ref = %s",
                (audit_ref,),
            ).fetchone()
        if not row:
            return None
        payload = row[0]
        if isinstance(payload, dict):
            return payload
        return json.loads(str(payload))
