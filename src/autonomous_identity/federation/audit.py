from __future__ import annotations

from dataclasses import asdict
from typing import Any

from autonomous_identity.federation.model import FederationDecision
from autonomous_identity.storage.base import AuditStore


class FederationAuditRecorder:
    """Write federation verification decisions into an AuditStore."""

    def __init__(self, audit_store: AuditStore) -> None:
        self.audit_store = audit_store

    def record(self, decision: FederationDecision, *, extra: dict[str, Any] | None = None) -> str:
        return self.audit_store.append(
            {
                "kind": "federation_decision",
                "decision": asdict(decision),
                "extra": extra or {},
            }
        )