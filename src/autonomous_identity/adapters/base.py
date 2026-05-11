from __future__ import annotations

from typing import Any, Protocol

from autonomous_identity.core.envelope import IdentityEnvelope


class IdentityAdapter(Protocol):
    """Pluggable identity construction / verification (Merkle chain, SPIFFE, hybrid, …)."""

    name: str

    def issue(self, context: dict[str, Any]) -> IdentityEnvelope:
        """Create or refresh an identity envelope from context."""

    def verify(self, envelope: IdentityEnvelope) -> bool:
        """Verify cryptographic material for this envelope."""

    def delegate(
        self,
        envelope: IdentityEnvelope,
        child_subject: str,
        caveats: dict[str, Any],
    ) -> IdentityEnvelope:
        """Return envelope with narrowed delegation (v0.1 may raise NotImplementedError)."""

    def revoke(self, system_identifier: str, reason: str) -> None:
        """Adapter-specific revocation hooks (registry usually updates lifecycle store)."""

    def audit(self, envelope: IdentityEnvelope, action: dict[str, Any]) -> str:
        """Record action evidence; return audit reference."""
