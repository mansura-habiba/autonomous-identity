from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from autonomous_identity.core.envelope import IdentityEnvelope, ProvenanceReference
from autonomous_identity.core.exceptions import ValidationError


class ValidatorStrictness(str, Enum):
    STRICT = "strict"
    DEVELOPMENT = "development"


class IdentityValidator:
    """Executable checks for the eight identity properties."""

    def __init__(
        self,
        strictness: ValidatorStrictness = ValidatorStrictness.STRICT,
        *,
        enforce_scope_convention: bool = False,
    ) -> None:
        self.strictness = strictness
        self.enforce_scope_convention = enforce_scope_convention

    def validate(self, envelope: IdentityEnvelope) -> None:
        self.check_persistent(envelope)
        self.check_addressable(envelope)
        self.check_verifiable(envelope)
        self.check_attenuable(envelope)
        self.check_delegation_grants_not_expired(envelope)
        self.check_instance_specific(envelope)
        self.check_provenance_aware(envelope)
        self.check_lifecycle_controlled(envelope)
        self.check_auditable(envelope)
        self.check_scope_vocabulary(envelope)

    def check_persistent(self, envelope: IdentityEnvelope) -> None:
        if not envelope.system_identifier:
            raise ValidationError("Missing persistent system identifier")

    def check_addressable(self, envelope: IdentityEnvelope) -> None:
        if "://" not in envelope.system_identifier:
            raise ValidationError("System identifier should be URI-like and addressable")

    def check_verifiable(self, envelope: IdentityEnvelope) -> None:
        if not envelope.signature_chain and not envelope.attestation_chain:
            raise ValidationError("Envelope has no cryptographic verification material")

    def check_attenuable(self, envelope: IdentityEnvelope) -> None:
        for delegation in envelope.delegations:
            # ``allowed_scopes`` may be empty for an identity-only handoff (no capability
            # strings on this edge); authorization otherwise lives in non-empty lists.
            if delegation.parent_subject == delegation.child_subject:
                raise ValidationError("Delegation parent and child subjects must differ")

    def check_delegation_grants_not_expired(self, envelope: IdentityEnvelope) -> None:
        now = datetime.now(timezone.utc)
        for d in envelope.delegations:
            if d.child_subject != envelope.system_identifier:
                continue
            if d.expires_at is not None and d.expires_at <= now:
                raise ValidationError(
                    f"Delegation grant from {d.parent_subject!r} has expired for this actor"
                )

    def check_instance_specific(self, envelope: IdentityEnvelope) -> None:
        if not envelope.runtime_instance.instance_id:
            raise ValidationError("Missing runtime instance ID")

    def check_provenance_aware(self, envelope: IdentityEnvelope) -> None:
        provenance = envelope.provenance
        if _provenance_any(provenance):
            return
        if self.strictness is ValidatorStrictness.DEVELOPMENT:
            if envelope.metadata.get("dev_provenance_placeholder"):
                return
            raise ValidationError(
                "Envelope has no provenance reference; add provenance fields or set "
                "metadata['dev_provenance_placeholder']=True for local development only"
            )
        raise ValidationError("Envelope has no provenance reference")

    def check_lifecycle_controlled(self, envelope: IdentityEnvelope) -> None:
        if envelope.lifecycle_state not in ("active", "restricted"):
            raise ValidationError(f"Identity is not currently valid: {envelope.lifecycle_state}")

    def check_auditable(self, envelope: IdentityEnvelope) -> None:
        if not envelope.audit_ref:
            raise ValidationError("Missing audit reference")

    def check_scope_vocabulary(self, envelope: IdentityEnvelope) -> None:
        """When ``enforce_scope_convention`` is set, require ``asid:`` v1 scope strings."""
        if not self.enforce_scope_convention:
            return
        from autonomous_identity.core.scope_convention import validate_envelope_scope_strings

        validate_envelope_scope_strings(envelope)


def _provenance_any(provenance: ProvenanceReference) -> bool:
    return any(
        [
            provenance.code_hash,
            provenance.model_hash,
            provenance.config_hash,
            provenance.policy_bundle_hash,
            provenance.build_artifact_ref,
            provenance.deployment_manifest_hash,
            provenance.slsa_attestation_ref,
            provenance.in_toto_statement_ref,
        ]
    )
