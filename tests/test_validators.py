import pytest

from autonomous_identity.core.envelope import (
    IdentityEnvelope,
    OwnerBinding,
    ProvenanceReference,
    RuntimeInstance,
)
from autonomous_identity.core.exceptions import ValidationError
from autonomous_identity.core.validators import IdentityValidator, ValidatorStrictness
from datetime import datetime, timezone


def _minimal_envelope(**kwargs) -> IdentityEnvelope:
    defaults = dict(
        system_identifier="agent://x/y",
        runtime_instance=RuntimeInstance(
            instance_id="i1", deployment_id="d1", environment="dev", region="local"
        ),
        owner_binding=OwnerBinding(owner_id="o1", owner_type="team", responsibility_scope="s"),
        attestation_chain=["x"],
        provenance=ProvenanceReference(code_hash="sha256:1"),
        lifecycle_state="active",
        issued_at=datetime.now(timezone.utc),
        verified_at=None,
        audit_ref="audit://memory/1",
        signature_chain=["sig"],
    )
    defaults.update(kwargs)
    return IdentityEnvelope(**defaults)


def test_strict_requires_provenance() -> None:
    v = IdentityValidator(ValidatorStrictness.STRICT)
    env = _minimal_envelope(provenance=ProvenanceReference())
    with pytest.raises(ValidationError):
        v.validate(env)


def test_dev_placeholder() -> None:
    v = IdentityValidator(ValidatorStrictness.DEVELOPMENT)
    env = _minimal_envelope(
        provenance=ProvenanceReference(),
        metadata={"dev_provenance_placeholder": True},
    )
    v.validate(env)


def test_unknown_adapter_raises() -> None:
    from autonomous_identity.adapters.registry import get_adapter
    from autonomous_identity.core.exceptions import AdapterNotFoundError

    with pytest.raises(AdapterNotFoundError):
        get_adapter("not_real", {"signer": None, "audit_store": None, "lifecycle_store": None})
