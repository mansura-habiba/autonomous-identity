"""asid scope v1 helpers and opt-in enforcement."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.core.exceptions import ValidationError
from autonomous_identity.core.scope_convention import (
    build_scope_v1,
    is_valid_scope_v1,
    validate_envelope_scope_strings,
    validate_scope_strings,
)
from autonomous_identity.core.envelope import Delegation, IdentityEnvelope, OwnerBinding, ProvenanceReference, RuntimeInstance
from autonomous_identity.core.validators import IdentityValidator


def test_build_scope_v1_roundtrip_pattern() -> None:
    s = build_scope_v1("Acme Corp", "commerce", "orders.read")
    assert s == "asid:acme-corp:commerce:orders.read"
    assert is_valid_scope_v1(s)


def test_is_valid_scope_v1_rejects_legacy_flat_string() -> None:
    assert not is_valid_scope_v1("orders.read")
    assert not is_valid_scope_v1("")


def test_validate_scope_strings_rejects_empty_when_enforcing() -> None:
    with pytest.raises(ValidationError, match="Empty"):
        validate_scope_strings([""], label="scope")


def test_identity_validator_skips_by_default() -> None:
    v = IdentityValidator(strictness=ValidatorStrictness.DEVELOPMENT, enforce_scope_convention=False)
    now = datetime.now(timezone.utc)
    env = IdentityEnvelope(
        system_identifier="agent://x/y",
        runtime_instance=RuntimeInstance(
            instance_id="i",
            deployment_id="d",
            environment="dev",
            region="local",
        ),
        owner_binding=OwnerBinding(owner_id="o", owner_type="team", responsibility_scope="r"),
        attestation_chain=["local"],
        provenance=ProvenanceReference(),
        lifecycle_state="active",
        issued_at=now,
        verified_at=None,
        metadata={"issuer_scopes": ["not-asid"], "dev_provenance_placeholder": True},
        signature_chain=["sig"],
        audit_ref="audit://file/abc",
    )
    v.validate(env)


def test_identity_validator_enforces_on_envelope() -> None:
    v = IdentityValidator(strictness=ValidatorStrictness.DEVELOPMENT, enforce_scope_convention=True)
    now = datetime.now(timezone.utc)
    bad = IdentityEnvelope(
        system_identifier="agent://x/y",
        runtime_instance=RuntimeInstance(
            instance_id="i",
            deployment_id="d",
            environment="dev",
            region="local",
        ),
        owner_binding=OwnerBinding(owner_id="o", owner_type="team", responsibility_scope="r"),
        attestation_chain=["local"],
        provenance=ProvenanceReference(),
        lifecycle_state="active",
        issued_at=now,
        verified_at=None,
        metadata={"issuer_scopes": ["legacy.read"], "dev_provenance_placeholder": True},
        signature_chain=["sig"],
        audit_ref="audit://file/abc",
    )
    with pytest.raises(ValidationError, match="issuer_scope"):
        v.validate(bad)


def test_autonomous_identity_enforcement_issue(tmp_path) -> None:
    good = AutonomousIdentity.local(tmp_path, strictness=ValidatorStrictness.STRICT)
    env = good.issue_envelope(
        {
            "system_identifier": "agent://t/p",
            "instance_id": "i",
            "deployment_id": "d",
            "owner_id": "o",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local"],
            "issuer_scopes": [build_scope_v1("org", "svc", "cap.one")],
        }
    )
    assert env.metadata["issuer_scopes"][0].startswith("asid:org:svc:")

    strict = AutonomousIdentity.local(
        tmp_path / "s2",
        strictness=ValidatorStrictness.STRICT,
        enforce_scope_convention=True,
    )
    with pytest.raises(ValidationError, match="issuer_scope"):
        strict.issue_envelope(
            {
                "system_identifier": "agent://t/q",
                "instance_id": "i",
                "deployment_id": "d",
                "owner_id": "o",
                "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
                "attestation_chain": ["local"],
                "issuer_scopes": ["legacy"],
            }
        )


def test_validate_envelope_scope_strings_delegation(tmp_path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "s3", enforce_scope_convention=True)
    a = build_scope_v1("ns", "s", "a")
    b = build_scope_v1("ns", "s", "b")
    parent = identity.issue_envelope(
        {
            "system_identifier": "agent://t/parent",
            "instance_id": "i",
            "deployment_id": "d",
            "owner_id": "o",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local"],
            "issuer_scopes": [a, b],
        }
    )
    child = identity.delegate(parent, "agent://t/child", [a], {})
    assert a in child.delegations[0].allowed_scopes


def test_validate_envelope_scope_strings_rejects_delegation_allowed_scopes() -> None:
    now = datetime.now(timezone.utc)
    env = IdentityEnvelope(
        system_identifier="agent://p/c",
        runtime_instance=RuntimeInstance(
            instance_id="i", deployment_id="d", environment="dev", region="local"
        ),
        owner_binding=OwnerBinding(owner_id="o", owner_type="team", responsibility_scope="r"),
        attestation_chain=["local"],
        provenance=ProvenanceReference(),
        lifecycle_state="active",
        issued_at=now,
        verified_at=None,
        signature_chain=["sig"],
        audit_ref="audit://file/z",
        delegations=[
            Delegation(
                parent_subject="agent://p",
                child_subject="agent://p/c",
                allowed_scopes=["not-an-asid-scope"],
            )
        ],
    )
    with pytest.raises(ValidationError, match="delegation.allowed_scope"):
        validate_envelope_scope_strings(env)


def test_run_material_action_validates_required_scope(tmp_path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "s4", enforce_scope_convention=True)
    s = build_scope_v1("ns", "api", "get")
    env = identity.issue_envelope(
        {
            "system_identifier": "agent://t/x",
            "instance_id": "i",
            "deployment_id": "d",
            "owner_id": "o",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local"],
            "issuer_scopes": [s],
        }
    )
    with pytest.raises(ValidationError, match="required_scope"):
        identity.run_material_action(
            env,
            action_type="x",
            required_scope="bad-scope",
            fn=lambda: 1,
            args=(),
            kwargs={},
        )
    proof = identity.run_material_action(
        env,
        action_type="x",
        required_scope=s,
        fn=lambda: 1,
        args=(),
        kwargs={},
    )
    assert proof["result"] == 1
