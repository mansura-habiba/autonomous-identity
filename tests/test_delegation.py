from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from autonomous_identity.adapters.merkle_chain import MerkleChainIdentityAdapter
from autonomous_identity.application.facade import AutonomousIdentity
from autonomous_identity.core.exceptions import VerificationError, ValidationError
from autonomous_identity.core.validators import ValidatorStrictness
from autonomous_identity.crypto.ed25519 import Ed25519Signer
from autonomous_identity.storage.memory import MemoryAuditStore


def _identity_memory() -> AutonomousIdentity:
    cfg = {"identity": {"adapter": "merkle_chain"}, "storage": {"backend": "memory"}}
    return AutonomousIdentity.from_config_dict(cfg)


def test_delegate_monotone_subset() -> None:
    identity = _identity_memory()
    parent = identity.issue_envelope(
        {
            "system_identifier": "agent://org/parent",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "team:a",
            "provenance": {"code_hash": "sha256:1", "policy_bundle_hash": "sha256:2"},
            "attestation_chain": ["local:x"],
            "issuer_scopes": ["finance.read", "finance.write", "admin"],
        }
    )
    child = identity.delegate(
        parent,
        "agent://org/child",
        ["finance.read"],
        {"trace": "abc"},
    )
    assert child.system_identifier == "agent://org/child"
    assert len(child.delegations) == 1
    assert child.delegations[0].allowed_scopes == ["finance.read"]
    assert "issuer_scopes" not in child.metadata

    with pytest.raises(VerificationError):
        identity.delegate(parent, "agent://org/child2", ["other.scope"], {})


def test_delegate_nonempty_scopes_requires_parent_effective() -> None:
    signer = Ed25519Signer.generate()
    audit = MemoryAuditStore()
    adapter = MerkleChainIdentityAdapter(signer, audit_store=audit)
    parent = adapter.issue(
        {
            "system_identifier": "agent://p/x",
            "instance_id": "i",
            "deployment_id": "d",
            "owner_id": "o",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["x"],
        }
    )
    with pytest.raises(VerificationError, match="non-empty allowed_scopes"):
        adapter.delegate(parent, "agent://p/y", ["any"], {})


def test_delegate_identity_only_no_issuer_scopes(tmp_path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "idonly", strictness=ValidatorStrictness.STRICT)
    parent = identity.issue_envelope(
        {
            "system_identifier": "agent://org/root",
            "instance_id": "i",
            "deployment_id": "d",
            "owner_id": "team:a",
            "provenance": {"code_hash": "sha256:1", "policy_bundle_hash": "sha256:2"},
            "attestation_chain": ["local:x"],
        }
    )
    child = identity.delegate(parent, "agent://org/leaf", [], {})
    assert child.delegations[-1].allowed_scopes == []
    assert "issuer_scopes" not in child.metadata

    @identity.material_action(action_type="t", required_scope="any")
    def gated() -> str:
        return "x"

    with identity.exercise(child), pytest.raises(VerificationError, match="not in effective"):
        gated()


def test_delegate_identity_only_allowed_from_scoped_parent(tmp_path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "idonly2", strictness=ValidatorStrictness.STRICT)
    parent = identity.issue_envelope(
        {
            "system_identifier": "agent://org/p",
            "instance_id": "i",
            "deployment_id": "d",
            "owner_id": "team:a",
            "provenance": {"code_hash": "sha256:1", "policy_bundle_hash": "sha256:2"},
            "attestation_chain": ["local:x"],
            "issuer_scopes": ["a.read", "a.write"],
        }
    )
    child = identity.delegate(parent, "agent://org/leaf2", [], {})
    assert "issuer_scopes" not in child.metadata

    @identity.material_action(action_type="t", required_scope="a.read")
    def need() -> None:
        return None

    with identity.exercise(child), pytest.raises(VerificationError, match="not in effective"):
        need()


def test_material_action_respects_scope_and_expiry() -> None:
    identity = _identity_memory()
    parent = identity.issue_envelope(
        {
            "system_identifier": "agent://org/p2",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "team:a",
            "provenance": {"code_hash": "sha256:1", "policy_bundle_hash": "sha256:2"},
            "attestation_chain": ["local:x"],
            "issuer_scopes": ["a.read", "a.write"],
        }
    )
    child = identity.delegate(parent, "agent://org/c2", ["a.read"], {}, expires_at=None)

    @identity.material_action(action_type="t", required_scope="a.read")
    def ok() -> str:
        return "y"

    with identity.exercise(child):
        assert ok()["result"] == "y"

    @identity.material_action(action_type="t", required_scope="a.write")
    def bad() -> str:
        return "n"

    with identity.exercise(child), pytest.raises(VerificationError, match="not in effective"):
        bad()


def test_expired_delegation_blocks_validate() -> None:
    from dataclasses import replace

    identity = _identity_memory()
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    parent = identity.issue_envelope(
        {
            "system_identifier": "agent://org/p3",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "team:a",
            "provenance": {"code_hash": "sha256:1", "policy_bundle_hash": "sha256:2"},
            "attestation_chain": ["local:x"],
            "issuer_scopes": ["scope.a"],
        }
    )
    child = identity.delegate(
        parent,
        "agent://org/c3",
        ["scope.a"],
        {},
        expires_at=future,
    )
    d0 = child.delegations[0]
    child.delegations[0] = replace(d0, expires_at=past)
    from autonomous_identity.core.validators import IdentityValidator

    with pytest.raises(ValidationError, match="expired"):
        IdentityValidator().validate(child)


def test_expired_blocks_material_action() -> None:
    from dataclasses import replace

    identity = _identity_memory()
    parent = identity.issue_envelope(
        {
            "system_identifier": "agent://org/p4",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "team:a",
            "provenance": {"code_hash": "sha256:1", "policy_bundle_hash": "sha256:2"},
            "attestation_chain": ["local:x"],
            "issuer_scopes": ["s"],
        }
    )
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    child = identity.delegate(parent, "agent://org/c4", ["s"], {}, expires_at=future)
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    d0 = child.delegations[0]
    child.delegations[0] = replace(d0, expires_at=past)

    @identity.material_action(action_type="t", required_scope=None)
    def f() -> int:
        return 1

    with identity.exercise(child), pytest.raises(VerificationError, match="expired"):
        f()
