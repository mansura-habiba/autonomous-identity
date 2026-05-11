"""Runtime delegation chain from spec."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.application.delegation_chain import issue_and_delegate_tree


def test_issue_and_delegate_tree_order_and_scopes(tmp_path: Path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "dc", strictness=ValidatorStrictness.STRICT)
    envs = issue_and_delegate_tree(
        identity,
        issue_context={
            "system_identifier": "agent://rt/platform",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "o1",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local:x"],
            "issuer_scopes": ["a", "b", "c"],
        },
        edges=[
            {
                "role": "child1",
                "parent_role": "platform",
                "child_subject": "agent://rt/c1",
                "allowed_scopes": ["a", "b"],
                "caveats": {},
                "expires_in_hours": 1,
            },
            {
                "role": "child2",
                "parent_role": "child1",
                "child_subject": "agent://rt/c2",
                "allowed_scopes": ["a"],
                "caveats": {},
            },
        ],
        root_role="platform",
    )
    assert set(envs.keys()) == {"platform", "child1", "child2"}
    assert envs["platform"].system_identifier == "agent://rt/platform"
    assert envs["child1"].system_identifier == "agent://rt/c1"
    assert envs["child2"].system_identifier == "agent://rt/c2"
    assert envs["child1"].delegations[-1].child_subject == "agent://rt/c1"


def test_issue_and_delegate_tree_bad_parent_order(tmp_path: Path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "dc2", strictness=ValidatorStrictness.STRICT)
    with pytest.raises(ValueError, match="not built yet"):
        issue_and_delegate_tree(
            identity,
            issue_context={
                "system_identifier": "agent://rt/p",
                "instance_id": "i1",
                "deployment_id": "d1",
                "owner_id": "o1",
                "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
                "attestation_chain": ["local:x"],
                "issuer_scopes": ["x"],
            },
            edges=[
                {
                    "role": "late",
                    "parent_role": "missing",
                    "child_subject": "agent://rt/x",
                    "allowed_scopes": ["x"],
                },
            ],
        )


def test_parse_expires_at_iso(tmp_path: Path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "dc3", strictness=ValidatorStrictness.STRICT)
    future = datetime.now(timezone.utc) + timedelta(days=1)
    iso = future.isoformat()
    envs = issue_and_delegate_tree(
        identity,
        issue_context={
            "system_identifier": "agent://rt/p2",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "o1",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local:x"],
            "issuer_scopes": ["s"],
        },
        edges=[
            {
                "role": "c",
                "parent_role": "platform",
                "child_subject": "agent://rt/c",
                "allowed_scopes": ["s"],
                "expires_at": iso,
            },
        ],
    )
    assert envs["c"].delegations[-1].expires_at is not None


def test_issue_and_delegate_tree_identity_only_edge(tmp_path: Path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "dc4", strictness=ValidatorStrictness.STRICT)
    envs = issue_and_delegate_tree(
        identity,
        issue_context={
            "system_identifier": "agent://rt/root",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "o1",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local:x"],
        },
        edges=[
            {
                "role": "worker",
                "parent_role": "platform",
                "child_subject": "agent://rt/worker",
                "allowed_scopes": [],
                "caveats": {},
            },
        ],
    )
    assert "issuer_scopes" not in envs["worker"].metadata
    assert envs["worker"].delegations[-1].allowed_scopes == []
