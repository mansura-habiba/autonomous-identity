import os
from pathlib import Path

import pytest

from autonomous_identity import AutonomousIdentity
from autonomous_identity.core.exceptions import LifecycleError


def _make_cfg(backend: str, tmp_path: Path) -> dict:
    if backend == "file":
        return {
            "identity": {"adapter": "merkle_chain"},
            "storage": {"backend": "file", "data_dir": str(tmp_path / "f")},
        }
    if backend == "sqlite":
        p = tmp_path / "s" / "store.sqlite3"
        p.parent.mkdir(parents=True, exist_ok=True)
        return {"identity": {"adapter": "merkle_chain"}, "storage": {"backend": "sqlite", "path": str(p)}}
    if backend == "memory":
        return {"identity": {"adapter": "merkle_chain"}, "storage": {"backend": "memory"}}
    if backend == "postgres":
        dsn = os.environ.get("TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("TEST_POSTGRES_DSN not set")
        return {"identity": {"adapter": "merkle_chain"}, "storage": {"backend": "postgres", "dsn": dsn}}
    raise AssertionError


@pytest.mark.parametrize("backend", ["file", "sqlite", "memory"])
def test_lifecycle_revoke_blocks_action(backend: str, tmp_path: Path) -> None:
    cfg = _make_cfg(backend, tmp_path)
    identity = AutonomousIdentity.from_config_dict(cfg)
    env = identity.issue_envelope(
        {
            "system_identifier": f"agent://stor/{backend}",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "o1",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local:x"],
        }
    )

    @identity.material_action(action_type="x")
    def boom() -> str:
        return "ok"

    with identity.exercise(env):
        assert boom() == "ok"

    identity.revoke(env.system_identifier, "test")

    with identity.exercise(env), pytest.raises(LifecycleError):
        boom()


@pytest.mark.parametrize("backend", ["postgres"])
def test_postgres_optional(backend: str, tmp_path: Path) -> None:
    cfg = _make_cfg(backend, tmp_path)
    identity = AutonomousIdentity.from_config_dict(cfg)
    env = identity.issue_envelope(
        {
            "system_identifier": "agent://stor/pg",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "o1",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local:x"],
        }
    )
    assert env.audit_ref
