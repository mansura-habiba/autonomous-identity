from pathlib import Path

import pytest

from autonomous_identity import AutonomousIdentity


def test_material_action_requires_exercise(tmp_path: Path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "d", backend="memory")

    @identity.material_action(action_type="t")
    def f() -> int:
        return 1

    env = identity.issue_envelope(
        {
            "system_identifier": "agent://facade/a",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "o1",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local:x"],
        }
    )

    with pytest.raises(RuntimeError):
        f()

    with identity.exercise(env):
        assert f() == 1
