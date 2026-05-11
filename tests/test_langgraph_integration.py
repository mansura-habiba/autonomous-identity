"""Tests for integrations.langgraph (no langgraph package required)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from autonomous_identity import AutonomousIdentity
from autonomous_identity.application.facade import AutonomousIdentity as AI
from autonomous_identity.core.envelope import IdentityEnvelope
from autonomous_identity.integrations.langgraph import langgraph_identity, wrap_langgraph_node


def _minimal_issue(identity: AutonomousIdentity, sid: str):
    return identity.issue_envelope(
        {
            "system_identifier": sid,
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "o1",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local:x"],
        }
    )


def test_wrap_langgraph_node_sets_context(tmp_path: Path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "lg", backend="memory")
    env = _minimal_issue(identity, "agent://wrap/test")

    def node(_state: dict) -> dict:
        assert AI._envelope_ctx.get() is env
        return {"ok": True}

    wrapped = wrap_langgraph_node(identity, env, node)
    assert wrapped({}) == {"ok": True}
    assert AI._envelope_ctx.get() is None


def test_wrap_langgraph_node_async(tmp_path: Path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "lga", backend="memory")
    env = _minimal_issue(identity, "agent://wrap/async")

    async def node(_state: dict) -> dict:
        assert AI._envelope_ctx.get() is env
        return {"async": True}

    wrapped = wrap_langgraph_node(identity, env, node)
    assert asyncio.run(wrapped({})) == {"async": True}


def test_wrap_langgraph_node_callable_envelope(tmp_path: Path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "lgc", backend="memory")
    env_a = _minimal_issue(identity, "agent://wrap/a")
    env_b = _minimal_issue(identity, "agent://wrap/b")

    def pick(s: dict) -> IdentityEnvelope:
        return env_a if s["which"] == "a" else env_b

    def node(state: dict) -> str:
        return AI._envelope_ctx.get().system_identifier  # type: ignore[union-attr]

    wrapped = wrap_langgraph_node(identity, pick, node)
    assert wrapped({"which": "a"}) == "agent://wrap/a"
    assert wrapped({"which": "b"}) == "agent://wrap/b"


def test_langgraph_identity_decorator(tmp_path: Path) -> None:
    identity = AutonomousIdentity.local(tmp_path / "lgd", backend="memory")
    env = _minimal_issue(identity, "agent://wrap/dec")

    @langgraph_identity(identity, env)
    def node(_state: dict) -> int:
        assert AI._envelope_ctx.get() is env
        return 42

    assert node({}) == 42
