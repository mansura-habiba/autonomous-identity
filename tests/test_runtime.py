"""Tests for the framework-agnostic IdentityRuntime."""

from __future__ import annotations

import asyncio
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.integrations.runtime import IdentityRuntime


def _facade() -> AutonomousIdentity:
    td = Path(tempfile.mkdtemp(prefix="asid-runtime-"))
    return AutonomousIdentity.local(
        td,
        adapter_name="spiffe",
        strictness=ValidatorStrictness.STRICT,
    )


def _root_ctx() -> dict:
    return {
        "system_identifier": "spiffe://example.org/agents/root",
        "instance_id": "i-1",
        "deployment_id": "d-1",
        "owner_id": "team:demo",
        "provenance": {"code_hash": "sha256:a"},
        "attestation_chain": ["local:bootstrap"],
        "issuer_scopes": ["web.read", "doc.write", "orchestrate"],
    }


def test_wrap_tool_returns_new_callable_does_not_mutate() -> None:
    identity = _facade()
    env = identity.issue_envelope(_root_ctx())
    runtime = IdentityRuntime(identity, env)

    calls = []

    def my_fetch(url: str) -> str:
        calls.append(url)
        return f"FETCHED:{url}"

    safe_fetch = runtime.wrap_tool(my_fetch, required_scope="web.read")

    # Wrapper is a different object than the input function.
    assert safe_fetch is not my_fetch
    # Original is untouched and still callable directly (no gate).
    assert my_fetch("https://x") == "FETCHED:https://x"
    # Wrapped goes through the identity gate.
    assert safe_fetch("https://y") == "FETCHED:https://y"
    assert calls == ["https://x", "https://y"]


def test_wrap_tool_enforces_scope_at_call_time() -> None:
    identity = _facade()
    env = identity.issue_envelope(_root_ctx())
    runtime = IdentityRuntime(identity, env)
    deny = runtime.wrap_tool(lambda: "x", required_scope="not.in.scopes")
    with pytest.raises(VerificationError):
        deny()


def test_handoff_returns_new_runtime_with_narrower_scope() -> None:
    from autonomous_identity.core.delegation_util import effective_scopes_for_actor

    identity = _facade()
    parent_env = identity.issue_envelope(_root_ctx())
    parent_runtime = IdentityRuntime(identity, parent_env)
    child_runtime = parent_runtime.handoff(
        "spiffe://example.org/agents/child",
        ["web.read"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    assert child_runtime.system_identifier == "spiffe://example.org/agents/child"
    assert effective_scopes_for_actor(child_runtime.envelope) == {"web.read"}


def test_handoff_rejects_scope_escalation() -> None:
    identity = _facade()
    env = identity.issue_envelope(_root_ctx())
    runtime = IdentityRuntime(identity, env)
    with pytest.raises(VerificationError, match="not allowed"):
        runtime.handoff(
            "spiffe://example.org/agents/child",
            ["scope.never.granted"],
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )


def test_context_manager_sets_active_envelope() -> None:
    identity = _facade()
    env = identity.issue_envelope(_root_ctx())
    runtime = IdentityRuntime(identity, env)

    @identity.material_action(action_type="web.fetch", required_scope="web.read")
    def fetch(url: str) -> str:
        return f"FETCHED:{url}"

    # Without entering the runtime: no envelope in context.
    with pytest.raises(RuntimeError, match="No identity envelope in context"):
        fetch("https://x")

    # Inside the runtime: envelope is exercised, fetch goes through the gate.
    # The decorator returns the audit dict — extract the actual result.
    with runtime:
        proof = fetch("https://x")
        assert proof["result"] == "FETCHED:https://x"
        assert proof["audit_ref"].startswith("audit://")


def test_async_callable_is_supported() -> None:
    identity = _facade()
    env = identity.issue_envelope(_root_ctx())
    runtime = IdentityRuntime(identity, env)

    async def async_compose(topic: str) -> str:
        await asyncio.sleep(0)
        return f"# {topic}"

    safe_compose = runtime.wrap_tool(async_compose, required_scope="doc.write")
    result = asyncio.run(safe_compose("renewables"))
    assert result == "# renewables"


def test_two_runtime_handoff_chain_is_monotone() -> None:
    """user → researcher → tool-runner: scopes must narrow at each hop."""
    from autonomous_identity.core.delegation_util import effective_scopes_for_actor

    identity = _facade()
    user_env = identity.issue_envelope(_root_ctx())
    user_rt = IdentityRuntime(identity, user_env)

    researcher_rt = user_rt.handoff(
        "spiffe://example.org/agents/researcher",
        ["web.read", "doc.write"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    tool_runner_rt = researcher_rt.handoff(
        "spiffe://example.org/agents/tool",
        ["web.read"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    s_user = effective_scopes_for_actor(user_rt.envelope)
    s_research = effective_scopes_for_actor(researcher_rt.envelope)
    s_tool = effective_scopes_for_actor(tool_runner_rt.envelope)
    assert s_tool <= s_research <= s_user
