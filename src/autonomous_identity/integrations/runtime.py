"""Framework-agnostic identity runtime.

The rest of this package ships framework-specific helpers (LangChain,
LangGraph, Langflow, A2A). This module ships the **opposite** — a
framework-free object that any orchestrator can use with three lines of
glue, regardless of whether the orchestrator is CrewAI, AutoGen, Pydantic
AI, Letta, a homegrown function-call planner, or no framework at all.

Pattern
=======

::

    from autonomous_identity import AutonomousIdentity
    from autonomous_identity.integrations.runtime import IdentityRuntime

    identity = AutonomousIdentity.local(".asid", adapter_name="spiffe")
    root = identity.issue_envelope({...})

    runtime = IdentityRuntime(identity, root)

    # 1) Wrap any callable as a material action. Returns a NEW callable;
    #    the original is untouched. Works on sync or async functions.
    safe_fetch = runtime.wrap_tool(my_fetch, required_scope="web.read")

    # 2) Run a one-shot action without pre-wrapping.
    proof = runtime.run("doc.compose", "doc.write", compose, topic, research)

    # 3) Hand off to a sub-agent. Returns a NEW IdentityRuntime bound to
    #    a child envelope with strictly narrower scope.
    research_runtime = runtime.handoff(
        "spiffe://corp.example/agents/researcher",
        allowed_scopes=["web.read"],
    )

The runtime is also a context manager that opens ``identity.exercise(...)``
for the underlying envelope — so anything called inside a
``with runtime:`` block automatically runs under that envelope, including
decorator-style ``@identity.material_action(...)`` functions.

Hygiene
-------

* ``wrap_tool`` returns a new callable; it does NOT mutate the input.
  This avoids the Pydantic-v2 trap where reassigning ``.invoke`` on a
  ``BaseTool`` raises a validation error.
* ``handoff()`` enforces scope monotonicity via the underlying adapter;
  no child can hold a scope the parent did not.
* The runtime never logs raw inputs/outputs; per-action audit rows record
  hashes only (the underlying facade behavior).
"""

from __future__ import annotations

import asyncio
import inspect
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Callable, Iterator, TypeVar

from autonomous_identity.application.facade import AutonomousIdentity
from autonomous_identity.core.envelope import IdentityEnvelope

F = TypeVar("F", bound=Callable[..., Any])


class IdentityRuntime:
    """Framework-agnostic envelope + execution bundle.

    Build one per logical actor at the moment that actor starts work.
    Wrap any callable the actor will run through :meth:`wrap_tool`.
    Hand off to a sub-actor via :meth:`handoff`. Use as a context
    manager to scope ``identity.exercise(envelope)``.
    """

    def __init__(
        self,
        identity: AutonomousIdentity,
        envelope: IdentityEnvelope,
        *,
        default_action_type: str = "tool_call",
    ) -> None:
        self._identity = identity
        self._envelope = envelope
        self._default_action_type = default_action_type

    # ----- introspection ----------------------------------------------------

    @property
    def identity(self) -> AutonomousIdentity:
        return self._identity

    @property
    def envelope(self) -> IdentityEnvelope:
        return self._envelope

    @property
    def system_identifier(self) -> str:
        return self._envelope.system_identifier

    # ----- one-shot execution ----------------------------------------------

    def run(
        self,
        action_type: str,
        required_scope: str | None,
        fn: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Run ``fn(*args, **kwargs)`` as a material action under this envelope.

        Returns the same dict the underlying facade returns:
        ``{"result", "audit_ref", "system_identifier", "lifecycle_state",
        "verified_at"}``.
        """
        return self._identity.run_material_action(
            self._envelope,
            action_type=action_type,
            required_scope=required_scope,
            fn=fn,
            args=args,
            kwargs=kwargs,
        )

    async def run_async(
        self,
        action_type: str,
        required_scope: str | None,
        fn: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Async equivalent of :meth:`run`. The fn may be sync or coroutine.

        The facade is synchronous; for a coroutine we await it first to get
        the value, then ask the facade to audit the value computation. This
        keeps the per-action audit semantics intact (input/output hashes,
        envelope verification) for async callers.
        """
        if inspect.iscoroutinefunction(fn):
            result = await fn(*args, **kwargs)
            # Audit the value the coroutine produced. The facade re-verifies
            # the envelope here; if the lifecycle flipped between await-start
            # and now, this raises before recording the row.
            return self._identity.run_material_action(
                self._envelope,
                action_type=action_type,
                required_scope=required_scope,
                fn=lambda: result,
                args=(),
                kwargs={},
            )
        return self.run(action_type, required_scope, fn, *args, **kwargs)

    # ----- non-mutating wrapping -------------------------------------------

    def wrap_tool(
        self,
        fn: Callable[..., Any],
        *,
        required_scope: str | None = None,
        action_type: str | None = None,
    ) -> Callable[..., Any]:
        """Return a NEW callable that runs ``fn`` as a material action.

        Mirrors the input function's signature. Works on both sync and async
        callables — pick the right one by introspection. Does NOT mutate
        ``fn``; the original remains usable un-gated for tests.

        Use this for any framework that hands you a list of callables to
        register as tools (CrewAI, Pydantic AI, AutoGen, plain function
        orchestrators).
        """
        atype = action_type or self._default_action_type
        scope = required_scope

        if inspect.iscoroutinefunction(fn):
            async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
                proof = await self.run_async(atype, scope, fn, *args, **kwargs)
                return proof["result"]

            _async_wrapper.__name__ = getattr(fn, "__name__", "wrapped")
            _async_wrapper.__doc__ = getattr(fn, "__doc__", None)
            _async_wrapper.__wrapped__ = fn  # type: ignore[attr-defined]
            return _async_wrapper

        def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            proof = self.run(atype, scope, fn, *args, **kwargs)
            return proof["result"]

        _sync_wrapper.__name__ = getattr(fn, "__name__", "wrapped")
        _sync_wrapper.__doc__ = getattr(fn, "__doc__", None)
        _sync_wrapper.__wrapped__ = fn  # type: ignore[attr-defined]
        return _sync_wrapper

    def wrap_tools(
        self,
        tools: list[Callable[..., Any]],
        *,
        required_scope: str | None = None,
        action_type: str | None = None,
    ) -> list[Callable[..., Any]]:
        """Convenience: wrap a list of callables with the same gate."""
        return [
            self.wrap_tool(t, required_scope=required_scope, action_type=action_type)
            for t in tools
        ]

    # ----- delegation -------------------------------------------------------

    def handoff(
        self,
        child_subject: str,
        allowed_scopes: list[str],
        caveats: dict[str, Any] | None = None,
        *,
        expires_at: datetime | None = None,
        default_action_type: str | None = None,
    ) -> "IdentityRuntime":
        """Mint a child envelope and return a new runtime bound to it.

        ``allowed_scopes`` must be a subset of this runtime's effective
        scopes — the underlying adapter raises ``VerificationError`` if not.
        Caveats are forwarded to the adapter; SPIFFE federation across
        trust domains requires ``caveats['spiffe.allow_cross_trust_domain']
        = True``.
        """
        child_env = self._identity.delegate(
            self._envelope,
            child_subject,
            allowed_scopes,
            caveats or {},
            expires_at=expires_at,
        )
        return IdentityRuntime(
            self._identity,
            child_env,
            default_action_type=default_action_type or self._default_action_type,
        )

    # ----- context manager --------------------------------------------------

    @contextmanager
    def exercise(self) -> Iterator["IdentityRuntime"]:
        """Open ``identity.exercise(envelope)`` for this runtime.

        Anything inside the ``with`` block — including decorator-style
        ``@identity.material_action`` functions — runs under this envelope.
        """
        with self._identity.exercise(self._envelope):
            yield self

    def __enter__(self) -> "IdentityRuntime":
        self._cm = self._identity.exercise(self._envelope)
        self._cm.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        cm = getattr(self, "_cm", None)
        if cm is not None:
            cm.__exit__(exc_type, exc, tb)

    # ----- handoff-by-name convenience -------------------------------------

    def child(
        self,
        child_subject: str,
        *,
        allowed_scopes: list[str],
        caveats: dict[str, Any] | None = None,
        expires_at: datetime | None = None,
    ) -> "IdentityRuntime":
        """Alias for :meth:`handoff` with keyword-only call shape."""
        return self.handoff(
            child_subject,
            allowed_scopes,
            caveats=caveats,
            expires_at=expires_at,
        )
