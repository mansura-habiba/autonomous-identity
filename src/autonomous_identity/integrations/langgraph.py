"""LangGraph helpers: bind each node to an ``IdentityEnvelope`` without boilerplate.

Use :func:`wrap_langgraph_node` when registering nodes, or :func:`langgraph_identity`
as a decorator. Both wrap sync or async callables so the body runs inside
``with identity.exercise(envelope):``.

**Fixed envelope** (typical after you have ``envs["research"]`` from delegation)::

    graph.add_node(
        "research",
        wrap_langgraph_node(identity, envs["research"], do_research),
    )

**Envelope from state** (e.g. state carries a map of agent roles to envelopes)::

    graph.add_node(
        "research",
        wrap_langgraph_node(identity, lambda s: s["envelopes"]["research"], do_research),
    )

Decorator style::

    @langgraph_identity(identity, envs["platform"])
    def node_platform(state: GraphState) -> dict[str, Any]:
        ...

Build envelopes at **invoke** time from JSON-like data using
:func:`autonomous_identity.application.delegation_chain.issue_and_delegate_tree`,
store them on ``state["envelopes"]``, then bind nodes with
``wrap_langgraph_node(identity, lambda s: s["envelopes"]["research"], fn)``.

This module does **not** import LangGraph; it only wraps callables you pass to
``StateGraph.add_node``. No extra dependency beyond your own ``langgraph`` install.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from autonomous_identity.application.facade import AutonomousIdentity
from autonomous_identity.core.envelope import IdentityEnvelope

EnvelopeSource = IdentityEnvelope | Callable[[Any], IdentityEnvelope]
StateT = TypeVar("StateT")

F = TypeVar("F", bound=Callable[..., Any])


def _resolve_envelope(source: EnvelopeSource, state: Any) -> IdentityEnvelope:
    if isinstance(source, IdentityEnvelope):
        return source
    return source(state)


def wrap_langgraph_node(
    identity: AutonomousIdentity,
    envelope: EnvelopeSource,
    fn: F,
) -> F:
    """Return ``fn`` wrapped so each invocation runs under ``identity.exercise(<envelope>)``.

    Supports sync and async ``fn``. ``envelope`` may be a fixed :class:`IdentityEnvelope`
    or a callable ``state -> IdentityEnvelope`` (for multi-agent graphs that store
    envelopes on ``state``).
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapped(state: StateT) -> Any:
            with identity.exercise(_resolve_envelope(envelope, state)):
                return await fn(state)

        return async_wrapped  # type: ignore[return-value]

    @functools.wraps(fn)
    def sync_wrapped(state: StateT) -> Any:
        with identity.exercise(_resolve_envelope(envelope, state)):
            return fn(state)

    return sync_wrapped  # type: ignore[return-value]


def langgraph_identity(
    identity: AutonomousIdentity,
    envelope: EnvelopeSource,
) -> Callable[[F], F]:
    """Decorator factory: ``@langgraph_identity(identity, env)`` on a node function."""

    def decorator(fn: F) -> F:
        return wrap_langgraph_node(identity, envelope, fn)

    return decorator
