"""Tracing adapters for autonomous-identity.

Public surface:
    - :class:`Tracer`, :class:`SpanContext`, :class:`NoopTracer` — base types.
    - :class:`ConsoleTracer` — zero-dep tracer that prints structured rows.
    - :class:`LangfuseTracer` — Langfuse adapter (lazy import).
    - :class:`TracedIdentity` — wrap :class:`AutonomousIdentity` with tracing
      without modifying the core facade.
"""

from autonomous_identity.tracing.base import (
    BaseTracer,
    NoopTracer,
    SpanContext,
    Tracer,
)
from autonomous_identity.tracing.console import ConsoleTracer
from autonomous_identity.tracing.traced_identity import TracedIdentity

__all__ = [
    "BaseTracer",
    "ConsoleTracer",
    "NoopTracer",
    "SpanContext",
    "TracedIdentity",
    "Tracer",
]


def __getattr__(name: str):  # pragma: no cover - lazy-loads optional adapter
    if name == "LangfuseTracer":
        from autonomous_identity.tracing.langfuse_tracer import LangfuseTracer

        return LangfuseTracer
    raise AttributeError(f"module 'autonomous_identity.tracing' has no attribute {name!r}")
