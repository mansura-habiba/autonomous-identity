"""Tracer protocol + base types for autonomous-identity observability.

The library does not depend on any particular tracing framework. Adapters are
shipped for ``langfuse`` (SaaS LLM observability) and ``opentelemetry`` (any
OTel collector). New tracers only need to implement the small protocol below.

Telemetry hygiene
-----------------
Span attributes carry **identity metadata only**: SPIFFE ID, trust domain,
effective scopes, action type, required scope, input/output *hashes*, and
audit_ref. **No raw input/output payloads, envelope JSON, or signature
material is sent to telemetry by default.** Setting ``capture_io=True`` on a
tracer opts a deployment into shipping raw I/O — useful for local debugging
but generally NOT what you want for production observability.
"""

from __future__ import annotations

import contextvars
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator, Protocol


@dataclass
class SpanContext:
    """Mutable handle yielded from :meth:`Tracer.span`.

    Callers may mutate ``attributes`` and ``output`` before the span ends.
    Tracers read both at end-of-span and ship them to their backend.
    """

    name: str
    kind: str
    span_id: str
    trace_id: str
    parent_id: str | None
    start_ns: int
    attributes: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] | None = None
    error: str | None = None

    def set(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def update(self, **kwargs: Any) -> None:
        self.attributes.update(kwargs)

    def set_output(self, output: dict[str, Any]) -> None:
        self.output = output


class Tracer(Protocol):
    """Minimal protocol every tracer adapter implements."""

    capture_io: bool

    def span(
        self,
        name: str,
        *,
        kind: str,
        attributes: dict[str, Any] | None = None,
    ) -> Iterator[SpanContext]:
        """Context manager that opens a span and emits it on close."""


# ----- shared scaffolding ----------------------------------------------------


_current_span: contextvars.ContextVar[SpanContext | None] = contextvars.ContextVar(
    "autonomous_identity_current_span", default=None
)


def _new_span_context(name: str, kind: str, attributes: dict[str, Any] | None) -> SpanContext:
    parent = _current_span.get()
    trace_id = parent.trace_id if parent is not None else uuid.uuid4().hex
    return SpanContext(
        name=name,
        kind=kind,
        span_id=uuid.uuid4().hex,
        trace_id=trace_id,
        parent_id=parent.span_id if parent is not None else None,
        start_ns=time.time_ns(),
        attributes=dict(attributes or {}),
    )


class BaseTracer:
    """Common ``span()`` scaffolding for sync tracers.

    Subclasses only need to implement :meth:`_emit_start` and :meth:`_emit_end`.
    The ``capture_io`` flag is honored at the call sites that record I/O.
    """

    capture_io: bool = False

    @contextmanager
    def span(
        self,
        name: str,
        *,
        kind: str,
        attributes: dict[str, Any] | None = None,
    ) -> Iterator[SpanContext]:
        ctx = _new_span_context(name, kind, attributes)
        token = _current_span.set(ctx)
        self._emit_start(ctx)
        try:
            yield ctx
        except BaseException as exc:
            ctx.error = f"{type(exc).__name__}: {exc}"
            self._emit_end(ctx, status="error")
            _current_span.reset(token)
            raise
        else:
            self._emit_end(ctx, status="ok")
            _current_span.reset(token)

    # subclasses override -----------------------------------------------------

    def _emit_start(self, ctx: SpanContext) -> None:  # pragma: no cover - override
        ...

    def _emit_end(self, ctx: SpanContext, *, status: str) -> None:  # pragma: no cover
        ...


class NoopTracer(BaseTracer):
    """Default tracer — zero overhead, zero side effects."""

    def _emit_start(self, ctx: SpanContext) -> None:
        return None

    def _emit_end(self, ctx: SpanContext, *, status: str) -> None:
        return None
