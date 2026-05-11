"""ConsoleTracer — prints structured span rows. No dependencies.

Output is intentionally compact so it's readable while a demo runs::

    [trace] start asid.issue        trace=ab12 span=cd34                  spiffe_id=spiffe://corp.example/platform
    [trace] end   asid.issue        trace=ab12 span=cd34 dur=2.1ms status=ok audit_ref=audit://file/...
    [trace] start asid.delegate     trace=ab12 span=ef56 parent=cd34      parent_subject=... child_subject=... scopes=[orchestrate,web.read,doc.write]
    [trace] end   asid.delegate     trace=ab12 span=ef56 dur=0.8ms status=ok audit_ref=audit://file/...
"""

from __future__ import annotations

import sys
import time
from typing import Any, IO

from autonomous_identity.tracing.base import BaseTracer, SpanContext


def _fmt_attr(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_fmt_attr(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(f"{k}={_fmt_attr(v)}" for k, v in value.items()) + "}"
    return str(value)


def _fmt_kvs(attrs: dict[str, Any], *, keys: list[str] | None = None) -> str:
    if keys:
        items = [(k, attrs[k]) for k in keys if k in attrs]
    else:
        items = list(attrs.items())
    return " ".join(f"{k}={_fmt_attr(v)}" for k, v in items)


# Curated subset of attributes that are useful to see inline. Anything else
# stays in the SpanContext (and gets forwarded to richer tracers) but isn't
# printed to avoid line noise.
_HEADLINE_KEYS = [
    "spiffe_id",
    "trust_domain",
    "system_identifier",
    "action_type",
    "required_scope",
    "parent_subject",
    "child_subject",
    "scopes",
    "federation",
    "audit_ref",
    "outcome",
]


class ConsoleTracer(BaseTracer):
    """Print spans to a stream (stdout by default)."""

    def __init__(
        self,
        *,
        stream: IO[str] | None = None,
        capture_io: bool = False,
        color: bool = True,
    ) -> None:
        self._stream = stream if stream is not None else sys.stdout
        self.capture_io = capture_io
        self._color = color

    def _color_for(self, kind: str, status: str) -> str:
        if not self._color:
            return ""
        if status == "error":
            return "\033[31m"  # red
        return {
            "asid.issue": "\033[36m",        # cyan
            "asid.delegate": "\033[35m",     # magenta
            "asid.exercise": "\033[33m",     # yellow
            "asid.material_action": "\033[32m",  # green
            "asid.verify": "\033[34m",       # blue
        }.get(kind, "")

    def _reset(self) -> str:
        return "\033[0m" if self._color else ""

    def _emit_start(self, ctx: SpanContext) -> None:
        c = self._color_for(ctx.kind, "ok")
        r = self._reset()
        parent = f" parent={ctx.parent_id[:4]}" if ctx.parent_id else ""
        line = (
            f"{c}[trace] start {ctx.kind:<22}{r} "
            f"trace={ctx.trace_id[:4]} span={ctx.span_id[:4]}{parent}  "
            f"{_fmt_kvs(ctx.attributes, keys=_HEADLINE_KEYS)}"
        )
        print(line, file=self._stream, flush=True)

    def _emit_end(self, ctx: SpanContext, *, status: str) -> None:
        c = self._color_for(ctx.kind, status)
        r = self._reset()
        dur_ms = (time.time_ns() - ctx.start_ns) / 1_000_000
        parent = f" parent={ctx.parent_id[:4]}" if ctx.parent_id else ""
        suffix = ""
        if status == "error" and ctx.error:
            suffix = f" error={ctx.error}"
        elif ctx.output:
            suffix = " " + _fmt_kvs(ctx.output, keys=_HEADLINE_KEYS)
        elif "audit_ref" in ctx.attributes:
            suffix = f" audit_ref={ctx.attributes['audit_ref']}"
        line = (
            f"{c}[trace] end   {ctx.kind:<22}{r} "
            f"trace={ctx.trace_id[:4]} span={ctx.span_id[:4]}{parent} "
            f"dur={dur_ms:.1f}ms status={status}{suffix}"
        )
        print(line, file=self._stream, flush=True)
