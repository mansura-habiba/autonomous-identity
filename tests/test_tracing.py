"""Tests for the tracing framework.

Covers:
    * NoopTracer is truly a no-op (no side effects).
    * ConsoleTracer prints structured rows and nests spans.
    * TracedIdentity emits one span per observable hop and preserves the
      underlying AutonomousIdentity behaviour bit-for-bit.
    * Error inside ``run_material_action`` propagates and marks the span
      ``status=error`` with the exception message.
    * Telemetry hygiene: by default the span attributes do NOT include raw
      input/output payloads — only metadata + hashes.
    * Top-level operations create distinct trace_ids; nested ops share one.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import StringIO
from typing import Any

import pytest

from autonomous_identity.application.facade import AutonomousIdentity
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.crypto.ed25519 import Ed25519Signer
from autonomous_identity.storage.memory import MemoryAuditStore, MemoryLifecycleStore
from autonomous_identity.tracing import (
    BaseTracer,
    ConsoleTracer,
    NoopTracer,
    SpanContext,
    TracedIdentity,
)


# ---------- helpers ----------------------------------------------------------


class RecordingTracer(BaseTracer):
    """Captures every span so tests can assert on order, kind, and attributes."""

    def __init__(self) -> None:
        self.events: list[tuple[str, SpanContext]] = []
        self.capture_io = False

    def _emit_start(self, ctx: SpanContext) -> None:
        self.events.append(("start", ctx))

    def _emit_end(self, ctx: SpanContext, *, status: str) -> None:
        ctx.attributes["__final_status__"] = status
        self.events.append(("end", ctx))


def _facade(adapter_name: str = "spiffe") -> AutonomousIdentity:
    """Return an in-memory AutonomousIdentity for SPIFFE adapter tests."""
    from autonomous_identity.adapters.spiffe import SpiffeIdentityAdapter

    adapter = SpiffeIdentityAdapter(
        Ed25519Signer.generate(), audit_store=MemoryAuditStore()
    )
    return AutonomousIdentity(
        identity_adapter=adapter,
        lifecycle_store=MemoryLifecycleStore(),
        audit_store=MemoryAuditStore(),  # unused by SPIFFE adapter directly
        signer=Ed25519Signer.generate(),
    )


def _issue_root_ctx() -> dict[str, Any]:
    return {
        "system_identifier": "spiffe://example.org/agents/root",
        "instance_id": "i-1",
        "deployment_id": "d-1",
        "owner_id": "team:demo",
        "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
        "attestation_chain": ["local:bootstrap"],
        "issuer_scopes": ["tool.invoke", "doc.write"],
    }


# ---------- NoopTracer -------------------------------------------------------


class TestNoopTracer:
    def test_is_a_noop(self) -> None:
        tracer = NoopTracer()
        with tracer.span("anything", kind="anything", attributes={"k": "v"}) as ctx:
            assert isinstance(ctx, SpanContext)
            assert ctx.attributes["k"] == "v"

    def test_nested_spans_share_trace_id(self) -> None:
        tracer = NoopTracer()
        with tracer.span("outer", kind="x") as outer:
            with tracer.span("inner", kind="y") as inner:
                assert inner.trace_id == outer.trace_id
                assert inner.parent_id == outer.span_id


# ---------- ConsoleTracer ----------------------------------------------------


class TestConsoleTracer:
    def test_emits_start_and_end_lines(self) -> None:
        buf = StringIO()
        tracer = ConsoleTracer(stream=buf, color=False)
        with tracer.span("test.op", kind="asid.issue", attributes={"spiffe_id": "spiffe://x/y"}):
            pass
        out = buf.getvalue()
        assert "start asid.issue" in out
        assert "end   asid.issue" in out
        assert "spiffe://x/y" in out
        assert "status=ok" in out

    def test_marks_errors(self) -> None:
        buf = StringIO()
        tracer = ConsoleTracer(stream=buf, color=False)
        with pytest.raises(RuntimeError):
            with tracer.span("test.op", kind="asid.material_action", attributes={}):
                raise RuntimeError("boom")
        out = buf.getvalue()
        assert "status=error" in out
        assert "boom" in out


# ---------- TracedIdentity ---------------------------------------------------


class TestTracedIdentity:
    def test_issue_emits_one_span_with_outcome_attributes(self) -> None:
        tracer = RecordingTracer()
        ti = TracedIdentity(_facade(), tracer=tracer)
        env = ti.issue_envelope(_issue_root_ctx())

        starts = [e for e in tracer.events if e[0] == "start"]
        ends = [e for e in tracer.events if e[0] == "end"]
        assert len(starts) == 1
        assert len(ends) == 1
        ctx = ends[0][1]
        assert ctx.kind == "asid.issue"
        assert ctx.attributes["system_identifier"] == env.system_identifier
        assert ctx.attributes["trust_domain"] == "example.org"
        assert ctx.attributes["audit_ref"] == env.audit_ref
        assert ctx.attributes["__final_status__"] == "ok"

    def test_full_chain_issue_delegate_exercise_material_action(self) -> None:
        tracer = RecordingTracer()
        ti = TracedIdentity(_facade(), tracer=tracer)
        parent = ti.issue_envelope(_issue_root_ctx())
        child = ti.delegate(
            parent,
            "spiffe://example.org/agents/child",
            ["tool.invoke"],
            {},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        with ti.exercise(child):
            proof = ti.run_material_action(
                child,
                action_type="tool.call",
                required_scope="tool.invoke",
                fn=lambda x: x + 1,
                args=(41,),
                kwargs={},
            )
        assert proof["result"] == 42

        kinds = [
            e[1].kind for e in tracer.events if e[0] == "end"
        ]
        assert kinds == [
            "asid.issue",
            "asid.delegate",
            "asid.material_action",
            "asid.exercise",
        ]

    def test_material_action_inherits_exercise_trace_id(self) -> None:
        tracer = RecordingTracer()
        ti = TracedIdentity(_facade(), tracer=tracer)
        parent = ti.issue_envelope(_issue_root_ctx())
        child = ti.delegate(
            parent,
            "spiffe://example.org/agents/child",
            ["tool.invoke"],
            {},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        with ti.exercise(child):
            ti.run_material_action(
                child,
                action_type="t",
                required_scope=None,
                fn=lambda: "ok",
                args=(),
                kwargs={},
            )
        ends = [e[1] for e in tracer.events if e[0] == "end"]
        exercise = next(e for e in ends if e.kind == "asid.exercise")
        material = next(e for e in ends if e.kind == "asid.material_action")
        assert material.trace_id == exercise.trace_id
        assert material.parent_id == exercise.span_id

    def test_error_marks_material_action_span(self) -> None:
        tracer = RecordingTracer()
        ti = TracedIdentity(_facade(), tracer=tracer)
        parent = ti.issue_envelope(_issue_root_ctx())
        child = ti.delegate(
            parent,
            "spiffe://example.org/agents/child",
            ["tool.invoke"],  # no doc.write
            {},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        with ti.exercise(child):
            with pytest.raises(VerificationError):
                ti.run_material_action(
                    child,
                    action_type="t",
                    required_scope="doc.write",  # NOT in effective scopes
                    fn=lambda: "x",
                    args=(),
                    kwargs={},
                )
        material_end = next(
            e for e in tracer.events
            if e[0] == "end" and e[1].kind == "asid.material_action"
        )[1]
        assert material_end.attributes["__final_status__"] == "error"
        assert "doc.write" in (material_end.error or "")

    def test_default_does_not_capture_raw_io(self) -> None:
        tracer = RecordingTracer()  # capture_io defaults to False
        ti = TracedIdentity(_facade(), tracer=tracer)
        parent = ti.issue_envelope(_issue_root_ctx())
        child = ti.delegate(
            parent,
            "spiffe://example.org/agents/child",
            ["tool.invoke"],
            {},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        secret = {"ssn": "111-11-1111"}  # would be terrible to ship to telemetry
        with ti.exercise(child):
            ti.run_material_action(
                child,
                action_type="t",
                required_scope=None,
                fn=lambda payload: payload,
                args=(secret,),
                kwargs={},
            )
        material_end = next(
            e for e in tracer.events
            if e[0] == "end" and e[1].kind == "asid.material_action"
        )[1]
        assert "input" not in material_end.attributes
        # Output is also redacted to metadata only.
        assert "result" not in (material_end.output or {})
        assert (material_end.output or {}).get("audit_ref")

    def test_top_level_operations_get_distinct_trace_ids(self) -> None:
        tracer = RecordingTracer()
        ti = TracedIdentity(_facade(), tracer=tracer)
        parent = ti.issue_envelope(_issue_root_ctx())
        ti.delegate(
            parent,
            "spiffe://example.org/agents/child1",
            ["tool.invoke"],
            {},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        ti.delegate(
            parent,
            "spiffe://example.org/agents/child2",
            ["tool.invoke"],
            {},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        ends = [e[1] for e in tracer.events if e[0] == "end"]
        trace_ids = {e.trace_id for e in ends}
        assert len(trace_ids) == 3  # one per top-level op
