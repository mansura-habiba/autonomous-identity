"""TracedIdentity — wrap :class:`AutonomousIdentity` with span emission.

Drop-in replacement: every method on :class:`AutonomousIdentity` is exposed
here, but with spans around the observable hops:

    asid.issue            — issue_envelope
    asid.delegate         — delegate
    asid.exercise         — exercise(...) context
    asid.material_action  — run_material_action (and decorator path)
    asid.verify           — verify_audit_ref
    asid.revoke           — revoke

Span attributes carry identity *metadata only* by default — SPIFFE ID,
trust domain, scopes, audit_ref, action_type, input/output hashes — never
raw payloads. Set ``tracer.capture_io = True`` if you genuinely want
input/output bodies in your telemetry backend.

This wrapper does NOT modify the core facade or adapters; existing tests
keep passing.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Iterator, TypeVar

from autonomous_identity.application.facade import AutonomousIdentity
from autonomous_identity.core.envelope import IdentityEnvelope
from autonomous_identity.core.validators import ValidatorStrictness
from autonomous_identity.tracing.base import NoopTracer, Tracer

F = TypeVar("F", bound=Callable[..., Any])


def _spiffe_attrs(envelope: IdentityEnvelope) -> dict[str, Any]:
    """Pull out the headline attributes for any envelope-bearing span."""
    md = envelope.metadata or {}
    return {
        "system_identifier": envelope.system_identifier,
        "spiffe_id": md.get("spiffe.id"),
        "trust_domain": md.get("spiffe.trust_domain"),
        "lifecycle_state": envelope.lifecycle_state,
        "delegation_depth": len(envelope.delegations),
    }


class TracedIdentity:
    """Span-emitting wrapper around :class:`AutonomousIdentity`.

    Pass any :class:`~autonomous_identity.tracing.base.Tracer` implementation;
    :class:`~autonomous_identity.tracing.base.NoopTracer` is used by default,
    which gives you zero overhead until you opt in.
    """

    def __init__(
        self,
        identity: AutonomousIdentity,
        tracer: Tracer | None = None,
    ) -> None:
        self._identity = identity
        self._tracer: Tracer = tracer if tracer is not None else NoopTracer()

    # ----- constructors mirroring AutonomousIdentity --------------------------

    @classmethod
    def local(
        cls,
        data_dir: str | Path,
        *,
        backend: str = "file",
        adapter_name: str = "merkle_chain",
        strictness: ValidatorStrictness = ValidatorStrictness.STRICT,
        tracer: Tracer | None = None,
    ) -> "TracedIdentity":
        return cls(
            AutonomousIdentity.local(
                data_dir,
                backend=backend,
                adapter_name=adapter_name,
                strictness=strictness,
            ),
            tracer=tracer,
        )

    # ----- core operations ----------------------------------------------------

    def issue_envelope(self, context: dict[str, Any]) -> IdentityEnvelope:
        with self._tracer.span(
            "asid.issue",
            kind="asid.issue",
            attributes={
                "system_identifier": context.get("system_identifier"),
                "owner_id": context.get("owner_id"),
                "issuer_scopes": list(context.get("issuer_scopes") or []),
                "adapter": getattr(self._identity._adapter, "name", "?"),  # noqa: SLF001
            },
        ) as span:
            envelope = self._identity.issue_envelope(context)
            attrs = _spiffe_attrs(envelope)
            span.update(**attrs)
            span.set("audit_ref", envelope.audit_ref)
            span.set_output(
                {**attrs, "audit_ref": envelope.audit_ref}
            )
            return envelope

    def delegate(
        self,
        envelope: IdentityEnvelope,
        child_subject: str,
        allowed_scopes: list[str],
        caveats: dict[str, Any] | None = None,
        *,
        expires_at: datetime | None = None,
    ) -> IdentityEnvelope:
        caveats = caveats or {}
        with self._tracer.span(
            "asid.delegate",
            kind="asid.delegate",
            attributes={
                "parent_subject": envelope.system_identifier,
                "child_subject": child_subject,
                "scopes": list(allowed_scopes),
                "federation": bool(caveats.get("spiffe.allow_cross_trust_domain")),
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        ) as span:
            child = self._identity.delegate(
                envelope,
                child_subject,
                allowed_scopes,
                caveats,
                expires_at=expires_at,
            )
            attrs = _spiffe_attrs(child)
            span.update(**attrs)
            span.set("audit_ref", child.audit_ref)
            span.set_output(
                {**attrs, "audit_ref": child.audit_ref}
            )
            return child

    def revoke(self, system_identifier: str, reason: str) -> None:
        with self._tracer.span(
            "asid.revoke",
            kind="asid.revoke",
            attributes={
                "system_identifier": system_identifier,
                "reason": reason,
            },
        ) as span:
            self._identity.revoke(system_identifier, reason)
            span.set_output({"system_identifier": system_identifier, "outcome": "revoked"})

    def verify_audit_ref(self, audit_ref: str) -> None:
        with self._tracer.span(
            "asid.verify",
            kind="asid.verify",
            attributes={"audit_ref": audit_ref},
        ) as span:
            self._identity.verify_audit_ref(audit_ref)
            span.set_output({"audit_ref": audit_ref, "outcome": "verified"})

    def inspect_audit(self, audit_ref: str) -> dict[str, Any] | None:
        return self._identity.inspect_audit(audit_ref)

    @contextmanager
    def exercise(self, envelope: IdentityEnvelope) -> Iterator[None]:
        with self._tracer.span(
            "asid.exercise",
            kind="asid.exercise",
            attributes=_spiffe_attrs(envelope),
        ):
            with self._identity.exercise(envelope):
                yield

    def material_action(
        self,
        *,
        action_type: str,
        required_scope: str | None = None,
    ) -> Callable[[F], F]:
        wrapped_decorator = self._identity.material_action(
            action_type=action_type, required_scope=required_scope
        )

        def decorator(fn: F) -> F:
            traced_fn = wrapped_decorator(fn)

            @wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Pull the active envelope so we can attribute the span. The
                # core facade already requires it via its contextvar; we just
                # peek at it for span metadata.
                envelope = AutonomousIdentity._envelope_ctx.get()  # noqa: SLF001
                attrs: dict[str, Any] = {
                    "action_type": action_type,
                    "required_scope": required_scope,
                }
                if envelope is not None:
                    attrs.update(_spiffe_attrs(envelope))
                with self._tracer.span(
                    "asid.material_action",
                    kind="asid.material_action",
                    attributes=attrs,
                ) as span:
                    proof = traced_fn(*args, **kwargs)
                    # ``traced_fn`` returns whatever the underlying fn returned
                    # — the audit metadata is reachable via ``inspect_audit``
                    # if needed. But the decorator path doesn't surface the
                    # audit_ref, so we don't either.
                    span.set_output({"action_type": action_type})
                    return proof

            return wrapper  # type: ignore[return-value]

        return decorator

    def run_material_action(
        self,
        envelope: IdentityEnvelope,
        *,
        action_type: str,
        required_scope: str | None,
        fn: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        attrs = {
            "action_type": action_type,
            "required_scope": required_scope,
            **_spiffe_attrs(envelope),
        }
        with self._tracer.span(
            "asid.material_action",
            kind="asid.material_action",
            attributes=attrs,
        ) as span:
            # Capture inputs only if the tracer was explicitly opted in.
            if getattr(self._tracer, "capture_io", False):
                span.set("input", {"args": list(args), "kwargs": kwargs})
            proof = self._identity.run_material_action(
                envelope,
                action_type=action_type,
                required_scope=required_scope,
                fn=fn,
                args=args,
                kwargs=kwargs,
            )
            span.set("audit_ref", proof["audit_ref"])
            span.set_output(
                {
                    "audit_ref": proof["audit_ref"],
                    "system_identifier": proof["system_identifier"],
                    "lifecycle_state": proof["lifecycle_state"],
                }
            )
            return proof

    # ----- escape hatch for adapter / store access ----------------------------

    @property
    def underlying(self) -> AutonomousIdentity:
        return self._identity

    # Forwarders for the few private attrs the existing demos peek at.

    @property
    def _adapter(self):  # noqa: D401, ANN201
        return self._identity._adapter  # noqa: SLF001

    @property
    def _lifecycle(self):  # noqa: D401, ANN201
        return self._identity._lifecycle  # noqa: SLF001
