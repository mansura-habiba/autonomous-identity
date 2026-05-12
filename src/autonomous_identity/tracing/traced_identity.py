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
    """Headline identity attributes for any envelope-bearing span.

    Returns the **always-relevant** subset: who this actor is, what trust
    domain it belongs to, whether the lifecycle is interesting. For the
    deeper "what produced it / which execution / who's accountable" view,
    see :func:`_envelope_full_attrs` which is used on issue and delegate
    spans where the answer to those questions is the whole point.

    Telemetry hygiene rules applied here:

    * If the envelope was minted by the SPIFFE adapter, ``system_identifier``
      equals ``metadata['spiffe.id']``. We emit the SPIFFE-flavoured field
      name only (``spiffe_id``) so the same value isn't shipped twice.
    * ``lifecycle_state`` is dropped from spans when it's the default
      ``"active"``. It only appears in the metadata when the envelope is
      in an unusual state (``restricted`` / ``suspended`` / ``revoked`` /
      ``retired``), which is where the field carries operational meaning.
    """
    md = envelope.metadata or {}
    spiffe_id = md.get("spiffe.id")
    attrs: dict[str, Any] = {}
    if spiffe_id:
        attrs["spiffe_id"] = spiffe_id
        if envelope.system_identifier != spiffe_id:
            attrs["system_identifier"] = envelope.system_identifier
    else:
        attrs["system_identifier"] = envelope.system_identifier
    td = md.get("spiffe.trust_domain")
    if td:
        attrs["trust_domain"] = td
    if envelope.lifecycle_state and envelope.lifecycle_state != "active":
        attrs["lifecycle_state"] = envelope.lifecycle_state
    if envelope.delegations:
        attrs["delegation_depth"] = len(envelope.delegations)
    return attrs


def _envelope_full_attrs(envelope: IdentityEnvelope) -> dict[str, Any]:
    """Headline attrs PLUS runtime instance, owner, provenance, SVID expiry.

    These are the attributes that make the 8-property envelope visually
    demonstrable in a trace pane. Used on issue / delegate spans where the
    question being answered is "which execution acted, who produced it,
    who owns it, until when".
    """
    attrs = _spiffe_attrs(envelope)
    ri = envelope.runtime_instance
    if ri is not None:
        if ri.instance_id:
            attrs["instance_id"] = ri.instance_id
        if ri.deployment_id:
            attrs["deployment_id"] = ri.deployment_id
        if ri.environment and ri.environment != "dev":
            attrs["environment"] = ri.environment
        if ri.region and ri.region != "local":
            attrs["region"] = ri.region
    ob = envelope.owner_binding
    if ob is not None and ob.owner_id:
        attrs["owner_id"] = ob.owner_id
    prov = envelope.provenance
    if prov is not None:
        if prov.code_hash:
            attrs["code_hash"] = prov.code_hash
        if prov.policy_bundle_hash:
            attrs["policy_bundle_hash"] = prov.policy_bundle_hash
        if prov.model_hash:
            attrs["model_hash"] = prov.model_hash
        if prov.config_hash:
            attrs["config_hash"] = prov.config_hash
    if envelope.attestation_chain:
        # Cap at 4 so the metadata pane doesn't explode for long chains.
        chain = list(envelope.attestation_chain)
        attrs["attestation_chain"] = chain[:4] + (
            ["…"] if len(chain) > 4 else []
        )
    md = envelope.metadata or {}
    svid_exp = md.get("spiffe.svid_exp")
    if svid_exp:
        # int unix-seconds → ISO so the UI doesn't show a raw timestamp.
        from datetime import datetime, timezone

        try:
            attrs["svid_exp"] = (
                datetime.fromtimestamp(int(svid_exp), tz=timezone.utc).isoformat()
            )
        except (TypeError, ValueError):
            attrs["svid_exp"] = str(svid_exp)
    kid = md.get("spiffe.kid")
    if kid:
        attrs["kid"] = kid
    return attrs


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
            attrs = _envelope_full_attrs(envelope)
            span.update(**attrs)
            span.set("audit_ref", envelope.audit_ref)
            span.set_output({**attrs, "audit_ref": envelope.audit_ref})
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
            attrs = _envelope_full_attrs(child)
            # Also surface the redacted caveats so the delegation rationale
            # ("why was this hop allowed?") is visible in the trace.
            caveat_keys = [
                k for k in caveats.keys()
                if "key" not in k.lower() and "secret" not in k.lower()
            ]
            if caveat_keys:
                attrs["caveat_keys"] = caveat_keys
            span.update(**attrs)
            span.set("audit_ref", child.audit_ref)
            span.set_output({**attrs, "audit_ref": child.audit_ref})
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
        attrs: dict[str, Any] = {
            "action_type": action_type,
            "required_scope": required_scope,
            **_spiffe_attrs(envelope),
        }
        # Surface the owner on every material action so accountability is
        # visible in the trace without clicking into the issue span.
        ob = envelope.owner_binding
        if ob is not None and ob.owner_id:
            attrs["owner_id"] = ob.owner_id
        with self._tracer.span(
            "asid.material_action",
            kind="asid.material_action",
            attributes=attrs,
        ) as span:
            # Compute input hash up-front so it's on the span even if the
            # downstream fn raises before the facade gets to record it.
            from autonomous_identity.core.hashing import hash_canonical  # noqa: PLC0415

            try:
                input_hash = hash_canonical({"args": list(args), "kwargs": kwargs})
                span.set("input_hash", input_hash)
            except Exception:  # noqa: BLE001
                pass

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
            # Output hash is what the audit log records. Replay it on the span
            # so a verifier can cross-check the trace against the audit row.
            try:
                output_hash = hash_canonical(proof["result"])
                span.set("output_hash", output_hash)
            except Exception:  # noqa: BLE001
                pass

            span.set("audit_ref", proof["audit_ref"])
            if proof.get("verified_at"):
                span.set("verified_at", proof["verified_at"])
            span.set_output(
                {
                    "audit_ref": proof["audit_ref"],
                    "system_identifier": proof["system_identifier"],
                    "lifecycle_state": proof["lifecycle_state"],
                    "verified_at": proof.get("verified_at"),
                    "output_hash": span.attributes.get("output_hash"),
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
