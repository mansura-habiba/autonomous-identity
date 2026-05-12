"""LangfuseTracer — ship autonomous-identity spans to Langfuse.

Supports the Langfuse v2 (``client.trace().span()``), v3, and v4
(``client.start_as_current_observation()``) SDKs. The active SDK is detected
at construction time and the right code path is used. Setting
``ASID_TRACE_DEBUG=1`` prints diagnostics if construction fails.

Install with::

    pip install -e ".[tracing-langfuse]"

Configure via constructor args or the standard Langfuse environment
variables (``LANGFUSE_PUBLIC_KEY``, ``LANGFUSE_SECRET_KEY``, ``LANGFUSE_HOST``).

Telemetry hygiene
-----------------
Span attributes carry **identity metadata only** by default — SPIFFE ID,
trust domain, scopes, audit_ref, action_type, input/output hashes. The SVID
JWS, signatures, and raw input/output payloads are never sent. Set
``capture_io=True`` to opt into shipping raw I/O during local debugging.
"""

from __future__ import annotations

import contextvars
import os
import sys
from contextlib import contextmanager
from typing import Any, Iterator

from autonomous_identity.tracing.base import (
    BaseTracer,
    SpanContext,
    _current_span,
    _new_span_context,
)


def _debug(msg: str) -> None:
    if os.environ.get("ASID_TRACE_DEBUG"):
        print(f"[asid-trace-debug] {msg}", file=sys.stderr, flush=True)


class LangfuseTracer:
    """Forward spans to Langfuse (v2 / v3 / v4 SDKs)."""

    def __init__(
        self,
        *,
        public_key: str | None = None,
        secret_key: str | None = None,
        host: str | None = None,
        trace_name: str = "autonomous-identity",
        service_name: str = "autonomous-identity",
        capture_io: bool = False,
    ) -> None:
        # The Langfuse SDK boots OpenTelemetry under the hood. OTel reads its
        # ``service.name`` resource attribute from this env var at SDK init
        # time, which is BEFORE we get a handle on the OTel SDK. Setting it
        # here keeps the default "unknown_service" out of every span.
        os.environ.setdefault("OTEL_SERVICE_NAME", service_name)

        try:
            from langfuse import Langfuse  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "LangfuseTracer requires the langfuse package. "
                "Install with: pip install -e \".[tracing-langfuse]\""
            ) from exc

        kwargs: dict[str, Any] = {}
        pk = public_key or os.environ.get("LANGFUSE_PUBLIC_KEY")
        sk = secret_key or os.environ.get("LANGFUSE_SECRET_KEY")
        h = host or os.environ.get("LANGFUSE_HOST")
        if pk:
            kwargs["public_key"] = pk
        if sk:
            kwargs["secret_key"] = sk
        if h:
            kwargs["host"] = h
        self._client = Langfuse(**kwargs)
        self._trace_name = trace_name
        self.capture_io = capture_io

        # Detect SDK API surface.
        if hasattr(self._client, "start_as_current_observation"):
            self._api = "v4"
        elif hasattr(self._client, "start_span") or hasattr(
            self._client, "start_as_current_span"
        ):
            self._api = "v3"
        elif hasattr(self._client, "trace"):
            self._api = "v2"
        else:
            raise RuntimeError(
                "Unrecognised Langfuse SDK shape — no trace/start_span/"
                "start_as_current_observation found on client."
            )

        # Validate auth so we fail loudly instead of silently dropping spans.
        try:
            if hasattr(self._client, "auth_check"):
                ok = self._client.auth_check()
                _debug(f"langfuse auth_check={ok!r}")
        except Exception as exc:  # noqa: BLE001
            _debug(f"langfuse auth_check failed: {exc!r}")

        _debug(f"LangfuseTracer ready (api={self._api}, host={h or 'default'})")

        # v3/v4 maintain their own otel context for nesting; only v2 needs us
        # to thread a Trace handle through the spans we open.
        self._root_trace: contextvars.ContextVar[Any] = contextvars.ContextVar(
            "asid_langfuse_root_trace", default=None
        )

    @classmethod
    def from_env_or_none(
        cls,
        *,
        verbose: bool = True,
        **overrides: Any,
    ) -> "LangfuseTracer | None":
        """Return a configured tracer if Langfuse env vars are present, else ``None``.

        ``verbose=True`` (the default) prints a one-line reason when falling
        back so demos make it obvious whether Langfuse is actually wired up.
        """
        if not (
            os.environ.get("LANGFUSE_PUBLIC_KEY")
            and os.environ.get("LANGFUSE_SECRET_KEY")
        ):
            if verbose:
                missing = [
                    n for n in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY")
                    if not os.environ.get(n)
                ]
                print(
                    f"[asid] LangfuseTracer disabled — missing env vars: "
                    f"{', '.join(missing)}",
                    file=sys.stderr,
                )
            return None
        try:
            return cls(**overrides)
        except Exception as exc:  # noqa: BLE001
            if verbose:
                print(
                    f"[asid] LangfuseTracer construction failed ({type(exc).__name__}: {exc});"
                    f" falling back. Set ASID_TRACE_DEBUG=1 for details.",
                    file=sys.stderr,
                )
            _debug(f"construction error: {exc!r}")
            return None

    # ------------------------------------------------------------------
    # Span emission
    # ------------------------------------------------------------------

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
        try:
            with self._open_lf_span(ctx) as lf_span:
                try:
                    yield ctx
                except BaseException as exc:
                    ctx.error = f"{type(exc).__name__}: {exc}"
                    self._finish_lf_span(lf_span, ctx, status="error")
                    raise
                else:
                    self._finish_lf_span(lf_span, ctx, status="ok")
        finally:
            _current_span.reset(token)
            # Flush at end of root span so the SaaS sees data promptly.
            if ctx.parent_id is None:
                try:
                    self._client.flush()
                    _debug("flushed")
                except Exception as exc:  # noqa: BLE001
                    _debug(f"flush failed: {exc!r}")

    @contextmanager
    def _open_lf_span(self, ctx: SpanContext) -> Iterator[Any]:
        meta = _safe_metadata(ctx)
        inp = _safe_input(ctx, capture_io=self.capture_io)

        if self._api == "v4":
            cm = self._client.start_as_current_observation(
                name=ctx.name,
                as_type="span",
                input=inp,
                metadata=meta,
            )
            with cm as lf_span:
                yield lf_span
        elif self._api == "v3":
            cm_fn = getattr(self._client, "start_as_current_span", None)
            if cm_fn is None:
                # v3 without context manager — open a span explicitly.
                span = self._client.start_span(name=ctx.name, input=inp, metadata=meta)
                try:
                    yield span
                finally:
                    try:
                        span.end()
                    except Exception:  # pragma: no cover
                        pass
            else:
                with cm_fn(name=ctx.name, input=inp, metadata=meta) as span:
                    yield span
        elif self._api == "v2":
            parent_trace = self._root_trace.get()
            is_root = parent_trace is None
            if is_root:
                parent_trace = self._client.trace(
                    id=ctx.trace_id,
                    name=ctx.attributes.get("trace_name", self._trace_name),
                    metadata=meta,
                )
                self._root_trace.set(parent_trace)
            try:
                span = parent_trace.span(
                    id=ctx.span_id,
                    name=ctx.name,
                    input=inp,
                    metadata=meta,
                )
                yield span
            finally:
                if is_root:
                    self._root_trace.set(None)
        else:  # pragma: no cover
            raise RuntimeError(f"Unknown Langfuse API tier: {self._api}")

    def _finish_lf_span(
        self,
        lf_span: Any,
        ctx: SpanContext,
        *,
        status: str,
    ) -> None:
        """Attach output / metadata / level before the span's context exits.

        For v4 (``start_as_current_observation``) and v3
        (``start_as_current_span``) the surrounding ``with`` closes the span
        automatically. For older SDKs we end it manually below.
        """
        output = _safe_output(ctx, capture_io=self.capture_io)
        update_kwargs: dict[str, Any] = {"metadata": _safe_metadata(ctx)}
        if output is not None:
            update_kwargs["output"] = output
        if status == "error":
            update_kwargs["level"] = "ERROR"
            update_kwargs["status_message"] = ctx.error

        try:
            if hasattr(lf_span, "update"):
                lf_span.update(**update_kwargs)
            elif hasattr(lf_span, "end"):
                lf_span.end(**update_kwargs)
                return
        except TypeError as exc:
            _debug(f"lf_span.update kwargs not all accepted: {exc}")
            try:
                lf_span.update(output=output)  # type: ignore[call-arg]
            except Exception:  # pragma: no cover
                pass
        except Exception as exc:  # noqa: BLE001
            _debug(f"lf_span.update failed: {exc!r}")

        # v3/v4 context managers end the span automatically on __exit__; only
        # explicitly call .end() when we opened the span without a context.
        if self._api == "v3" and not hasattr(self._client, "start_as_current_span"):
            if hasattr(lf_span, "end"):
                try:
                    lf_span.end()
                except Exception:  # pragma: no cover
                    pass


# ----- payload shaping -------------------------------------------------------


# Attribute keys that never leave the process even when ``capture_io=True``.
# These are signature material — they have no analytical value in
# observability and shipping them widens the credential blast radius.
_NEVER_SHIP = {
    "signature",
    "signature_b64",
    "private_key",
    "spiffe.svid_jws",  # the SVID itself
    "spiffe.svid_jti",
}


# Per-span-kind allowlist. Anything not on this list is dropped before the
# metadata is shipped to Langfuse. Trace-correlation fields (trace_id,
# span_id, parent_id) are NOT included — Langfuse already attaches its own
# OTel-level trace/span identifiers, so duplicating them in metadata is
# pure noise. ``kind`` is always shipped.
_KIND_ALLOWLIST: dict[str, frozenset[str]] = {
    "asid.issue": frozenset({
        # WHO + WHERE
        "spiffe_id", "system_identifier", "trust_domain",
        "owner_id", "adapter", "issuer_scopes",
        # WHICH EXECUTION  (runtime instance)
        "instance_id", "deployment_id", "environment", "region",
        # WHAT PRODUCED IT  (provenance)
        "code_hash", "policy_bundle_hash", "model_hash", "config_hash",
        # HOW DO WE KNOW
        "attestation_chain", "kid",
        # UNTIL WHEN
        "svid_exp",
        # AUDIT
        "audit_ref",
    }),
    "asid.delegate": frozenset({
        # delegation edge itself
        "parent_subject", "child_subject", "scopes", "federation",
        "expires_at", "caveat_keys",
        # resulting child identity (full envelope view)
        "spiffe_id", "system_identifier", "trust_domain",
        "owner_id", "delegation_depth",
        "instance_id", "deployment_id", "environment", "region",
        "code_hash", "policy_bundle_hash", "model_hash", "config_hash",
        "attestation_chain", "kid", "svid_exp",
        # audit
        "audit_ref",
    }),
    "asid.exercise": frozenset({
        "spiffe_id", "system_identifier", "trust_domain",
        "lifecycle_state",
    }),
    "asid.material_action": frozenset({
        # who's acting + with what authority
        "action_type", "required_scope",
        "spiffe_id", "system_identifier", "trust_domain", "owner_id",
        # what the action did, fingerprinted
        "input_hash", "output_hash",
        # when the envelope was re-verified
        "verified_at",
        # audit
        "audit_ref",
    }),
    "asid.verify": frozenset({"audit_ref", "outcome"}),
    "asid.revoke": frozenset({"system_identifier", "spiffe_id", "reason"}),
}


def _safe_metadata(ctx: SpanContext) -> dict[str, Any]:
    """Build the metadata dict that's sent to Langfuse.

    Drops everything not on the per-kind allowlist and everything in
    ``_NEVER_SHIP``. The Langfuse UI already shows OTel ``trace_id`` and
    ``span_id`` natively, so we don't duplicate them in metadata.
    """
    allowed = _KIND_ALLOWLIST.get(ctx.kind)
    out: dict[str, Any] = {"kind": ctx.kind}
    for k, v in ctx.attributes.items():
        if k in _NEVER_SHIP:
            continue
        if allowed is not None and k not in allowed:
            continue
        if v is None or v == "" or v == []:
            # Drop empty values so the UI panel stays readable.
            continue
        out[k] = v
    return out


def _safe_input(ctx: SpanContext, *, capture_io: bool) -> dict[str, Any] | None:
    raw_input = ctx.attributes.get("input")
    if raw_input is None:
        return None
    if capture_io:
        return _redact(raw_input)
    h = ctx.attributes.get("input_hash")
    return {"input_hash": h} if h else None


def _safe_output(ctx: SpanContext, *, capture_io: bool) -> dict[str, Any] | None:
    if ctx.output is None:
        return None
    if capture_io:
        return _redact(ctx.output)
    keep = {"audit_ref", "system_identifier", "output_hash", "lifecycle_state"}
    return {k: v for k, v in ctx.output.items() if k in keep}


def _redact(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {k: _redact(v) for k, v in payload.items() if k not in _NEVER_SHIP}
    if isinstance(payload, list):
        return [_redact(v) for v in payload]
    return payload
