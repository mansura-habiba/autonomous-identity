from __future__ import annotations

import contextvars
from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar

from autonomous_identity.adapters.registry import get_adapter
from autonomous_identity.application.config import build_stores_from_config, load_yaml_config
from autonomous_identity.core.delegation_util import ensure_delegations_not_expired, effective_scopes_for_actor
from autonomous_identity.core.envelope import IdentityEnvelope
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.core.scope_convention import validate_required_scope
from autonomous_identity.core.hashing import hash_canonical
from autonomous_identity.core.validators import IdentityValidator, ValidatorStrictness
from autonomous_identity.crypto.ed25519 import Ed25519Signer

F = TypeVar("F", bound=Callable[..., Any])


class AutonomousIdentity:
    """Main entry: configurable identity adapter + lifecycle + audit + validation."""

    _envelope_ctx: contextvars.ContextVar[IdentityEnvelope | None] = contextvars.ContextVar(
        "autonomous_identity_envelope", default=None
    )

    def __init__(
        self,
        *,
        identity_adapter: Any,
        lifecycle_store: Any,
        audit_store: Any,
        signer: Ed25519Signer,
        strictness: ValidatorStrictness = ValidatorStrictness.STRICT,
        enforce_scope_convention: bool = False,
    ) -> None:
        self._adapter = identity_adapter
        self._lifecycle = lifecycle_store
        self._audit = audit_store
        self._signer = signer
        self._validator = IdentityValidator(
            strictness=strictness,
            enforce_scope_convention=enforce_scope_convention,
        )

    @classmethod
    def local(
        cls,
        data_dir: str | Path,
        *,
        backend: str = "file",
        adapter_name: str = "merkle_chain",
        strictness: ValidatorStrictness = ValidatorStrictness.STRICT,
        enforce_scope_convention: bool = False,
    ) -> AutonomousIdentity:
        data_dir = Path(data_dir)
        cfg: dict[str, Any] = {
            "identity": {"adapter": adapter_name},
            "storage": {"backend": backend, "data_dir": str(data_dir)},
        }
        if enforce_scope_convention:
            cfg["identity"]["enforce_scope_convention"] = True
        return cls.from_config_dict(cfg, strictness=strictness)

    @classmethod
    def from_config(cls, path: str | Path, *, strictness: ValidatorStrictness = ValidatorStrictness.STRICT) -> AutonomousIdentity:
        return cls.from_config_dict(load_yaml_config(path), strictness=strictness)

    @classmethod
    def from_config_dict(cls, cfg: dict[str, Any], *, strictness: ValidatorStrictness = ValidatorStrictness.STRICT) -> AutonomousIdentity:
        lifecycle_store, audit_store = build_stores_from_config(cfg)
        adapter_name = (cfg.get("identity") or {}).get("adapter", "merkle_chain")
        key_path = cfg.get("crypto", {}).get("private_key_pem")
        if key_path:
            signer = Ed25519Signer.from_pem_file(Path(key_path))
        else:
            data_hint = (cfg.get("storage") or {}).get("data_dir")
            if data_hint and (cfg.get("storage") or {}).get("backend") in (None, "file", "memory"):
                p = Path(data_hint)
                p.mkdir(parents=True, exist_ok=True)
                key_file = p / "signing_key.pem"
                if key_file.exists():
                    signer = Ed25519Signer.from_pem_file(key_file)
                else:
                    signer = Ed25519Signer.generate()
                    signer.write_pem_file(key_file)
            else:
                signer = Ed25519Signer.generate()
        deps = {"signer": signer, "audit_store": audit_store, "lifecycle_store": lifecycle_store}
        adapter = get_adapter(adapter_name, deps)
        enforce_scope = bool((cfg.get("identity") or {}).get("enforce_scope_convention", False))
        return cls(
            identity_adapter=adapter,
            lifecycle_store=lifecycle_store,
            audit_store=audit_store,
            signer=signer,
            strictness=strictness,
            enforce_scope_convention=enforce_scope,
        )

    def issue_envelope(self, context: dict[str, Any]) -> IdentityEnvelope:
        envelope = self._adapter.issue(context)
        self._validator.validate(envelope)
        if not self._adapter.verify(envelope):
            raise VerificationError("Issued envelope failed verification")
        self._lifecycle.set_lifecycle(envelope.system_identifier, envelope.lifecycle_state, reason=None)
        return envelope

    def revoke(self, system_identifier: str, reason: str) -> None:
        self._lifecycle.set_lifecycle(system_identifier, "revoked", reason=reason)
        self._adapter.revoke(system_identifier, reason)

    def delegate(
        self,
        envelope: IdentityEnvelope,
        child_subject: str,
        allowed_scopes: list[str],
        caveats: dict[str, Any] | None = None,
        *,
        expires_at: datetime | None = None,
    ) -> IdentityEnvelope:
        """Hand off narrowed authority to child_subject; returns a new envelope for the child."""
        child = self._adapter.delegate(
            envelope,
            child_subject,
            allowed_scopes,
            caveats or {},
            expires_at=expires_at,
        )
        self._validator.validate(child)
        if not self._adapter.verify(child):
            raise VerificationError("Delegated envelope failed verification")
        self._lifecycle.set_lifecycle(child.system_identifier, child.lifecycle_state, reason=None)
        return child

    def verify_audit_ref(self, audit_ref: str) -> None:
        if hasattr(self._adapter, "verify_chain_event"):
            self._adapter.verify_chain_event(audit_ref)
            return
        event = self._audit.get(audit_ref)
        if not event:
            raise VerificationError("Unknown audit reference")

    def inspect_audit(self, audit_ref: str) -> dict[str, Any] | None:
        return self._audit.get(audit_ref)

    @contextmanager
    def exercise(self, envelope: IdentityEnvelope):
        token = self._envelope_ctx.set(envelope)
        try:
            yield
        finally:
            self._envelope_ctx.reset(token)

    def material_action(
        self,
        *,
        action_type: str,
        required_scope: str | None = None,
    ) -> Callable[[F], F]:
        def decorator(fn: F) -> F:
            @wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                envelope = self._envelope_ctx.get()
                if envelope is None:
                    raise RuntimeError(
                        "No identity envelope in context. Wrap the call with "
                        "`with identity.exercise(envelope):` before invoking a material_action."
                    )
                return self.run_material_action(
                    envelope,
                    action_type=action_type,
                    required_scope=required_scope,
                    fn=fn,
                    args=args,
                    kwargs=kwargs,
                )

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
        self._lifecycle.ensure_active_or_raise(envelope.system_identifier)
        ensure_delegations_not_expired(envelope)
        if self._validator.enforce_scope_convention:
            validate_required_scope(required_scope)
        if required_scope:
            eff = effective_scopes_for_actor(envelope)
            if required_scope not in eff:
                raise VerificationError(
                    f"Required scope {required_scope!r} not in effective scopes {sorted(eff)}"
                )
        self._validator.validate(envelope)
        if not self._adapter.verify(envelope):
            raise VerificationError("Envelope verification failed at action time")
        input_hash = hash_canonical({"args": list(args), "kwargs": kwargs})
        result = fn(*args, **kwargs)
        output_hash = hash_canonical(result)
        audit_ref = self._adapter.audit(
            envelope,
            {
                "action_type": action_type,
                "required_scope": required_scope,
                "input_hash": input_hash,
                "output_hash": output_hash,
            },
        )
        return {
            "result": result,
            "audit_ref": audit_ref,
            "system_identifier": envelope.system_identifier,
            "lifecycle_state": envelope.lifecycle_state,
            "verified_at": envelope.verified_at.isoformat() if envelope.verified_at else None,
        }
