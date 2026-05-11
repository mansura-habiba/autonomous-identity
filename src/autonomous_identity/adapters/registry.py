from __future__ import annotations

from collections.abc import Callable
from typing import Any

from autonomous_identity.core.exceptions import AdapterNotFoundError

AdapterFactory = Callable[[dict[str, Any]], Any]

_registry: dict[str, AdapterFactory] = {}


def register_adapter(name: str, factory: AdapterFactory) -> None:
    """Register a factory that receives dependency dict and returns an identity adapter."""
    _registry[name] = factory


def get_adapter(name: str, deps: dict[str, Any]) -> Any:
    _install_default_adapters()
    if name not in _registry:
        raise AdapterNotFoundError(
            f"Identity adapter {name!r} is not registered. "
            f"Available: {sorted(_registry) or '(none)'}. "
            "See documentation for optional extras and roadmap adapters."
        )
    return _registry[name](deps)


def list_adapters() -> list[str]:
    _install_default_adapters()
    return sorted(_registry.keys())


def _install_default_adapters() -> None:
    if "merkle_chain" in _registry and "spiffe" in _registry:
        return

    def _merkle_factory(deps: dict[str, Any]) -> Any:
        from autonomous_identity.adapters.merkle_chain import MerkleChainIdentityAdapter

        signer = deps["signer"]
        audit_store = deps["audit_store"]
        return MerkleChainIdentityAdapter(signer, audit_store=audit_store)

    def _spiffe_factory(deps: dict[str, Any]) -> Any:
        from autonomous_identity.adapters.spiffe import SpiffeIdentityAdapter

        signer = deps["signer"]
        audit_store = deps["audit_store"]
        # Optional adapter config (TTL / audience) can be threaded through
        # deps["adapter_config"] when the facade is taught to forward it; the
        # adapter falls back to sensible defaults otherwise.
        config = deps.get("adapter_config") or {}
        return SpiffeIdentityAdapter(
            signer,
            audit_store=audit_store,
            svid_ttl=config.get("svid_ttl"),
            default_audience=config.get("default_audience"),
        )

    register_adapter("merkle_chain", _merkle_factory)
    register_adapter("spiffe", _spiffe_factory)
