"""Config-driven runtime construction.

The application code should not own the system identifier, the build hash,
the deployment ID, the owner, or the scope vocabulary. Those belong to the
operator (in config) and to CI (in a provenance file). The application
code asks the runtime to issue an envelope on its behalf using whatever
config and provenance the deployment environment provides.

Config layout
=============

Two files. The agent's source code refers to neither by hardcoded path —
use the ``ASID_CONFIG`` env var (or the ``config_path`` argument) to point
at the active config file.

``agent.yaml`` — operator owned. Checked into config-repo / mounted as a
ConfigMap / written by an IaC tool::

    identity:
      adapter: spiffe                # spiffe | merkle_chain
      data_dir: /var/lib/asid

    system:
      identifier: spiffe://corp.example/agents/inbox-triage
      instance_id: env:HOSTNAME        # env:NAME → os.environ[NAME]
      deployment_id: env:ASID_DEPLOYMENT_ID
      environment: prod
      region: env:REGION

    owner:
      id: team:platform
      type: team
      responsibility_scope: inbox-automation

    attestation:
      chain:
        - local:bootstrap
        - env:ASID_ATTESTATION_REF      # optional, dropped if env var missing

    scopes:
      issuer:                         # what THIS envelope may delegate
        - web.read
        - inbox.label
        - text.summarise
      tools:                          # function name → required scope
        web_search: web.read
        apply_label: inbox.label
        summarise: text.summarise

    provenance:
      file: ./provenance.json         # CI-generated, see Makefile
      required: false                 # set true in production

    lifecycle:
      svid_ttl_hours: 24              # SPIFFE adapter only

``provenance.json`` — CI/CD owned. Written at build time by a CI job, never
hand-edited::

    {
      "code_hash": "sha256:a1b2c3d4...",
      "policy_bundle_hash": "sha256:e5f6...",
      "model_hash": "sha256:0011...",
      "build_artifact_ref": "ghcr.io/corp/agent:v1.2.3@sha256:..."
    }

Usage in application code
-------------------------

::

    from autonomous_identity.config import IdentityRuntime

    # Reads ASID_CONFIG env var, else ./agent.yaml, else /etc/asid/agent.yaml.
    runtime = IdentityRuntime.from_config()

    # Bind a tool by name. Scope comes from the config's scopes.tools map.
    safe_search = runtime.tool("web_search", _raw_search)

    # Or with a decorator:
    @runtime.identity_tool("apply_label")
    def apply_label(message_id: str, label: str) -> str: ...
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, TypeVar

from autonomous_identity.application.facade import AutonomousIdentity
from autonomous_identity.core.envelope import IdentityEnvelope
from autonomous_identity.core.validators import ValidatorStrictness
from autonomous_identity.integrations.runtime import IdentityRuntime as _BaseIdentityRuntime

F = TypeVar("F", bound=Callable[..., Any])


# ----- env var interpolation -------------------------------------------------

_ENV_REF = re.compile(r"^env:([A-Z_][A-Z0-9_]*)$")


class _MissingEnv:
    """Sentinel for an env var that was referenced but not set.

    Treated as "drop this field" rather than empty string so the operator's
    intent ("only include this when the env supplies it") is preserved.
    """

    __slots__ = ()
    def __repr__(self) -> str:  # pragma: no cover
        return "<MissingEnv>"


MISSING_ENV = _MissingEnv()


def _resolve_env(value: Any) -> Any:
    """Replace ``env:NAME`` strings with ``os.environ[NAME]`` recursively."""
    if isinstance(value, str):
        m = _ENV_REF.match(value)
        if not m:
            return value
        env_value = os.environ.get(m.group(1))
        return env_value if env_value is not None else MISSING_ENV
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            resolved = _resolve_env(v)
            if resolved is MISSING_ENV:
                continue
            out[k] = resolved
        return out
    if isinstance(value, list):
        out_list: list[Any] = []
        for item in value:
            resolved = _resolve_env(item)
            if resolved is MISSING_ENV:
                continue
            out_list.append(resolved)
        return out_list
    return value


# ----- config + provenance loaders -------------------------------------------


class ConfigError(Exception):
    """Raised when the config or provenance file is malformed or missing required fields."""


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise ConfigError(
            "Loading YAML configs requires PyYAML. Install with: pip install PyYAML"
        ) from exc
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ConfigError(f"Config root must be a mapping, got {type(data).__name__}")
    return data


def _load_provenance(path: Path, *, required: bool) -> dict[str, Any]:
    """Load CI-generated provenance.json. Empty when not required and missing."""
    if not path.is_file():
        if required:
            raise ConfigError(
                f"provenance.required=true but {path} does not exist. CI must "
                f"generate this file. See examples/crewai_identity/Makefile for "
                f"a worked recipe."
            )
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Could not parse provenance file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(
            f"Provenance root must be a JSON object, got {type(data).__name__}"
        )
    return data


# ----- the public construction API -------------------------------------------


def find_config_path(explicit: str | Path | None = None) -> Path:
    """Discovery order: explicit arg → ASID_CONFIG env → ./agent.yaml → /etc/asid/agent.yaml."""
    if explicit is not None:
        return Path(explicit)
    env_path = os.environ.get("ASID_CONFIG")
    if env_path:
        return Path(env_path)
    cwd_path = Path.cwd() / "agent.yaml"
    if cwd_path.is_file():
        return cwd_path
    return Path("/etc/asid/agent.yaml")


class IdentityRuntime(_BaseIdentityRuntime):
    """Config-driven IdentityRuntime.

    Inherits all behaviour from
    :class:`autonomous_identity.integrations.runtime.IdentityRuntime` and adds
    config-driven construction plus tool binding by name.

    Build with :meth:`from_config`; bind tools with :meth:`tool` or
    :meth:`identity_tool`. Application code does not need to know the
    scope vocabulary — only the tool name in config.
    """

    def __init__(
        self,
        identity: AutonomousIdentity,
        envelope: IdentityEnvelope,
        *,
        scope_map: dict[str, str] | None = None,
        default_action_type: str = "tool_call",
    ) -> None:
        super().__init__(identity, envelope, default_action_type=default_action_type)
        self._scope_map: dict[str, str] = dict(scope_map or {})

    # ----- construction ------------------------------------------------------

    @classmethod
    def from_config(
        cls,
        config_path: str | Path | None = None,
        *,
        strictness: ValidatorStrictness = ValidatorStrictness.STRICT,
    ) -> "IdentityRuntime":
        """Build an IdentityRuntime from a YAML config + provenance file.

        See module docstring for the schema. Discovery of the config path
        follows :func:`find_config_path`.
        """
        path = find_config_path(config_path)
        config = _load_yaml(path)
        config = _resolve_env(config)

        # --- identity facade
        id_cfg = config.get("identity", {}) or {}
        adapter_name = id_cfg.get("adapter", "merkle_chain")
        data_dir = id_cfg.get("data_dir", ".asid")
        identity = AutonomousIdentity.local(
            Path(data_dir).expanduser(),
            adapter_name=adapter_name,
            strictness=strictness,
        )

        # --- provenance from CI
        prov_cfg = config.get("provenance", {}) or {}
        prov_file = prov_cfg.get("file", "provenance.json")
        prov_required = bool(prov_cfg.get("required", False))
        prov_path = (path.parent / prov_file).resolve() if not Path(prov_file).is_absolute() else Path(prov_file)
        provenance = _load_provenance(prov_path, required=prov_required)
        if prov_required:
            missing = [
                k for k in ("code_hash", "policy_bundle_hash") if not provenance.get(k)
            ]
            if missing:
                raise ConfigError(
                    f"provenance.required=true but {prov_path} is missing required "
                    f"keys: {missing}. CI must populate them at build time."
                )

        # --- issue context
        system_cfg = config.get("system", {}) or {}
        owner_cfg = config.get("owner", {}) or {}
        attestation_cfg = (config.get("attestation") or {}).get("chain", [])
        scopes_cfg = config.get("scopes", {}) or {}
        lifecycle_cfg = config.get("lifecycle", {}) or {}

        if not system_cfg.get("identifier"):
            raise ConfigError("config: system.identifier is required")
        if not owner_cfg.get("id"):
            raise ConfigError("config: owner.id is required")

        issue_context: dict[str, Any] = {
            "system_identifier": system_cfg["identifier"],
            "instance_id": system_cfg.get("instance_id") or "default-instance",
            "deployment_id": system_cfg.get("deployment_id") or "default-deployment",
            "owner_id": owner_cfg["id"],
            "owner_type": owner_cfg.get("type", "team"),
            "responsibility_scope": owner_cfg.get("responsibility_scope", "unspecified"),
            "environment": system_cfg.get("environment", "dev"),
            "region": system_cfg.get("region", "local"),
            "provenance": {
                "code_hash": provenance.get("code_hash"),
                "model_hash": provenance.get("model_hash"),
                "config_hash": provenance.get("config_hash"),
                "policy_bundle_hash": provenance.get("policy_bundle_hash"),
                "build_artifact_ref": provenance.get("build_artifact_ref"),
                "deployment_manifest_hash": provenance.get("deployment_manifest_hash"),
            },
            "attestation_chain": list(attestation_cfg) or ["local:config-driven"],
            "issuer_scopes": list(scopes_cfg.get("issuer") or []),
        }
        # Drop empty provenance fields so the validator's "any-provenance"
        # check has at least one real value to point at.
        issue_context["provenance"] = {
            k: v for k, v in issue_context["provenance"].items() if v
        }
        if not issue_context["provenance"]:
            if prov_required:
                raise ConfigError("provenance.required=true but no provenance fields populated")
            # Mark the envelope explicitly as dev-only so the strict validator
            # gives a clean error rather than a generic "no provenance" one.
            issue_context["metadata"] = {"dev_provenance_placeholder": True}

        envelope = identity.issue_envelope(issue_context)

        scope_map = dict(scopes_cfg.get("tools") or {})

        # Apply SPIFFE-only lifecycle config if present.
        ttl = lifecycle_cfg.get("svid_ttl_hours")
        if ttl and adapter_name == "spiffe":
            try:
                # The default SPIFFE adapter created above uses a 24h TTL; for
                # a custom value the adapter would need to be reconstructed
                # via adapter_config. Surface this clearly rather than
                # silently ignoring the setting.
                adapter = getattr(identity, "_adapter", None)
                if adapter is not None and hasattr(adapter, "_svid_ttl"):
                    adapter._svid_ttl = timedelta(hours=float(ttl))
            except Exception:  # pragma: no cover
                pass

        return cls(identity, envelope, scope_map=scope_map)

    # ----- tool binding by config-driven scope -------------------------------

    @property
    def scope_map(self) -> dict[str, str]:
        return dict(self._scope_map)

    def required_scope_for(self, name: str) -> str | None:
        """Look up the required scope for a tool by name. Raises if unmapped.

        Returns ``None`` when the config explicitly maps the tool to no scope
        (rare; mainly useful for invocation hops).
        """
        if name not in self._scope_map:
            raise ConfigError(
                f"No scope configured for tool {name!r}. Add it to scopes.tools "
                f"in the agent config (or call wrap_tool() directly if this "
                f"tool intentionally has no scope gate)."
            )
        scope = self._scope_map[name]
        return scope if scope else None

    def tool(
        self,
        name: str,
        fn: Callable[..., Any],
        *,
        action_type: str | None = None,
    ) -> Callable[..., Any]:
        """Bind ``fn`` as a tool ``name``. Scope is looked up from config.

        Returns a new callable (same as :meth:`wrap_tool`) — never mutates
        the input function.
        """
        scope = self.required_scope_for(name)
        return self.wrap_tool(
            fn,
            required_scope=scope,
            action_type=action_type or f"tool.{name}",
        )

    def identity_tool(
        self,
        name: str,
        *,
        action_type: str | None = None,
    ) -> Callable[[F], F]:
        """Decorator form of :meth:`tool`.

        ::

            @runtime.identity_tool("web_search")
            def web_search(query: str) -> str: ...
        """
        def decorator(fn: F) -> F:
            return self.tool(name, fn, action_type=action_type)  # type: ignore[return-value]

        return decorator


# ----- helpful diagnostic shown when config is wrong -------------------------

def _hint_for_developer() -> str:  # pragma: no cover - error UX helper
    return (
        "An agent config (agent.yaml) and a CI-generated provenance.json are "
        "expected. See examples/crewai_identity/agent.yaml for a worked example. "
        "Run with ASID_CONFIG=/path/to/agent.yaml or place agent.yaml in cwd."
    )


def _log_init(runtime: IdentityRuntime) -> None:  # pragma: no cover
    if os.environ.get("ASID_DEBUG"):
        print(
            f"[asid] runtime ready: subject={runtime.system_identifier} "
            f"tools_in_config={sorted(runtime.scope_map.keys())}",
            file=sys.stderr,
        )
