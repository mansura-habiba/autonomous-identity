"""Config-driven runtime construction for autonomous-identity.

Public surface:
    * :class:`IdentityRuntime` — config-driven subclass of the base
      framework-agnostic runtime. Has ``from_config()``, ``tool(name, fn)``,
      and ``identity_tool(name)`` decorator.
    * :func:`find_config_path` — discovery order for the agent.yaml file.
    * :exc:`ConfigError` — raised on malformed or missing config / provenance.

See :mod:`autonomous_identity.config.runtime_config` docstring for the YAML
schema and the CI provenance file convention.
"""

from autonomous_identity.config.runtime_config import (
    ConfigError,
    IdentityRuntime,
    find_config_path,
)

__all__ = ["ConfigError", "IdentityRuntime", "find_config_path"]
