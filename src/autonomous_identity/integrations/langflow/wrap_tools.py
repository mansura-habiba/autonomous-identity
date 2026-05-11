from __future__ import annotations

from typing import Any

from autonomous_identity.application.facade import AutonomousIdentity


def _bind_tool_invoke(
    identity: AutonomousIdentity,
    tool: Any,
    *,
    action_type: str,
    required_scope: str | None,
) -> Any:
    orig = tool.invoke

    def _invoke(input: Any, config: Any = None, **kwargs: Any) -> Any:
        env = AutonomousIdentity._envelope_ctx.get()
        if env is None:
            raise RuntimeError("No envelope in context; use identity.exercise(envelope).")
        return identity.run_material_action(
            env,
            action_type=action_type,
            required_scope=required_scope,
            fn=lambda: orig(input, config=config, **kwargs),
            args=(),
            kwargs={},
        )["result"]

    tool.invoke = _invoke  # type: ignore[method-assign]
    return tool


def wrap_tools_for_identity(
    identity: AutonomousIdentity,
    tools: list[Any],
    *,
    action_type: str = "tool_call",
    required_scope: str | None = None,
) -> list[Any]:
    """Wrap LangChain tools so each ``invoke`` runs through ``AutonomousIdentity.run_material_action``.

    Intended for use inside a custom Langflow ``AgentComponent`` after tools are collected.
    """

    try:
        from langchain_core.tools import BaseTool
    except ImportError as e:  # pragma: no cover
        raise ImportError("langchain-core is required for wrap_tools_for_identity") from e

    out: list[Any] = []
    for t in tools:
        if isinstance(t, BaseTool):
            out.append(_bind_tool_invoke(identity, t, action_type=action_type, required_scope=required_scope))
        else:
            out.append(t)
    return out
