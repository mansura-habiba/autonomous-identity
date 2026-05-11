from __future__ import annotations

from typing import Any, Callable, TypeVar

from autonomous_identity.application.facade import AutonomousIdentity

F = TypeVar("F", bound=Callable[..., Any])


def identity_protected_tool(
    *,
    identity: AutonomousIdentity,
    action_type: str = "tool_call",
    required_scope: str | None = None,
) -> Callable[[F], F]:
    """Wrap a LangChain @tool so invocations run as material actions.

    Requires an active envelope from ``with identity.exercise(envelope):``.
    """

    try:
        from langchain_core.tools import StructuredTool, tool as lc_tool
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "Install langchain-core for identity_protected_tool, "
            "e.g. pip install autonomous-identity[langchain]"
        ) from e

    def decorator(fn: F) -> F:
        base = lc_tool(fn)

        def instrumented(**kwargs: Any) -> Any:
            env = AutonomousIdentity._envelope_ctx.get()
            if env is None:
                raise RuntimeError(
                    "No envelope in context. Use `with identity.exercise(envelope):` before tool calls."
                )
            return identity.run_material_action(
                env,
                action_type=action_type,
                required_scope=required_scope,
                fn=lambda: base.invoke(kwargs),
                args=(),
                kwargs={},
            )["result"]

        wrapped = StructuredTool.from_function(
            name=base.name,
            description=base.description or "",
            func=instrumented,
            args_schema=base.args_schema,
        )
        return wrapped  # type: ignore[return-value]

    return decorator
