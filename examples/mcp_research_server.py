"""Minimal FastMCP server for the LangGraph delegation demo.

Same in-process pattern as `nexa-claw/agentic` (FastMCP + ``Client(server)`` +
``langchain_mcp_adapters.tools.load_mcp_tools``): real MCP tool discovery and
invocation, no hand-rolled dict stubs.

Run standalone (stdio) for external clients (Cursor MCP, Claude Desktop, etc.)::

    uv run python examples/mcp_research_server.py

**Cursor / MCP hosts:** point the server command at **this file**
(``mcp_research_server.py``), not at ``langgraph_multi_agent_delegation.py``. The
LangGraph demo is a **client** of the in-process server; if a host mistakenly runs
that script as the stdio MCP server, stdin will not be JSON-RPC and you will see
errors like ``JSONRPCMessage ... Invalid JSON`` with a ``.py`` path in the message.

Or import ``research_mcp`` / ``get_research_mcp()`` from
``examples/langgraph_multi_agent_delegation.py``.
"""

from __future__ import annotations

from fastmcp import FastMCP

research_mcp = FastMCP(
    name="asid-research-demo",
    instructions=(
        "Demo research tools for autonomous-identity. "
        "Expose factual snippets for downstream document agents."
    ),
)


@research_mcp.tool()
def research_fetch_topic(topic: str) -> str:
    """Return a short research line for ``topic`` (deterministic demo content)."""
    return f"[MCP research_fetch_topic] Stub facts about {topic!r}."


def get_research_mcp() -> FastMCP:
    return research_mcp


def main() -> None:
    import asyncio

    asyncio.run(research_mcp.run_stdio_async())


if __name__ == "__main__":
    main()
