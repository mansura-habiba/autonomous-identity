"""LangGraph multi-agent flow: **runtime delegation spec** + identity-wrapped nodes.

Identities are **not** hard-coded at graph build time. The first node builds
``state["envelopes"]`` from ``state["delegation_spec"]`` (issue context + delegation
edges) via :func:`autonomous_identity.application.delegation_chain.issue_and_delegate_tree`.
Swap that spec from a database, planner output, or request payload on each ``invoke``.

Later nodes use ``wrap_langgraph_node(identity, lambda s: s["envelopes"][...], fn)``.

Install::

    pip install -e ".[langgraph]"

Run::

    uv run python examples/langgraph_multi_agent_delegation.py

Standalone MCP server (stdio)::

    uv run python examples/mcp_research_server.py
"""

from __future__ import annotations

import asyncio
import json
import operator
import sys
from pathlib import Path
from typing import Annotated, Any, NotRequired, TypedDict

from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.application.delegation_chain import issue_and_delegate_tree
from autonomous_identity.core.delegation_util import effective_scopes_for_actor
from autonomous_identity.core.envelope import IdentityEnvelope
from autonomous_identity.core.scope_convention import build_scope_v1
from autonomous_identity.integrations.langgraph import wrap_langgraph_node

_EXAMPLES = Path(__file__).resolve().parent
if str(_EXAMPLES) not in sys.path:
    sys.path.insert(0, str(_EXAMPLES))

from mcp_research_server import research_mcp  # noqa: E402

# asid v1 scopes shared by ``_demo_delegation_spec`` and material actions (see docs/SCOPE_CONVENTION.md).
_DEMO_NS = "org-demo"
S_GOV_TICKET = build_scope_v1(_DEMO_NS, "governance", "ticket")
S_ORCH = build_scope_v1(_DEMO_NS, "runtime", "orchestrate")
S_MCP = build_scope_v1(_DEMO_NS, "mcp", "invoke")
S_WEB = build_scope_v1(_DEMO_NS, "web", "read")
S_DOC = build_scope_v1(_DEMO_NS, "docs", "write")


def _tool_output_to_text(raw: Any) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list) and raw:
        first = raw[0]
        if isinstance(first, dict) and "text" in first:
            return str(first["text"])
    return str(raw)


def _demo_delegation_spec() -> dict[str, Any]:
    """Example runtime payload (replace per request / planner / DB).

    Scopes use **asid v1** strings (``docs/SCOPE_CONVENTION.md``); ``build_scope_v1`` avoids typos.
    """
    issuer = [S_GOV_TICKET, S_ORCH, S_MCP, S_WEB, S_DOC]
    return {
        "issue": {
            "system_identifier": "agent://demo/platform",
            "instance_id": "graph-1",
            "deployment_id": "d1",
            "owner_id": "org:demo",
            "provenance": {"code_hash": "sha256:plat", "policy_bundle_hash": "sha256:pol"},
            "attestation_chain": ["local:bootstrap"],
            "issuer_scopes": issuer,
        },
        "edges": [
            {
                "role": "orchestrator",
                "parent_role": "platform",
                "child_subject": "agent://demo/orchestrator",
                "allowed_scopes": [S_ORCH, S_MCP, S_WEB, S_DOC],
                "caveats": {"role": "orchestrator"},
                "expires_in_hours": 24,
            },
            {
                "role": "research",
                "parent_role": "orchestrator",
                "child_subject": "agent://demo/research",
                "allowed_scopes": [S_MCP, S_WEB],
                "caveats": {"role": "research", "mcp_transport": "fastmcp-in-process"},
                "expires_in_hours": 24,
            },
            {
                "role": "writer",
                "parent_role": "orchestrator",
                "child_subject": "agent://demo/writer",
                "allowed_scopes": [S_DOC],
                "caveats": {"role": "writer"},
                "expires_in_hours": 24,
            },
        ],
    }


def envelope_summary(env: IdentityEnvelope) -> dict[str, Any]:
    return {
        "system_identifier": env.system_identifier,
        "effective_scopes": sorted(effective_scopes_for_actor(env)),
        "delegations": [
            {
                "parent": d.parent_subject,
                "child": d.child_subject,
                "scopes": list(d.allowed_scopes),
                "caveats": dict(d.caveats),
            }
            for d in env.delegations
        ],
    }


async def _run_mcp_research(topic: str) -> tuple[list[str], str]:
    from fastmcp import Client
    from fastmcp.client.transports import FastMCPTransport
    from langchain_mcp_adapters.tools import load_mcp_tools

    async with Client(FastMCPTransport(research_mcp)) as mcp_client:
        tools = await load_mcp_tools(mcp_client.session)
        names = sorted(t.name for t in tools)
        tool = next(t for t in tools if t.name == "research_fetch_topic")
        raw = await tool.ainvoke({"topic": topic})
    return names, _tool_output_to_text(raw)


def run_graph(*, delegation_spec: dict[str, Any] | None = None) -> None:
    from langgraph.graph import END, StateGraph

    spec = delegation_spec if delegation_spec is not None else _demo_delegation_spec()

    data_dir = Path(".asid-langgraph-multi")
    identity = AutonomousIdentity.local(data_dir, strictness=ValidatorStrictness.STRICT)

    @identity.material_action(action_type="governance.open_ticket", required_scope=S_GOV_TICKET)
    def open_ops_ticket(topic: str) -> str:
        return f"ops-ticket-opened|topic={topic}"

    @identity.material_action(action_type="workflow.orchestrate", required_scope=S_ORCH)
    def orchestrate(topic: str) -> str:
        return f"route:research_then_write|topic={topic}"

    @identity.material_action(action_type="doc.compose", required_scope=S_DOC)
    def compose_doc(topic: str, research_text: str) -> str:
        return f"# {topic}\n\n{research_text}\n"

    class GraphState(TypedDict):
        topic: str
        delegation_spec: dict[str, Any]
        envelopes: dict[str, IdentityEnvelope]
        plan: NotRequired[str]
        research: NotRequired[str]
        document: NotRequired[str]
        trace: Annotated[list[dict[str, Any]], operator.add]

    def _trace(
        who: str,
        env: IdentityEnvelope,
        step: str,
        audit_ref: str | None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        row: dict[str, Any] = {
            "step": step,
            "acting_agent": who,
            "system_identifier": env.system_identifier,
            "audit_ref": audit_ref,
            "identity": envelope_summary(env),
        }
        if extra:
            row.update(extra)
        return row

    def bootstrap(state: GraphState) -> dict[str, Any]:
        s = state["delegation_spec"]
        envs = issue_and_delegate_tree(
            identity,
            issue_context=s["issue"],
            edges=s["edges"],
            root_role="platform",
        )
        return {"envelopes": envs}

    def node_platform_governance(state: GraphState) -> dict[str, Any]:
        proof = open_ops_ticket(state["topic"])
        env = state["envelopes"]["platform"]
        return {
            "trace": [_trace("platform", env, "governance.open_ticket", proof.get("audit_ref"))],
        }

    def node_orchestrate(state: GraphState) -> dict[str, Any]:
        proof = orchestrate(state["topic"])
        env = state["envelopes"]["orchestrator"]
        return {
            "plan": proof["result"],
            "trace": [_trace("orchestrator", env, "orchestrate", proof.get("audit_ref"))],
        }

    def node_research_mcp(state: GraphState) -> dict[str, Any]:
        topic = state["topic"]
        env = state["envelopes"]["research"]
        tool_names, research_text = asyncio.run(_run_mcp_research(topic))

        proof_list = identity.run_material_action(
            env,
            action_type="mcp.list_tools",
            required_scope=S_MCP,
            fn=lambda: json.dumps(tool_names),
            args=(),
            kwargs={},
        )
        proof_call = identity.run_material_action(
            env,
            action_type="mcp.call_tool",
            required_scope=S_MCP,
            fn=lambda: research_text,
            args=(),
            kwargs={},
        )
        return {
            "research": research_text,
            "trace": [
                _trace(
                    "research",
                    env,
                    "mcp.list_tools",
                    proof_list.get("audit_ref"),
                    extra={"mcp_tool_names": json.loads(str(proof_list["result"]))},
                ),
                _trace(
                    "research",
                    env,
                    "mcp.call_tool",
                    proof_call.get("audit_ref"),
                    extra={"tool": "research_fetch_topic", "transport": "fastmcp+Client"},
                ),
            ],
        }

    def node_write(state: GraphState) -> dict[str, Any]:
        env = state["envelopes"]["writer"]
        proof = compose_doc(state["topic"], state["research"])
        return {
            "document": proof["result"],
            "trace": [_trace("writer", env, "doc.compose", proof.get("audit_ref"))],
        }

    graph = StateGraph(GraphState)
    graph.add_node("bootstrap", bootstrap)
    graph.add_node(
        "platform_governance",
        wrap_langgraph_node(identity, lambda s: s["envelopes"]["platform"], node_platform_governance),
    )
    graph.add_node(
        "orchestrate",
        wrap_langgraph_node(identity, lambda s: s["envelopes"]["orchestrator"], node_orchestrate),
    )
    graph.add_node(
        "research_mcp",
        wrap_langgraph_node(identity, lambda s: s["envelopes"]["research"], node_research_mcp),
    )
    graph.add_node(
        "write",
        wrap_langgraph_node(identity, lambda s: s["envelopes"]["writer"], node_write),
    )
    graph.set_entry_point("bootstrap")
    graph.add_edge("bootstrap", "platform_governance")
    graph.add_edge("platform_governance", "orchestrate")
    graph.add_edge("orchestrate", "research_mcp")
    graph.add_edge("research_mcp", "write")
    graph.add_edge("write", END)
    app = graph.compile()

    initial: GraphState = {
        "topic": "renewable supply chain",
        "delegation_spec": spec,
        "envelopes": {},
        "trace": [],
    }
    final = app.invoke(initial)

    print("=== Runtime delegation_spec (issue + edges) ===")
    print("issuer:", spec["issue"]["system_identifier"])
    print("edges:", len(spec["edges"]), "delegation(s)")
    print()
    print("=== Envelopes after graph (from state) ===")
    for role, env in final["envelopes"].items():
        print(role.upper(), envelope_summary(env))
    print()
    print("=== LangGraph result ===")
    print("plan:", final.get("plan"))
    print("research:", final.get("research"))
    print("document:\n", final.get("document"))
    print()
    print("=== Per-step identity trace (acting agent + audit) ===")
    for i, row in enumerate(final["trace"], 1):
        print(f"{i}.", row["step"], "| actor:", row["system_identifier"], "| audit:", row.get("audit_ref"))


if __name__ == "__main__":
    run_graph()
