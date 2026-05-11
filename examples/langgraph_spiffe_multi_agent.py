"""LangGraph multi-agent demo using the **SPIFFE** identity adapter.

Topology (all inside one trust domain, ``corp.example``)::

    spiffe://corp.example/platform           # root issuer
      └─► spiffe://corp.example/orchestrator # plans the work
           ├─► spiffe://corp.example/agents/research  # web.read
           └─► spiffe://corp.example/agents/writer    # doc.write

Each envelope carries a JWT-SVID and a JWKS in its metadata. The audit log
records ``spiffe_issue`` / ``spiffe_delegate`` / ``spiffe_action`` rows; every
material action (tool call, doc compose) is bound to the actor's SVID and the
envelope commitment hash.

Install::

    pip install -e ".[langgraph]"

Run::

    uv run python examples/langgraph_spiffe_multi_agent.py
"""

from __future__ import annotations

import operator
import sys
from pathlib import Path
from typing import Annotated, Any, TypedDict

try:  # Python 3.11+: NotRequired is in typing; on 3.10 it's in typing_extensions.
    from typing import NotRequired  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    from typing_extensions import NotRequired

from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.application.delegation_chain import issue_and_delegate_tree
from autonomous_identity.core.delegation_util import effective_scopes_for_actor
from autonomous_identity.core.envelope import IdentityEnvelope
from autonomous_identity.integrations.langgraph import wrap_langgraph_node
from autonomous_identity.tracing import TracedIdentity

# Shared demo helper handles .env loading + tracer selection + flushing.
_EXAMPLES_DIR = Path(__file__).resolve().parent
if str(_EXAMPLES_DIR) not in sys.path:
    sys.path.insert(0, str(_EXAMPLES_DIR))
from _demo_support import build_tracer, wait_for_flush  # noqa: E402


def _build_tracer():
    return build_tracer(trace_name="asid-spiffe-langgraph")


# ----- trust domain + delegation spec ----------------------------------------

TRUST_DOMAIN = "corp.example"


def _spec() -> dict[str, Any]:
    """Runtime delegation spec — swap this from a planner / DB on each invoke."""
    return {
        "issue": {
            "system_identifier": f"spiffe://{TRUST_DOMAIN}/platform",
            "instance_id": "graph-1",
            "deployment_id": "d1",
            "owner_id": "team:platform",
            "provenance": {
                "code_hash": "sha256:plat",
                "policy_bundle_hash": "sha256:pol",
            },
            "attestation_chain": ["local:bootstrap"],
            "issuer_scopes": [
                "orchestrate",
                "web.read",
                "doc.write",
            ],
        },
        "edges": [
            {
                "role": "orchestrator",
                "parent_role": "platform",
                "child_subject": f"spiffe://{TRUST_DOMAIN}/orchestrator",
                "allowed_scopes": ["orchestrate", "web.read", "doc.write"],
                "caveats": {"role": "orchestrator"},
                "expires_in_hours": 24,
            },
            {
                "role": "research",
                "parent_role": "orchestrator",
                "child_subject": f"spiffe://{TRUST_DOMAIN}/agents/research",
                "allowed_scopes": ["web.read"],
                "caveats": {"role": "research"},
                "expires_in_hours": 24,
            },
            {
                "role": "writer",
                "parent_role": "orchestrator",
                "child_subject": f"spiffe://{TRUST_DOMAIN}/agents/writer",
                "allowed_scopes": ["doc.write"],
                "caveats": {"role": "writer"},
                "expires_in_hours": 24,
            },
        ],
    }


def _envelope_summary(env: IdentityEnvelope) -> dict[str, Any]:
    return {
        "spiffe_id": env.system_identifier,
        "trust_domain": env.metadata.get("spiffe.trust_domain"),
        "kid": env.metadata.get("spiffe.kid"),
        "svid_exp": env.metadata.get("spiffe.svid_exp"),
        "effective_scopes": sorted(effective_scopes_for_actor(env)),
        "delegations": [
            {
                "parent": d.parent_subject,
                "child": d.child_subject,
                "scopes": list(d.allowed_scopes),
            }
            for d in env.delegations
        ],
    }


# ----- the graph -------------------------------------------------------------


def run_graph(*, delegation_spec: dict[str, Any] | None = None) -> dict[str, Any]:
    from langgraph.graph import END, StateGraph

    spec = delegation_spec if delegation_spec is not None else _spec()
    data_dir = Path(".asid-langgraph-spiffe")
    identity = TracedIdentity.local(
        data_dir,
        adapter_name="spiffe",
        strictness=ValidatorStrictness.STRICT,
        tracer=_build_tracer(),
    )

    @identity.material_action(action_type="workflow.orchestrate", required_scope="orchestrate")
    def orchestrate(topic: str) -> str:
        return f"route:research_then_write|topic={topic}"

    @identity.material_action(action_type="research.fetch", required_scope="web.read")
    def do_research(topic: str) -> str:
        return f"research::{topic}: top 3 findings (stub)"

    @identity.material_action(action_type="doc.compose", required_scope="doc.write")
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
            "spiffe_id": env.system_identifier,
            "trust_domain": env.metadata.get("spiffe.trust_domain"),
            "audit_ref": audit_ref,
            "svid_kid": env.metadata.get("spiffe.kid"),
        }
        if extra:
            row.update(extra)
        return row

    def bootstrap(state: GraphState) -> dict[str, Any]:
        envs = issue_and_delegate_tree(
            identity,
            issue_context=state["delegation_spec"]["issue"],
            edges=state["delegation_spec"]["edges"],
            root_role="platform",
        )
        return {"envelopes": envs}

    def node_orchestrate(state: GraphState) -> dict[str, Any]:
        proof = orchestrate(state["topic"])
        env = state["envelopes"]["orchestrator"]
        return {
            "plan": proof["result"],
            "trace": [_trace("orchestrator", env, "workflow.orchestrate", proof.get("audit_ref"))],
        }

    def node_research(state: GraphState) -> dict[str, Any]:
        proof = do_research(state["topic"])
        env = state["envelopes"]["research"]
        return {
            "research": proof["result"],
            "trace": [_trace("research", env, "research.fetch", proof.get("audit_ref"))],
        }

    def node_writer(state: GraphState) -> dict[str, Any]:
        env = state["envelopes"]["writer"]
        proof = compose_doc(state["topic"], state["research"])
        return {
            "document": proof["result"],
            "trace": [_trace("writer", env, "doc.compose", proof.get("audit_ref"))],
        }

    graph = StateGraph(GraphState)
    graph.add_node("bootstrap", bootstrap)
    graph.add_node(
        "orchestrate",
        wrap_langgraph_node(identity, lambda s: s["envelopes"]["orchestrator"], node_orchestrate),
    )
    graph.add_node(
        "research",
        wrap_langgraph_node(identity, lambda s: s["envelopes"]["research"], node_research),
    )
    graph.add_node(
        "writer",
        wrap_langgraph_node(identity, lambda s: s["envelopes"]["writer"], node_writer),
    )
    graph.set_entry_point("bootstrap")
    graph.add_edge("bootstrap", "orchestrate")
    graph.add_edge("orchestrate", "research")
    graph.add_edge("research", "writer")
    graph.add_edge("writer", END)
    app = graph.compile()

    initial: GraphState = {
        "topic": "renewable supply chain",
        "delegation_spec": spec,
        "envelopes": {},
        "trace": [],
    }
    final = app.invoke(initial)

    print("=== SPIFFE envelopes (post-bootstrap) ===")
    for role, env in final["envelopes"].items():
        print(role.upper(), _envelope_summary(env))
        # Independent verification of the SVID at this point in time.
        ok = identity._adapter.verify(env)  # noqa: SLF001 (demo introspection)
        print("  verify():", ok)
    print()
    print("=== Graph result ===")
    print("plan:    ", final.get("plan"))
    print("research:", final.get("research"))
    print("document:\n", final.get("document"))
    print()
    print("=== Per-step identity trace (acting agent + audit) ===")
    for i, row in enumerate(final["trace"], 1):
        print(
            f"{i}. {row['step']:<22} actor={row['spiffe_id']:<48} "
            f"td={row['trust_domain']:<14} audit={row['audit_ref']}"
        )

    wait_for_flush()
    return final


if __name__ == "__main__":  # pragma: no cover
    try:
        run_graph()
    except ModuleNotFoundError as exc:
        print(
            "This demo requires the langgraph extra.\n"
            "Install with: pip install -e \".[langgraph]\"\n"
            f"Underlying import error: {exc}",
            file=sys.stderr,
        )
        sys.exit(2)
