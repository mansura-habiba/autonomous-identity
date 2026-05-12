"""Full CrewAI run with autonomous-identity — requires an LLM API key.

Same wrapping pattern as ``crewai_identity_demo.py``, but here the wrapped
tools are handed to a real CrewAI ``Agent`` and a ``Crew`` is kicked off
with a task. The LLM drives the agent; the agent decides when to call the
tools; the identity gate fires at every tool invocation regardless of
whether the LLM chose well.

Configure ONE of the following before running. CrewAI uses LiteLLM, so any
provider LiteLLM supports works.

    export OPENAI_API_KEY=sk-...
    # or
    export ANTHROPIC_API_KEY=sk-ant-...

Then::

    pip install -e ".[dev]"
    pip install crewai
    python examples/crewai_identity/crewai_identity_with_crew.py

The script prints the audit log at the end so you can see which tools the
LLM actually decided to call.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from crewai import Agent, Crew, Task
from crewai.tools import BaseTool

from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.integrations.runtime import IdentityRuntime


# ----- raw functions the agent can call -------------------------------------


def _raw_web_search(query: str) -> str:
    """Stubbed search — replace with a real search-API call in production."""
    return (
        f"Top 3 results for {query!r}: "
        "(1) example.com/quantum, (2) arxiv.org/abs/2401.0001, "
        "(3) nature.com/articles/example."
    )


def _raw_summarise(text: str) -> str:
    return f"SUMMARY[{len(text)} chars]: {text[:120]}…"


# ----- identity + wrapping --------------------------------------------------


def main() -> int:
    if not (os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")):
        print(
            "[skip] no OPENAI_API_KEY or ANTHROPIC_API_KEY set — this script "
            "needs an LLM to drive the crew. Set one of those env vars and "
            "rerun. (Use crewai_identity_demo.py for an LLM-free check that "
            "the identity gate works against real CrewAI BaseTools.)",
            file=sys.stderr,
        )
        return 0

    data_dir = Path(tempfile.mkdtemp(prefix="asid-crewai-crew-"))
    identity = AutonomousIdentity.local(
        data_dir,
        adapter_name="spiffe",
        strictness=ValidatorStrictness.STRICT,
    )
    envelope = identity.issue_envelope(
        {
            "system_identifier": "spiffe://corp.example/agents/researcher",
            "instance_id": "researcher-prod-1",
            "deployment_id": "release-2026-05-11",
            "owner_id": "team:research",
            "provenance": {
                "code_hash": "sha256:c00fee",
                "policy_bundle_hash": "sha256:policy-research-v1",
            },
            "attestation_chain": ["local:bootstrap"],
            "issuer_scopes": ["web.read", "text.summarise"],
        }
    )
    runtime = IdentityRuntime(identity, envelope)

    safe_search = runtime.wrap_tool(_raw_web_search, required_scope="web.read")
    safe_summarise = runtime.wrap_tool(
        _raw_summarise, required_scope="text.summarise"
    )

    class WebSearchTool(BaseTool):
        name: str = "web_search"
        description: str = "Search the web for a query string."

        def _run(self, query: str) -> str:
            return safe_search(query)

    class SummariseTool(BaseTool):
        name: str = "summarise"
        description: str = "Summarise a block of text."

        def _run(self, text: str) -> str:
            return safe_summarise(text)

    researcher = Agent(
        role="Research Analyst",
        goal="Find recent papers on quantum coherence and produce a one-paragraph brief.",
        backstory=(
            "You are a senior research analyst who finds primary sources and "
            "synthesises them. You only use the tools you are given."
        ),
        tools=[WebSearchTool(), SummariseTool()],
        verbose=True,
        allow_delegation=False,
    )

    task = Task(
        description=(
            "Find 3 recent papers on quantum coherence times. "
            "Summarise the top result in one paragraph."
        ),
        expected_output="One paragraph summarising the top result.",
        agent=researcher,
    )

    crew = Crew(agents=[researcher], tasks=[task], verbose=True)

    # Run the crew inside the runtime so every tool call goes through the
    # identity gate. The LLM does not need to know identity exists.
    with runtime:
        result = crew.kickoff()

    print("\n=== Crew result ===")
    print(result)

    print("\n=== Audit log ===")
    audit_path = data_dir / "audit.jsonl"
    for i, line in enumerate(audit_path.read_text().strip().splitlines(), 1):
        row = json.loads(line)
        kind = row.get("kind", "?")
        action = (row.get("action") or {}).get("action_type") or row.get(
            "action_type"
        )
        print(f"  {i:>2}. kind={kind!s:<18} action={action}")
    print(f"\nAudit store: {audit_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
