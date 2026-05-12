"""Config-driven CrewAI + autonomous-identity integration.

This is the production-shaped variant of ``crewai_identity_demo.py``.
The application code below contains:

    * NO system identifier
    * NO deployment / instance / region values
    * NO owner declaration
    * NO scope vocabulary
    * NO build hash / policy bundle hash
    * NO scope-per-tool mapping

All of that lives in ``agent.yaml`` (operator-owned) and ``provenance.json``
(CI-generated). The agent only knows its function names — ``web_search``,
``apply_label``, ``summarise``. The runtime looks up each function's
scope from config and re-verifies the envelope at every call.

Run::

    cd examples/crewai_identity
    make provenance          # CI normally does this — here we run it locally
    ASID_CONFIG=agent.yaml python crewai_config_driven.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from crewai.tools import BaseTool

from autonomous_identity.config import IdentityRuntime
from autonomous_identity.core.exceptions import VerificationError


# ----- raw tool functions ----------------------------------------------------
# Application code knows these by their function name. The function name
# (web_search / apply_label / summarise) matches a key in agent.yaml under
# scopes.tools — that's how the runtime knows which scope each one requires.


def web_search(query: str) -> str:
    """Pretend search; in production wire this to a real search API."""
    return f"results:[{query}]"


def apply_label(message_id: str, label: str) -> str:
    return f"labelled message {message_id} -> {label}"


def summarise(text: str) -> str:
    return f"SUMMARY[{len(text)}]: {text[:80]}…"


def send_email(to: str, subject: str, body: str) -> str:
    """This function exists but the agent.yaml does NOT map it to a scope,
    so binding it as a tool fails at startup — the operator hasn't granted
    the agent permission to send email."""
    return f"sent email to {to}: {subject}"


# ----- build the runtime from config ----------------------------------------


def build_tools(runtime: IdentityRuntime) -> list[BaseTool]:
    """Bind each tool by name. Scope lookup happens in config, not in code."""

    safe_search = runtime.tool("web_search", web_search)
    safe_label = runtime.tool("apply_label", apply_label)
    safe_summarise = runtime.tool("summarise", summarise)

    class WebSearchTool(BaseTool):
        name: str = "web_search"
        description: str = "Search the web for a query string."

        def _run(self, query: str) -> str:
            return safe_search(query)

    class ApplyLabelTool(BaseTool):
        name: str = "apply_label"
        description: str = "Apply a label to a message."

        def _run(self, message_id: str, label: str) -> str:
            return safe_label(message_id, label)

    class SummariseTool(BaseTool):
        name: str = "summarise"
        description: str = "Summarise a block of text."

        def _run(self, text: str) -> str:
            return safe_summarise(text)

    return [WebSearchTool(), ApplyLabelTool(), SummariseTool()]


# ----- demo orchestration ---------------------------------------------------


def main() -> int:
    runtime = IdentityRuntime.from_config()

    print("=== Config-driven IdentityRuntime ===")
    print(f"  subject:     {runtime.system_identifier}")
    print(f"  tools known: {sorted(runtime.scope_map.keys())}")
    print(f"  audit at:    {runtime.identity._adapter._audit_store}")  # noqa: SLF001
    print()

    tools = build_tools(runtime)
    search_tool, label_tool, summarise_tool = tools

    with runtime:
        print("--- 1) web_search → scope web.read (allowed by config) ---")
        print(f"    {search_tool.run(query='quantum coherence')}")
        print()

        print("--- 2) apply_label → scope inbox.label (allowed by config) ---")
        print(f"    {label_tool.run(message_id='msg-42', label='follow-up')}")
        print()

        print("--- 3) summarise → scope text.summarise (allowed by config) ---")
        print(f"    {summarise_tool.run(text='Quantum coherence times have...')}")
        print()

        print("--- 4) try to bind send_email → config has no entry ---")
        try:
            runtime.tool("send_email", send_email)
            print("    UNEXPECTEDLY BOUND")
            return 2
        except Exception as exc:  # noqa: BLE001
            print(f"    refused at bind time: {type(exc).__name__}: {exc}")
        print()

        print("--- 5) revoke, retry web_search ---")
        runtime.identity.revoke(runtime.system_identifier, reason="demo: SOC pull")
        try:
            search_tool.run(query="another search")
            print("    UNEXPECTEDLY ACCEPTED")
            return 2
        except Exception as exc:
            print(f"    rejected: {type(exc).__name__}: {exc}")

    print()
    print("=== Audit log ===")
    data_dir = Path(runtime.identity._adapter._audit_store._path).parent if hasattr(  # noqa: SLF001
        runtime.identity._adapter._audit_store, "_path"  # noqa: SLF001
    ) else None
    if data_dir is None:
        # File backend stores audit.jsonl in the data_dir
        audit_path = Path(".asid-crewai-config-demo") / "audit.jsonl"
    else:
        audit_path = data_dir / "audit.jsonl"
    if audit_path.is_file():
        for i, line in enumerate(audit_path.read_text().strip().splitlines(), 1):
            row = json.loads(line)
            kind = row.get("kind", "?")
            action = (row.get("action") or {}).get("action_type") or row.get(
                "action_type"
            )
            sub = row.get("system_identifier", "?")
            print(f"  {i:>2}. kind={kind!s:<18} action={action!s:<18} subject={sub}")
    else:
        print(f"  (no audit log at {audit_path})")

    print()
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        # Keep audit dir for inspection; rm explicitly when re-running.
        pass
