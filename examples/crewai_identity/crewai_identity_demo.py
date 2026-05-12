"""CrewAI + autonomous-identity, runnable without any LLM API key.

This script demonstrates the **Stage 1 integration pattern** end-to-end
against a real CrewAI install. It does NOT require an OpenAI / Anthropic
API key — the demo exercises CrewAI's ``BaseTool`` machinery directly so
the identity gate is provably the thing rejecting / allowing each call,
not the LLM.

For the full Crew run (with a real LLM driving the agent), see
``crewai_identity_with_crew.py`` in this folder.

Run::

    pip install -e ".[dev]"
    pip install crewai
    python examples/crewai_identity/crewai_identity_demo.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from crewai.tools import BaseTool

from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.integrations.runtime import IdentityRuntime


# ----- raw tool functions ----------------------------------------------------

def _raw_web_search(query: str) -> str:
    """Pretend to call a search API; return a deterministic stub."""
    return f"results:[{query}]"


def _raw_apply_label(message_id: str, label: str) -> str:
    """Pretend to apply a label to a message."""
    return f"labelled message {message_id} -> {label}"


def _raw_send_email(to: str, subject: str, body: str) -> str:
    """Pretend to send an email. Never wired to a real SMTP server here."""
    return f"sent email to {to}: {subject}"


# ----- wrap them under identity ---------------------------------------------

def build_identity_and_runtime(data_dir: Path) -> IdentityRuntime:
    identity = AutonomousIdentity.local(
        data_dir,
        adapter_name="spiffe",
        strictness=ValidatorStrictness.STRICT,
    )
    envelope = identity.issue_envelope(
        {
            "system_identifier": "spiffe://corp.example/agents/inbox-triage",
            "instance_id": "triage-prod-1",
            "deployment_id": "release-2026-05-11",
            "owner_id": "team:platform",
            "provenance": {
                "code_hash": "sha256:abcdef",
                "policy_bundle_hash": "sha256:policy-v3",
            },
            "attestation_chain": ["local:bootstrap"],
            # Intentionally NO email.send — the demo proves that an action
            # the envelope never received is rejected at the moment of
            # exercise, not at startup.
            "issuer_scopes": ["web.read", "inbox.label"],
        }
    )
    return IdentityRuntime(identity, envelope)


# ----- wrap raw functions, then plug them into CrewAI BaseTool subclasses ---

def build_crewai_tools(runtime: IdentityRuntime) -> tuple[BaseTool, BaseTool, BaseTool]:
    # The wrapped callables ARE the identity gate. Each call to
    # safe_search(...) re-verifies the envelope, enforces the scope, and
    # writes a signed audit row before the underlying function runs.
    safe_search = runtime.wrap_tool(
        _raw_web_search,
        required_scope="web.read",
        action_type="web.search",
    )
    safe_label = runtime.wrap_tool(
        _raw_apply_label,
        required_scope="inbox.label",
        action_type="inbox.label",
    )
    safe_send = runtime.wrap_tool(
        _raw_send_email,
        required_scope="email.send",          # <-- envelope never received this
        action_type="email.send",
    )

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

    class SendEmailTool(BaseTool):
        name: str = "send_email"
        description: str = "Send an email."

        def _run(self, to: str, subject: str, body: str) -> str:
            return safe_send(to, subject, body)

    return WebSearchTool(), ApplyLabelTool(), SendEmailTool()


# ----- demo ------------------------------------------------------------------


def main() -> int:
    data_dir = Path(tempfile.mkdtemp(prefix="asid-crewai-demo-"))
    try:
        runtime = build_identity_and_runtime(data_dir)
        search_tool, label_tool, send_tool = build_crewai_tools(runtime)

        print("=== CrewAI tools wrapped under SPIFFE identity ===")
        print(f"acting agent:   {runtime.system_identifier}")
        print(f"audit store:    {data_dir / 'audit.jsonl'}")
        print()

        # Inside the runtime: envelope is exercised, every wrapped call runs
        # through the identity gate.
        with runtime:
            print("--- 1) web.read action: ALLOWED  ---")
            out = search_tool.run(query="recent quantum coherence papers")
            print(f"    tool output: {out}")
            print()

            print("--- 2) inbox.label action: ALLOWED ---")
            out = label_tool.run(message_id="msg-42", label="follow-up")
            print(f"    tool output: {out}")
            print()

            print("--- 3) email.send action: REJECTED (scope not granted) ---")
            try:
                send_tool.run(to="ceo@corp.example", subject="lol", body="hi")
                print("    UNEXPECTEDLY ACCEPTED")
                return 2
            except VerificationError as exc:
                print(f"    rejected: {exc}")
            print()

            print("--- 4) revoke the agent's identity, then retry web.read ---")
            runtime.identity.revoke(
                runtime.system_identifier,
                reason="demo: simulate SOC pulling the agent",
            )
            try:
                search_tool.run(query="another search")
                print("    UNEXPECTEDLY ACCEPTED AFTER REVOKE")
                return 2
            except Exception as exc:
                print(f"    rejected post-revoke: {type(exc).__name__}: {exc}")

        print()
        print("=== Audit log inspection ===")
        audit_lines = (data_dir / "audit.jsonl").read_text().strip().splitlines()
        print(f"{len(audit_lines)} signed rows written.")
        for i, line in enumerate(audit_lines, 1):
            row = json.loads(line)
            kind = row.get("kind", "?")
            sub = row.get("system_identifier", "?")
            action = (row.get("action") or {}).get("action_type") or row.get(
                "action_type"
            )
            print(f"  {i:>2}. kind={kind!s:<18} subject={sub} action={action}")

        print()
        print("ALL CHECKS PASSED")
        return 0
    finally:
        # Keep the audit dir around for inspection unless caller sets KEEP=0.
        import os

        if os.environ.get("KEEP_ASID_DEMO_DIR") in (None, "", "0"):
            shutil.rmtree(data_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
