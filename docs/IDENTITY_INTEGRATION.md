# Stage 1: Identity for any AI framework

Identity comes first. Delegation comes later.

This guide gets a verifiable autonomous-system identity attached to a
single AI system — one agent, one envelope, signed audit row per material
action — regardless of which framework you're on. Multi-agent delegation
and cross-trust-domain federation are *Stage 2* and live in
[`MULTI_AGENT_INTEGRATION.md`](MULTI_AGENT_INTEGRATION.md). Do not skip
to Stage 2 until Stage 1 is wired and producing audit rows you can
inspect.

---

## The shape of Stage 1

```
   AI system starts up
        │
        ▼
   identity.issue_envelope({...})   ← happens once at startup
        │
        ▼
   runtime = IdentityRuntime(identity, envelope)
        │
        ▼
   wrap every tool the agent will call
   (runtime.wrap_tool(fn, required_scope="..."))
        │
        ▼
   inside the agent loop:
      with runtime:
          agent.run(...)            ← every tool call is audited
        │
        ▼
   .asid/audit.jsonl now has signed rows
   bound to this envelope's commitment hash
```

Three lines of glue per framework. No subclassing. No mutation of the
framework's internals. The wrapped tool is a *new* callable; the original
is untouched.

---

## The three primitives you need

1. **One envelope at startup.** `identity.issue_envelope({...})` issues
   the envelope your AI system runs under. Do this once per process.
2. **One runtime bound to the envelope.** `IdentityRuntime(identity, env)`
   bundles the envelope and the audit/verify machinery.
3. **Per-tool wrapping at registration time.** `runtime.wrap_tool(fn,
   required_scope="...")` returns a *new* callable. Hand the wrapped
   callable to your framework's tool list. The original is untouched.

Nothing in Stage 1 requires `delegate()`. Nothing requires multiple
agents. A single AI system using a single envelope is a complete,
auditable identity story.

---

## Recipe 1 — Plain Python orchestrator (no framework)

The minimal case. Useful for understanding what the runtime actually does
before you wire it into a framework.

```python
from pathlib import Path
from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.integrations.runtime import IdentityRuntime

identity = AutonomousIdentity.local(
    Path(".asid"),
    adapter_name="spiffe",
    strictness=ValidatorStrictness.STRICT,
)

# Issue once at startup. owner_id should be your team / service principal.
envelope = identity.issue_envelope({
    "system_identifier": "spiffe://corp.example/agents/email-triage",
    "instance_id": "email-triage-prod-1",
    "deployment_id": "release-2026-05-11",
    "owner_id": "team:platform",
    "provenance": {
        "code_hash": "sha256:" + your_commit_sha,
        "policy_bundle_hash": "sha256:" + your_policy_hash,
    },
    "attestation_chain": ["local:bootstrap"],
    "issuer_scopes": ["email.read", "email.label", "email.archive"],
})

runtime = IdentityRuntime(identity, envelope)

# Wrap each tool the agent can call.
def read_inbox(limit: int) -> list[dict]: ...
def apply_label(message_id: str, label: str) -> None: ...
def archive(message_id: str) -> None: ...

read_inbox   = runtime.wrap_tool(read_inbox,   required_scope="email.read")
apply_label  = runtime.wrap_tool(apply_label,  required_scope="email.label")
archive      = runtime.wrap_tool(archive,      required_scope="email.archive")

# Run the agent inside the runtime context. Every wrapped tool call writes
# a signed audit row bound to this envelope.
with runtime:
    for msg in read_inbox(50):
        if msg["from"].endswith("@spam.example"):
            apply_label(msg["id"], "spam")
            archive(msg["id"])
```

What just happened, in identity terms:

- The envelope was verified before each tool call (lifecycle, signature,
  scope). If someone revokes `spiffe://corp.example/agents/email-triage`
  between two messages, the next `apply_label` call fails.
- The audit log at `.asid/audit.jsonl` has one signed row per tool call.
  Each row carries the envelope's commitment hash, the input hash, the
  output hash, the action type, the required scope, and a timestamp.
- If `apply_label` is called with `required_scope="email.label"` but the
  envelope only had `["email.read"]`, the call fails at the moment of
  exercise — not at startup.

---

## Recipe 2 — LangChain

LangChain tools are `BaseTool` instances. Wrap them at construction time
and hand the wrapped callable to the agent.

```python
from langchain_core.tools import tool
from autonomous_identity.integrations.runtime import IdentityRuntime

runtime = IdentityRuntime(identity, envelope)

@tool
def fetch_url(url: str) -> str:
    """Fetch a URL and return the page text."""
    import requests
    return requests.get(url).text

# Wrap the function under the tool, not the BaseTool itself.
# This avoids the pydantic-v2 "BaseTool has no field 'invoke'" trap.
safe_fetch = runtime.wrap_tool(
    fetch_url.func,
    required_scope="web.read",
    action_type="web.fetch",
)

# Rebuild the tool around the wrapped function.
from langchain_core.tools import StructuredTool
safe_fetch_tool = StructuredTool.from_function(
    safe_fetch,
    name="fetch_url",
    description="Fetch a URL and return the page text.",
)

# Hand the wrapped tool to the agent.
agent = ToolCallingAgent(llm=llm, tools=[safe_fetch_tool])

with runtime:
    agent.invoke({"input": "Summarise the front page of example.com"})
```

If you control the tool definitions, the simpler pattern is to skip
`@tool` on the raw function and only call `StructuredTool.from_function`
once, on the wrapped callable.

---

## Recipe 3 — CrewAI

CrewAI tools subclass `BaseTool`. Same pattern: wrap the underlying
function, rebuild the tool around it.

```python
from crewai import Agent, Task, Crew
from crewai.tools import BaseTool
from autonomous_identity.integrations.runtime import IdentityRuntime

runtime = IdentityRuntime(identity, envelope)

def _raw_search(query: str) -> str:
    return external_search_api.search(query)

safe_search = runtime.wrap_tool(_raw_search, required_scope="web.read")

class SearchTool(BaseTool):
    name: str = "search"
    description: str = "Search the web."
    def _run(self, query: str) -> str:
        return safe_search(query)

researcher = Agent(
    role="Researcher",
    goal="Find sources for the report",
    tools=[SearchTool()],
)

with runtime:
    Crew(agents=[researcher], tasks=[Task(description="...", agent=researcher)]).kickoff()
```

The CrewAI agent has no idea identity exists. Every search call still
runs through the envelope check.

---

## Recipe 4 — AutoGen

AutoGen registers tools via decorators on the agent. Wrap before
registering.

```python
from autogen_agentchat.agents import AssistantAgent
from autonomous_identity.integrations.runtime import IdentityRuntime

runtime = IdentityRuntime(identity, envelope)

def raw_query_db(sql: str) -> list[dict]:
    return db.execute(sql).fetchall()

safe_query = runtime.wrap_tool(
    raw_query_db,
    required_scope="db.read",
    action_type="db.query",
)

agent = AssistantAgent(
    name="analyst",
    llm_config={...},
    tools=[safe_query],         # AutoGen sees the wrapped callable directly
)

with runtime:
    asyncio.run(agent.run(task="How many records last week?"))
```

---

## Recipe 5 — Pydantic AI

Pydantic AI uses `@agent.tool` decorators. Apply the wrapping inside the
tool body rather than around the function — Pydantic AI inspects the
function signature for type hints.

```python
from pydantic_ai import Agent
from autonomous_identity.integrations.runtime import IdentityRuntime

runtime = IdentityRuntime(identity, envelope)
agent = Agent("openai:gpt-4o", system_prompt="...")

@agent.tool_plain
def search(query: str) -> str:
    return runtime.run(
        action_type="web.search",
        required_scope="web.read",
        fn=lambda q: external_search.search(q),
        query,
    )["result"]

with runtime:
    print(agent.run_sync("Find recent papers on quantum coherence times").data)
```

Same effect: every call to `search` is gated by the envelope and writes
a signed audit row.

---

## Recipe 6 — Letta / MemGPT

Letta tools are registered via `client.tools.create`. Define the wrapped
callable first, then register it.

```python
from letta_client import Letta
from autonomous_identity.integrations.runtime import IdentityRuntime

runtime = IdentityRuntime(identity, envelope)

def _raw_send_email(to: str, subject: str, body: str) -> str:
    return mail_client.send(to=to, subject=subject, body=body)

safe_send_email = runtime.wrap_tool(
    _raw_send_email,
    required_scope="email.send",
    action_type="email.send",
)

client = Letta(...)
client.tools.create_from_function(safe_send_email, name="send_email")

with runtime:
    client.agents.messages.create(agent_id="...", messages=[...])
```

---

## Recipe 7 — HTTP / RPC service (no Python framework)

Identity isn't only for in-process agents. If your AI system is a service
behind an HTTP endpoint, the same primitives apply at the handler level.

```python
from fastapi import FastAPI, HTTPException
from autonomous_identity.integrations.runtime import IdentityRuntime

app = FastAPI()
runtime = IdentityRuntime(identity, envelope)

def _raw_summarise(text: str) -> str:
    return llm.summarise(text)

safe_summarise = runtime.wrap_tool(
    _raw_summarise,
    required_scope="text.summarise",
)

@app.post("/summarise")
def summarise(payload: dict) -> dict:
    with runtime:
        try:
            result = safe_summarise(payload["text"])
        except VerificationError as exc:
            raise HTTPException(403, detail=str(exc))
    return {"summary": result}
```

Every request runs through the envelope. The lifecycle check fires per
request; revoking the agent's identity stops the next request, not the
next session.

---

## What you get for free, once any of these recipes are wired

* **`.asid/audit.jsonl`** — one signed row per material action. Each row
  carries the envelope commitment hash, input hash, output hash, action
  type, required scope, verified-at timestamp, and audit_ref.
* **Lifecycle revocation that takes effect at the next action.** Run
  `asid revoke --system-id spiffe://corp.example/agents/email-triage
  --reason rotated` and watch the very next wrapped call raise
  `LifecycleError`.
* **Cryptographic replay.** Feed any `audit_ref` to
  `asid inspect --audit-ref ...` and you get back the signed row,
  reconstructable against the envelope by any verifier holding the
  envelope's JWKS (for SPIFFE) or the Merkle public key (for the chain
  adapter).
* **Tracing for free.** Replace `IdentityRuntime(identity, envelope)`
  with `TracedIdentity(identity, tracer=ConsoleTracer())` plus
  `IdentityRuntime(traced_identity, envelope)` and every action emits a
  span. Wire `LangfuseTracer` and the spans land in the Langfuse UI.

---

## What is NOT in Stage 1

* **No multi-agent delegation.** No `runtime.handoff(...)`. No child
  envelopes. No parent→child scope narrowing. If you only have one AI
  system, you do not need any of this. If you have multiple, see
  [`MULTI_AGENT_INTEGRATION.md`](MULTI_AGENT_INTEGRATION.md) (Stage 2).
* **No cross-trust-domain federation.** That's a Stage 2 capability and
  it builds on Stage 2 delegation.
* **No automatic provenance binding.** Your `code_hash` /
  `policy_bundle_hash` come from wherever you build them — a CI hook,
  a git commit, your release manifest. Stage 1 just plumbs the values
  through.

Each of those is a real concern. None of them is a Stage 1 concern. Get
identity working for one agent, get the audit log to produce rows you
can inspect, then move on.

---

## A short checklist before you call Stage 1 done

1. The agent runs and produces output. ✓
2. `.asid/audit.jsonl` grows by exactly one line per tool call. ✓
3. Running `asid revoke --system-id <your-id> --reason test` causes the
   next tool call to raise `LifecycleError`. ✓
4. `asid inspect --audit-ref <any ref from the log>` returns a signed row
   that reconstructs the envelope's commitment hash. ✓
5. A tool call with `required_scope` not in `issuer_scopes` raises
   `VerificationError`. ✓

If any of those isn't true, fix it before adding a second agent.

---

## When to move to Stage 2

Move to Stage 2 when you have a real second AI system that should run
under a *narrower* identity than the first — a sub-agent that should
only have read access, a tool-runner that should only have one specific
scope, a partner organization that should receive a federated envelope
across a trust-domain boundary. Until you have that real second system,
Stage 1 is enough.

See [`MULTI_AGENT_INTEGRATION.md`](MULTI_AGENT_INTEGRATION.md) when you
get there.
