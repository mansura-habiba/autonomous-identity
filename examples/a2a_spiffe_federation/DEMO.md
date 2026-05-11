# How to demo autonomous-identity

Three demos, ascending in setup cost. All run from the repo root.

## Setup once

```bash
cd /Users/mansurah/Development/autonomous-identity
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

If you'll run the LangGraph one too:

```bash
pip install -e ".[langgraph]"
```

If you'll push traces to Langfuse:

```bash
pip install -e ".[tracing-langfuse]"
```

---

## Demo 1 — Zero-setup terminal walkthrough (5 min)

Best for a quick technical screen-share. No SaaS, no UI, all output to the console
with color-coded traces.

### 1a. A2A federation across two SPIFFE trust domains

```bash
python examples/a2a_spiffe_federation/federation_demo.py
```

**What you'll see, in order:**

1. **Out-of-band trust bundle exchange.** tenant-b loads tenant-a's JWKS so it
   can verify inbound envelopes.
2. **Federated envelope minted by tenant-a.** SPIFFE ID for tenant-b, JWS signed
   by tenant-a's key, delegation chain carrying `spiffe.federation = True`.
3. **tenant-b verification + execution.** All four federation checks run, the
   work is exercised, an audit_ref comes back.
4. **Three negative cases — all rejected, all visible in trace as red error spans:**
   - tenant-b without tenant-a in its trust bundle → rejected
   - tenant-b trying to exercise a scope it was never granted → rejected
   - SVID JWS tampered in transit → rejected

**Narration points if you're presenting:**
- Point at the `federation=True` attribute on the second delegate span.
- When the scope-escalation negative case runs, both the `material_action`
  span AND the surrounding `exercise` span go red — error propagates up the
  call tree the same way it would in production.
- Each `audit_ref` is the handle into the append-only audit log; the demo
  prints the path to that log.

### 1b. LangGraph multi-agent inside one trust domain

```bash
python examples/langgraph_spiffe_multi_agent.py
```

Topology: `platform → orchestrator → {research, writer}`, all in `corp.example`.
Each LangGraph node runs under its own SPIFFE-bound envelope; every tool call
emits a material-action audit row.

**What to point at:**
- Effective scopes narrow strictly down the chain (orchestrator has all three,
  research has only `web.read`, writer has only `doc.write`).
- Each material action's span shows `required_scope` and `audit_ref`.
- The per-step trace at the bottom maps each step to its SPIFFE ID and audit
  reference.

---

## Demo 2 — Langfuse UI (for a CISO / non-engineer audience, 15 min)

This is the high-stakes show. Same scripts as Demo 1, but traces land in
Langfuse and you walk through them visually.

### Setup

```bash
pip install -e ".[tracing-langfuse]"
export LANGFUSE_PUBLIC_KEY=pk-lf-...
export LANGFUSE_SECRET_KEY=sk-lf-...
export LANGFUSE_HOST=https://cloud.langfuse.com   # or your self-hosted host
```

### Run

```bash
python examples/a2a_spiffe_federation/federation_demo.py
python examples/langgraph_spiffe_multi_agent.py
```

Both demos auto-detect the Langfuse env vars and switch from the console tracer
to the Langfuse tracer. If the env vars aren't set, you get the console output
from Demo 1 — same scripts, no code changes.

### What to show in the Langfuse UI

1. **Open the project → Traces.** Each top-level operation
   (issue, delegate, exercise) is its own trace. Filter by trace name
   `asid-fed-tenant-a`, `asid-fed-tenant-b`, or `asid-spiffe-langgraph`.

2. **Open the cross-trust-domain delegate trace.** This is the money screen.
   In a single pane you can point at every property the autonomous-identity
   envelope is supposed to give a CISO:

   ![Cross-trust-domain delegation in Langfuse](docs/images/langfuse-asid-delegate-federation.png)

   What to narrate, in order:

   - **`kind = asid.delegate`** — this is the span fired when one agent hands
     work to another. There is one of these for every hop in the chain.
   - **`parent_subject` → `child_subject`** — the SPIFFE IDs of the two
     workloads. Note the trust domain flips from `tenant-a.example` to
     `tenant-b.example` — this is a federation hop, not an internal one.
   - **`federation = true`** (highlighted orange in the Langfuse UI) — the
     adapter set this caveat on the delegation because the trust domains
     differ. Cross-TD delegation cannot happen by accident.
   - **`scopes = ["work.request"]`** — the only scope the federated child
     received. The parent had `[a2a.send, work.request, ops.read]`. This is
     monotone-decreasing delegation in one line of metadata.
   - **`expires_at = 2026-05-12T06:27:00+00:00`** — the SVID has a hard
     expiry. After this timestamp the envelope is dead even if the audit
     row exists.
   - **`lifecycle_state = active`** — the receiver-side lifecycle ledger
     said yes at the moment of issuance. If you revoke the SPIFFE ID, the
     next exercise span fails — try it live.
   - **`audit_ref = audit://file/18534c114...`** — the handle into the
     append-only audit log. Feed this into `asid inspect --audit-ref ...`
     to pull the signed row this span corresponds to.
   - **`trace_id` / `span_id` / `delegation_depth`** — OTel-shaped trace
     metadata. `delegation_depth=2` means this is the second hop in the
     chain (root → initiator → processor).
   - **No SVID, no signature, no envelope JSON in this view.** That's by
     design — see "What's deliberately NOT in Langfuse" below.

3. **Open an exercise trace.** It contains a nested material_action span.
   The material_action span carries `action_type`, `required_scope`, and
   `audit_ref`. Tell them: "the audit_ref is the entry in the signed,
   append-only log that proves this action happened under this envelope."

4. **Open one of the failing traces (run Demo 1's federation script
   first so the negative cases produce them).** Status: ERROR.
   Status message: "Required scope 'a2a.send' not in effective scopes
   ['work.request']". Tell them: "this is the scope-escalation guardrail
   firing at the moment of exercise, not at session start. Even if the
   envelope was minted an hour ago, the check runs *now*."

### What's deliberately NOT in Langfuse

Open the metadata of any span. Look for: there's no raw input payload, no
SVID JWS, no signature, no envelope JSON. The library defaults to shipping
**identity metadata and content hashes** to telemetry, not the underlying
data or credentials. This matters: telemetry pipelines run through SaaS,
shipping the SVID itself would widen the credential blast radius.

If you want raw I/O in Langfuse for local debugging, swap `ConsoleTracer()`
or `LangfuseTracer()` for `LangfuseTracer(capture_io=True)` in the demo's
`_build_tracer()` function. Production should leave this off.

---

## Demo 3 — Langflow visual multi-agent flow (for a "make it real" audience, 30 min)

This is the most visual demo: drop Identity Agents into a Langflow canvas,
wire envelopes between them, type a prompt in the chat panel, watch the
audit log grow.

### Setup

```bash
# 1) Install Langflow itself if you don't have it.
pip install langflow

# 2) Install autonomous-identity into the same environment so Langflow can
#    import it from your component.
pip install -e /Users/mansurah/Development/autonomous-identity

# 3) Start Langflow.
langflow run
```

### Register the IdentityAgent component

Option A (fastest) — paste it as a Custom Component:

1. Open Langflow → New Flow.
2. Drag a "Custom Component" node onto the canvas.
3. Paste the contents of `/Users/mansurah/GitHub/langflow/custom_components/identity_agent.py`
   into the code editor and save.

Option B — drop it into Langflow's component scan path. Refer to
`custom_components/IDENTITY_AGENT_DEMO.md` for the path your Langflow
install uses.

### Build the 5-agent demo flow

Follow the topology in
[`custom_components/IDENTITY_AGENT_DEMO.md`](../GitHub/langflow/custom_components/IDENTITY_AGENT_DEMO.md):

```
Chat Input  →  [Identity Agent: planner]
                  system_id      = agent://demo/planner
                  caller_subject = user:chat
                  issuer_scopes  = orchestrate,agent.invoke,web.read,doc.write,doc.review
                  required_scope = orchestrate
                  → Response → [Identity Agent: researcher].Input
                  → Envelope (downstream) → [Identity Agent: researcher].Parent envelope
                                              system_id      = agent://demo/researcher
                                              allowed_scopes = agent.invoke,web.read
                                              required_scope = web.read
                                              → Response  → [Identity Agent: summarizer].Input
                                              → Envelope  → [Identity Agent: summarizer].Parent envelope
                                                              ... (chain continues)
```

All Identity Agents share the same identity store path
(`.asid-langflow` by default) so they write to one audit trail.

### Run it

Type a prompt in the Chat Input. As each agent processes:
- The Response is the chat answer.
- The Delegation Receipt output (Data) shows that agent's SPIFFE ID,
  effective scopes, origin (user vs upstream agent), and audit_ref.
- The Envelope output flows downstream so the next agent self-delegates.

### Inspect the audit log

```bash
tail -f .asid-langflow/audit.jsonl | jq .
```

Or via the CLI:

```bash
asid --store file --data-dir .asid-langflow inspect \
  --audit-ref 'audit://file/<id-from-a-receipt>'
```

---

## Known issue worth pre-empting in the demo

`wrap_tools_for_identity` mutates `BaseTool.invoke` directly, which Pydantic v2
(used by current langchain-core) rejects. The demos and component still
record the **agent-to-agent delegation** and the **agent.invoke** material
action, but per-tool audit rows won't emit until that helper is refactored
to subclass-wrap rather than mutate. If a tool call triggers it the audit
chain still has the agent.invoke hop — just no row per tool.

---

## What to say at the end

Three things actually demonstrated:

1. **Identity is checked at the moment of exercise.** Not at session start.
   Revoke or rotate or restrict the lifecycle between two seconds and the
   next material action gets blocked.
2. **Scope is monotone-decreasing across delegation.** Cross-trust-domain
   delegation requires an explicit federation caveat that lands in the audit
   row. No agent can manufacture authority it didn't receive.
3. **Every material action carries an audit_ref into a signed, append-only
   log.** Tampering breaks the hash chain (Merkle adapter) or the JWS
   signature (SPIFFE adapter). You can hand a CISO a single audit_ref and
   they can reconstruct: who acted, under whose authority, with what scopes,
   against what envelope, signed by which key, at what time.
