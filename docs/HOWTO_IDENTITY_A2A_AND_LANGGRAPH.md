# How to use autonomous-identity with A2A or LangGraph

This guide explains how to attach **verifiable identity envelopes** to autonomous systems built on **Google A2A** (`a2a-sdk`) or **LangGraph**, using the same library primitives in both worlds.

## What you are wiring in

1. **`AutonomousIdentity`** — facade over an **identity adapter** (default `merkle_chain`), **lifecycle** store, **audit** store, and signer. Typical construction: `AutonomousIdentity.local(Path("…/data"), strictness=…)`.

2. **`IdentityEnvelope`** — credential for a **principal** (`system_identifier`), with provenance, optional **delegations** (narrowed child subjects + scopes), and adapter-specific metadata (for Merkle: tip hash, public key, audit pointer).

3. **`issue_envelope(issue_context)`** — mints an envelope, validates it, verifies it with the adapter, and records **lifecycle** as active for that `system_identifier`.

4. **`with identity.exercise(envelope):`** — sets the envelope as the **current identity context** for the duration of the block.

5. **Material actions** — any sensitive work should run through **`identity.run_material_action(...)`** (or `@identity.material_action(...)`), which re-checks lifecycle, delegation expiry, optional **scopes**, envelope verification, then executes your callable and appends an **audited** adapter event (Merkle: new signed chain node; returns `audit_ref`).

You do **not** need LangGraph or A2A inside the library; they only decide **where** the envelope comes from and **where** you call `exercise` + `run_material_action`.

---

## LangGraph

### Install

```bash
pip install -e ".[langgraph]"
# or: uv sync --extra langgraph
```

### Pattern

- Build envelopes **when you invoke the graph** (or when a supervisor node runs), not necessarily at import time.
- Put envelopes on **graph state** (for example `state["envelopes"]["research"]`).
- Wrap each node so the body runs under the right envelope without repeating `exercise` boilerplate.

Use **`wrap_langgraph_node`** from `autonomous_identity.integrations.langgraph`:

```python
from pathlib import Path
from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.integrations.langgraph import wrap_langgraph_node

identity = AutonomousIdentity.local(Path(".asid-graph"), strictness=ValidatorStrictness.STRICT)

# After you have state["envelopes"]["research"] = <IdentityEnvelope>:
graph.add_node(
    "research",
    wrap_langgraph_node(identity, lambda s: s["envelopes"]["research"], do_research),
)
```

- **Fixed envelope:** `wrap_langgraph_node(identity, env_obj, fn)` if the envelope never changes per run.
- **Decorator:** `langgraph_identity(identity, envelope)(fn)` is equivalent sugar.

### Runtime delegation tree

For **multi-agent** flows where each role gets a **narrower** envelope, build a spec (issue context + delegation edges) and call **`issue_and_delegate_tree(identity, spec)`** from `autonomous_identity.application.delegation_chain`. That returns a map of role names to envelopes you can store on state. Full example:

- [`examples/langgraph_multi_agent_delegation.py`](../examples/langgraph_multi_agent_delegation.py)

### Scopes and tools

- **Optional authorization:** put **`issuer_scopes`** on the **root** issue context only if you need string grants to subset; identity (subject, provenance, signatures) does not require them.
- **`delegate`** strips `issuer_scopes` on the child; downstream capability strings come from **`Delegation.allowed_scopes`** (or `[]` for identity-only hops).
- Use **`identity.delegate(...)`** or the tree helper for explicit parent→child chains.
- For LangChain tools, see **`identity_protected_tool`** (`pip install -e ".[langchain]"`) in `integrations/langchain.py`.
- **Namespace convention:** use **`asid:<namespace>:<service>:<capability>`** strings (see [SCOPE_CONVENTION.md](SCOPE_CONVENTION.md)) and set **`enforce_scope_convention=True`** on `AutonomousIdentity.local(...)` when you want the library to reject non-conforming scope strings.

---

## A2A (Agent2Agent)

### Install

```bash
pip install -e ".[a2a]"
# or: uv sync --extra a2a
```

### Pattern

A2A carries **user text** and **task metadata**; it does not define identity. You treat the envelope as **application metadata** on each `SendMessage` (or your own extension later).

1. **Issuer** (parent agent, policy service, or control plane) calls **`identity.issue_envelope(...)`** or **`issue_and_delegate_tree`** and serializes the envelope the **downstream** agent must use.

2. **Client** sends JSON-RPC `SendMessage` with metadata, for example:
   - Key: `autonomous_identity.envelope_json`
   - Value: **single JSON string** produced from `envelope_to_serializable(envelope)` (compact JSON is fine).

3. **Server** `AgentExecutor` reads metadata, **`envelope_from_serializable`**, validates, **`identity._adapter.verify(envelope)`**, then:

   ```python
   with identity.exercise(envelope):
       proof = identity.run_material_action(
           envelope,
           action_type="your.vendor.action_name",
           required_scope=None,  # or a scope string if you use root issuer_scopes / delegation grants
           fn=lambda: your_logic(),
           args=(),
           kwargs={},
       )
   ```

Reference implementation:

- [`examples/a2a_identity_agent/`](../examples/a2a_identity_agent/) — `README.md`, `server.py`, `agent_executor.py`, `bootstrap_envelope.py`, `demo_client.py`
- Server and client call **`a2a_upb_compat.apply()`** before other `a2a` imports on some Python/protobuf builds (see that folder’s README).

### Data directory and lifecycle

The demo resolves identity data under **`<repo>/.asid-a2a-demo`** from script paths so the **issuer** (bootstrap) and **server** share lifecycle and Merkle state. Override with **`ASID_A2A_DATA_DIR`** if you deploy elsewhere.

If the server sees “**No lifecycle record**” for the envelope’s `system_identifier`, the server’s store never received **`issue_envelope`** for that principal on that disk (wrong directory, or envelope minted out-of-band). Fix by issuing from the same `AutonomousIdentity` / `data_dir` the server uses, or by aligning paths.

### Multi-hop A2A

Issue a **leaf** envelope (after delegation) and attach **that** JSON on the downstream `SendMessage`. Same metadata contract at every hop.

---

## Serialization (A2A, HTTP, queues)

Stable JSON for wires and logs:

```python
from autonomous_identity.core.serialize import envelope_to_serializable, envelope_from_serializable

payload = envelope_to_serializable(envelope)
# transport as JSON string if your protocol wants a string field
text = json.dumps(payload, separators=(",", ":"))

round_trip = envelope_from_serializable(json.loads(text))
```

---

## After an action: audit

- **`proof["audit_ref"]`** from `run_material_action` points at the append-only audit row (file: `audit://file/…`).
- **`identity.verify_audit_ref(audit_ref)`** — for `merkle_chain`, verifies the stored node signature and shape.

---

## Choosing an approach

| Concern | LangGraph | A2A |
|--------|------------|-----|
| Where envelope lives | Graph state (or fixed closure) | `SendMessageRequest.metadata` (or your convention) |
| Where you call `exercise` | Inside `wrap_langgraph_node` | Inside your `AgentExecutor.execute` |
| Who issues | Your orchestration code before `invoke` | Parent / policy before each `sendMessage` to a child agent |
| Demo | `examples/langgraph_multi_agent_delegation.py` | `examples/a2a_identity_agent/` |

Both can use **`issue_and_delegate_tree`** for multi-principal graphs or agent chains; only the **transport** of the envelope bytes differs.
