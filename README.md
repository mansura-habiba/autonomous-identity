# autonomous-identity

Python library for **verifiable identity envelopes** on **material actions**: identity is checked at the moment of exercise, not only at session start.

## Quickstart (code)

```python
from pathlib import Path
from autonomous_identity import AutonomousIdentity, ValidatorStrictness

identity = AutonomousIdentity.local(Path(".asid"), strictness=ValidatorStrictness.STRICT)
envelope = identity.issue_envelope({
    "system_identifier": "agent://tenant/demo",
    "instance_id": "i-1",
    "deployment_id": "d-1",
    "owner_id": "team:demo",
    "provenance": {"code_hash": "sha256:abc", "policy_bundle_hash": "sha256:def"},
    "attestation_chain": ["local:bootstrap"],
})

@identity.material_action(action_type="demo.ping")
def ping() -> str:
    return "pong"

with identity.exercise(envelope):
    print(ping())
```

See `examples/` for storage swaps, LangChain, LangGraph multi-agent delegation, Langflow, delegation handoff, and **[A2A (Agent2Agent) + identity](examples/a2a_identity_agent/README.md)** (`pip install -e ".[a2a]"`). Step-by-step integration for **A2A + LangGraph**: [docs/HOWTO_IDENTITY_A2A_AND_LANGGRAPH.md](docs/HOWTO_IDENTITY_A2A_AND_LANGGRAPH.md).

**Demos:** `./scripts/demo.sh help` — clean local demo stores, install extras (`dev`, `langchain`, `langgraph`), run a named example. Same targets via `make help`, `make clean`, `make install`, `make demo-langgraph`, `make fresh-langgraph` (clean + install + langgraph demo).

### Delegation (narrowed handoff)

Identity is complete **without** scope strings; **`issuer_scopes`** (optional) are **authorization** hints you may put on the **root** issue context (`envelope.metadata`). **`identity.delegate(..., allowed_scopes, ...)`** mints a child envelope whose `system_identifier` is the child URI; the adapter **drops** `issuer_scopes` on the child so capability strings for that actor live only in **`Delegation.allowed_scopes`** (use `[]` for an identity-only handoff). Non-empty child scopes must be a **subset** of the parent’s effective scopes. **`@identity.material_action(..., required_scope="...")`** checks the required string against effective scopes (and expiry). Example: [`examples/delegate_handoff.py`](examples/delegate_handoff.py). CLI: `asid issue ... --issuer-scopes a,b` then `asid delegate --parent-json ...`.

For production-scale naming, use the optional **asid scope v1** grammar and opt-in enforcement (`enforce_scope_convention=True` on `AutonomousIdentity.local` or `identity.enforce_scope_convention` in YAML); see [docs/SCOPE_CONVENTION.md](docs/SCOPE_CONVENTION.md).

## CLI

```bash
pip install -e ".[dev]"
asid --store file --data-dir .asid issue \
  --system-id agent://tenant/demo \
  --instance-id i-1 --deployment-id d-1 \
  --owner team:demo \
  --code-hash sha256:abc --policy-hash sha256:def

asid --store file --data-dir .asid verify --audit-ref 'audit://file/...'
asid --store file --data-dir .asid revoke --system-id agent://tenant/demo --reason rotated
asid --store file --data-dir .asid inspect --audit-ref 'audit://file/...'
```

Delegation CLI: export a parent envelope to JSON (see `examples/delegate_handoff.py`), then:

```bash
asid delegate --store file --data-dir .asid --parent-json parent-envelope.json \
  --child-system-id agent://tenant/child --scopes orders.read
```

## Configuration

- **Storage:** `file` (default under `data_dir`), `sqlite`, `postgres` (requires `pip install autonomous-identity[postgres]`), or `memory` (tests).
- **Identity adapter:** `identity.adapter` in YAML; v0.1 ships **`merkle_chain`** only. Unknown adapters fail at startup with a clear error.

Example: `examples/identity_adapter_config.yaml`.

## Optional extras

- `pip install autonomous-identity[langchain]` — LangChain tool wrapper (`identity_protected_tool`).
- `pip install autonomous-identity[langgraph]` — LangGraph multi-agent + delegation demo ([`examples/langgraph_multi_agent_delegation.py`](examples/langgraph_multi_agent_delegation.py)): four principals; nodes are registered with **`wrap_langgraph_node(identity, envelope, fn)`** so identity context is automatic. Research uses **FastMCP** + `Client(FastMCPTransport(...))` + `load_mcp_tools` (Nexa-Claw `agentic`-style in-process MCP). Optional stdio server: [`examples/mcp_research_server.py`](examples/mcp_research_server.py).
- `pip install autonomous-identity[postgres]` — PostgreSQL lifecycle + audit stores.
- Langflow: see `examples/langflow/README.md` and `wrap_tools_for_identity`.

## Architecture

- `core/` — envelope types, validation, hashing (no I/O frameworks).
- `application/` — `AutonomousIdentity` facade; runtime delegation tree helper `issue_and_delegate_tree` ([`delegation_chain.py`](src/autonomous_identity/application/delegation_chain.py)) for issue + ordered delegate edges from plain data.
- `adapters/` — `IdentityAdapter` implementations + registry.
- `storage/` — `LifecycleStore` / `AuditStore` protocols + file/sqlite/postgres.
- `integrations/` — LangChain / Langflow helpers, plus **LangGraph** identity binding ([`integrations/langgraph.py`](src/autonomous_identity/integrations/langgraph.py): `wrap_langgraph_node`, `langgraph_identity`) so each graph node runs under the right envelope without repeating `exercise(...)`.

## Roadmap

Future work includes **multi-principal handoff** (user or peer system → agent) with **delegation reflected** on the envelope and in append-only audit, plus DAG-style evidence for cross-system flows. See [ROADMAP.md](ROADMAP.md).

## License

Apache-2.0
