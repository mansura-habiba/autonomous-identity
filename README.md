# autonomous-identity

> Identity is not the session. Identity is the moment of action.

Verifiable identity envelopes for autonomous systems, re-checked at every
material action rather than once at session start.

---

## The thesis

Most agent-identity in production today is a JWT minted when a session opens
and a string in a database. By the time the agent invokes a privileged tool,
the JWT may have been rotated, the policy bundle may have changed, the
workload may have been recompiled with a different code hash, the human
principal may have left the organization, the deployment may have been
revoked. An identity that was valid at 14:07:33 is not necessarily valid at
14:07:34.

This library treats identity as a property of the *moment of exercise*, not
of the session. Every material action — every tool call, state mutation,
decision, or sub-agent delegation — carries a portable identity envelope
that is re-verified at action time against an active lifecycle state, the
current scope grants, and a signed delegation chain rooted in a human
principal.

The envelope must demonstrate eight properties for the identity to be
governable:

1. **Persistent** — stable across sessions, restarts, and execution environments.
2. **Addressable** — independently referable as a subject (`agent://...`, `spiffe://...`).
3. **Verifiable** — cryptographically provable at the moment of exercise, not just at session start.
4. **Attenuable** — anchored to a human/team/org; delegation can only narrow authority, never expand it.
5. **Instance-specific** — distinguishes runtime instances of the same code.
6. **Provenance-aware** — bound to code, model, configuration, and policy hashes.
7. **Lifecycle-controlled** — can be created, restricted, suspended, rotated, and retired independently of the code that uses it.
8. **Auditable** — every action links back to system identity, runtime instance, owner, and verification chain.

No single cryptographic primitive satisfies all eight perfectly. The library
ships an `IdentityAdapter` protocol with multiple implementations, each
strong on different axes; `primary-idea.md` Table 8.2 documents the trade-offs.

For the long-form argument — fly-by-wire envelope protection as the analogue,
what the eight properties mean operationally, and what changes on Tuesday
afternoon when the envelope shows up — read
[`docs/blog/identity-is-the-moment-of-action.md`](docs/blog/identity-is-the-moment-of-action.md).

---

## Two stages: identity first, delegation second

Identity for a single AI system is one problem. Multi-agent delegation
across trust domains is a different problem, harder, that builds on the
first. The library separates them on purpose. Wire identity first.
Add delegation only when you have a real second agent to delegate to.

* **Stage 1 — Identity for any AI framework.** Drop-in recipes for
  CrewAI, AutoGen, Pydantic AI, LangChain, Letta, HTTP services, and
  plain Python. Single agent, single envelope, signed audit row per
  material action. Read
  [`docs/IDENTITY_INTEGRATION.md`](docs/IDENTITY_INTEGRATION.md).
  For the **config-driven path** (operator-owned `agent.yaml` plus
  CI-generated `provenance.json`, application code declares only
  function names), read
  [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).
* **Stage 2 — Multi-agent delegation and federation.** Parent→child
  envelope handoff with monotone-decreasing scope, plus
  cross-trust-domain federation for SPIFFE. Stage 2 builds on Stage 1
  primitives. The LangGraph and A2A demos exercise this path; see
  [`DEMO.md`](DEMO.md).

---

## What's in the library

### Core

The portable identity types and validation logic, framework-free.

- `IdentityEnvelope` — dataclass carrying system identifier, runtime instance,
  owner binding, attestation chain, provenance reference, lifecycle state,
  delegations, and signature chain. This is the object that travels with
  every material action.
- `IdentityValidator` — executable checks for the eight properties with
  STRICT and DEVELOPMENT modes; the STRICT mode is what you run in
  production. Optional scope-namespace enforcement via
  `enforce_scope_convention=True`.
- `effective_scopes_for_actor` — monotone-decreasing scope calculation used
  on every delegation. The child receives at most what the parent had.
- `Ed25519Signer` — local signing and verification, PEM round-trip,
  detached signature support.

### Identity adapters

`primary-idea.md` enumerates nine candidate constructions
(Merkle chain, Merkle DAG, Verifiable Credentials + DIDs, SPIFFE/SPIRE
SVIDs, Macaroons/Biscuits, nested JWS/COSE_Sign, in-toto/SLSA, hardware-rooted
attestation, threshold/BLS). v0.1 ships two:

- **`merkle_chain`** — append-only Merkle chain of signed identity nodes.
  Tamper-evident across the issuance + delegation + action history. Strong
  on persistence, addressability, owner binding, instance specificity,
  provenance, and audit. Weak on topology — it forces graph-shaped agent
  flows into a single-parent sequence.

- **`spiffe`** — JWT-SVID-shaped envelopes whose `system_identifier` is a
  SPIFFE ID (`spiffe://<trust_domain>/<path>`). Each envelope carries a
  compact JWS signed by the local Ed25519 signer plus a JWKS in metadata so
  verifiers can validate the SVID without the signer. Cross-trust-domain
  delegation is rejected by default and requires the explicit
  `spiffe.allow_cross_trust_domain` caveat — SPIFFE federation must be
  intentional. The audit row records `federation: true` and both trust
  domains so cross-org flows are operationally visible.

  The metadata key `spiffe.workload_api_socket` is reserved for the future
  `spire` adapter (Workload API client). Envelopes minted by this adapter
  carry forward unrecognized SPIFFE fields so a later SPIRE-backed verifier
  can pick them up without rewriting flows.

Roadmap: DAG adapter for multi-parent action attestation, DID + Verifiable
Credentials for cross-organization composition, SPIRE Workload API client,
in-toto/SLSA provenance binding, hardware attestation, threshold signatures.

### Storage backends

`LifecycleStore` + `AuditStore` protocols with four implementations:

- `file` (default) — append-only JSONL audit log and a JSON lifecycle file
  under `data_dir`. Suitable for single-process flows and demos.
- `sqlite` — same shape, single-file database.
- `postgres` — for multi-process / multi-host deployments where revocation
  must be visible to every actor at action time. Requires
  `pip install autonomous-identity[postgres]`.
- `memory` — tests only.

### Framework integrations

- **Framework-agnostic `IdentityRuntime`** — single object that bundles
  envelope + facade; wraps any callable (sync or async) without mutating
  it, and is a drop-in context manager. The base layer every framework
  recipe in [`docs/IDENTITY_INTEGRATION.md`](docs/IDENTITY_INTEGRATION.md)
  builds on. Works on CrewAI, AutoGen, Pydantic AI, Letta, HTTP services,
  and plain Python with three lines of glue per framework.
- **LangChain** — `identity_protected_tool` wrapper enforces
  `required_scope` at every tool invocation via `run_material_action`.
- **LangGraph** — `wrap_langgraph_node(identity, envelope, fn)` runs each
  node under its envelope without boilerplate; `issue_and_delegate_tree`
  builds a multi-agent delegation tree at invoke time from a JSON spec
  (planner output, request payload, database row).
- **A2A (Agent2Agent)** — sample server + executor that read the envelope
  off `metadata['autonomous_identity.envelope_json']` on each
  `SendMessageRequest`. Single-trust-domain version in
  `examples/a2a_identity_agent/`; cross-trust-domain federation with
  trust-bundle verification in `examples/a2a_spiffe_federation/`.

### Observability

The audit log is the system of record for what actually happened. Tracing
adds the *observability* layer — a real-time view of every identity hop as
the flow runs. Available adapters:

- **`ConsoleTracer`** — zero-dependency, color-coded console output.
- **`LangfuseTracer`** — Langfuse SDK v2 / v3 / v4 supported, auto-detects
  the right code path. Spans for issue / delegate / exercise /
  material_action / verify / revoke land in the Langfuse UI as nested
  trace trees. The federation caveat is visible inline on every cross-TD
  delegate span.

`TracedIdentity` wraps `AutonomousIdentity` and emits spans on every
observable hop. **Zero changes to the core facade** — your existing tests
keep passing. Telemetry hygiene is built in: spans carry metadata only
(SPIFFE ID, trust domain, scopes, audit_ref, hashes) by default. Raw I/O,
SVID JWS, and signatures never leave the process unless you opt in with
`capture_io=True`.

### Tests

`pytest tests/` — 65 tests, 1 expected skip (LangGraph integration test
requires the langgraph extra in the test env).

---

## Quick start

```bash
pip install -e .
```

```python
from pathlib import Path
from autonomous_identity import AutonomousIdentity, ValidatorStrictness

identity = AutonomousIdentity.local(
    Path(".asid"),
    adapter_name="spiffe",                       # or "merkle_chain"
    strictness=ValidatorStrictness.STRICT,
)

# Issue a root envelope with the scopes the root may delegate.
root = identity.issue_envelope({
    "system_identifier": "spiffe://example.org/agents/platform",
    "instance_id": "i-1",
    "deployment_id": "d-1",
    "owner_id": "team:platform",
    "provenance": {"code_hash": "sha256:abc", "policy_bundle_hash": "sha256:def"},
    "attestation_chain": ["local:bootstrap"],
    "issuer_scopes": ["orchestrate", "web.read", "doc.write"],
})

# Hand off a narrower scope set to a child agent.
researcher = identity.delegate(
    root,
    "spiffe://example.org/agents/research",
    ["web.read"],
)

# Decorate a function as a material action that requires a specific scope.
@identity.material_action(action_type="web.fetch", required_scope="web.read")
def fetch(url: str) -> str:
    ...

# Exercise the researcher envelope. The decorator re-verifies the envelope
# AT THE MOMENT OF THIS CALL — lifecycle state, scope grants, signature,
# delegation expiry — and records an audit row only if everything passes.
with identity.exercise(researcher):
    fetch("https://example.com")
```

Every call inside `identity.exercise(...)` writes an entry to the
append-only audit log at `.asid/audit.jsonl`. Each entry binds the action
to the envelope's commitment hash so tampering with either breaks the
verification.

---

## Multi-agent delegation

Build the delegation tree at invoke time from a plain JSON spec rather than
hard-coding it into the graph:

```python
from autonomous_identity.application.delegation_chain import issue_and_delegate_tree

envs = issue_and_delegate_tree(
    identity,
    issue_context={
        "system_identifier": "spiffe://corp.example/platform",
        "instance_id": "i-1", "deployment_id": "d-1",
        "owner_id": "team:platform",
        "provenance": {"code_hash": "sha256:plat"},
        "attestation_chain": ["local:bootstrap"],
        "issuer_scopes": ["orchestrate", "web.read", "doc.write"],
    },
    edges=[
        {
            "role": "orchestrator", "parent_role": "platform",
            "child_subject": "spiffe://corp.example/orchestrator",
            "allowed_scopes": ["orchestrate", "web.read", "doc.write"],
            "expires_in_hours": 24,
        },
        {
            "role": "research", "parent_role": "orchestrator",
            "child_subject": "spiffe://corp.example/agents/research",
            "allowed_scopes": ["web.read"],
            "expires_in_hours": 24,
        },
        {
            "role": "writer", "parent_role": "orchestrator",
            "child_subject": "spiffe://corp.example/agents/writer",
            "allowed_scopes": ["doc.write"],
            "expires_in_hours": 24,
        },
    ],
    root_role="platform",
)
# envs["research"], envs["writer"] etc. are IdentityEnvelope instances.
```

Bind them to LangGraph nodes:

```python
from autonomous_identity.integrations.langgraph import wrap_langgraph_node

graph.add_node(
    "research",
    wrap_langgraph_node(identity, lambda s: s["envelopes"]["research"], do_research),
)
```

Full runnable example:
[`examples/langgraph_spiffe_multi_agent.py`](examples/langgraph_spiffe_multi_agent.py).

---

## Cross-trust-domain federation (SPIFFE)

Federation is the case the design notes call out as architecturally hardest:
an agent in tenant A handing work to an agent in tenant B. The library handles it
through an explicit caveat on the delegation, a JWKS that travels with the
envelope, and a receiver-side trust bundle that decides which peer trust
domains are recognized.

```python
# Tenant A: mint the federated envelope.
initiator = identity_a.delegate(parent_in_a, "spiffe://tenant-a.example/agents/initiator",
                                ["a2a.send", "work.request"])
federated = identity_a.delegate(
    initiator,
    "spiffe://tenant-b.example/agents/processor",
    ["work.request"],                                   # narrower than initiator's
    {"spiffe.allow_cross_trust_domain": True},          # required for cross-TD
)
```

```python
# Tenant B: verify against the trust bundle BEFORE running any work.
from examples.a2a_spiffe_federation.trust_bundle import (
    TrustBundle, verify_federated_envelope,
)
bundle = TrustBundle(name="tenant-b.example")
bundle.add_peer("tenant-a.example", tenant_a_jwks_received_out_of_band)

verify_federated_envelope(
    federated,
    expected_trust_domain="tenant-b.example",
    trust_bundle=bundle,
)
```

`verify_federated_envelope` checks four things before the receiver does any
work: (1) the SPIFFE ID is in this receiver's trust domain, (2) a
delegation edge with the federation caveat crosses into this trust domain,
(3) the JWKS in the envelope matches what the receiver already trusts for
the parent trust domain (preventing a malicious sender from embedding its
own JWKS), (4) the SVID signature verifies against that trusted JWKS.

Full runnable example:
[`examples/a2a_spiffe_federation/`](examples/a2a_spiffe_federation/).

---

## Tracing

Same API as `AutonomousIdentity`, plus a tracer:

```python
from autonomous_identity.tracing import TracedIdentity, ConsoleTracer

identity = TracedIdentity.local(
    Path(".asid"),
    adapter_name="spiffe",
    tracer=ConsoleTracer(),
)
```

To ship to Langfuse instead, install the extra and set credentials:

```bash
pip install -e ".[tracing-langfuse]"
```

Put credentials in a `.env` file at the repo root (or any parent directory
of where you run the demos). The library walks up from cwd looking for it:

```
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_BASE_URL=https://us.cloud.langfuse.com
```

Every observable hop becomes a span in the Langfuse UI. Span metadata
shows SPIFFE ID, trust domain, scope list, audit_ref, federation flag,
OTel trace/span IDs, and lifecycle state. Errors land as red ERROR spans
with the exact verification message — the negative cases in the federation
demo (scope escalation, SVID tampering, missing trust bundle) all show up
visually as rejected hops.

A worked screenshot annotation of a cross-TD delegate span lives in
[`DEMO.md → What to show in the Langfuse UI`](DEMO.md#what-to-show-in-the-langfuse-ui).

---

## CLI

```bash
pip install -e ".[dev]"

asid --store file --data-dir .asid issue \
  --system-id spiffe://example.org/agent/x \
  --instance-id i-1 --deployment-id d-1 \
  --owner team:demo \
  --code-hash sha256:abc --policy-hash sha256:def

asid --store file --data-dir .asid verify  --audit-ref 'audit://file/...'
asid --store file --data-dir .asid revoke  --system-id spiffe://example.org/agent/x --reason rotated
asid --store file --data-dir .asid inspect --audit-ref 'audit://file/...'
```

Delegation from the CLI requires exporting the parent envelope to JSON first
(see `examples/delegate_handoff.py` for the round-trip), then:

```bash
asid delegate --store file --data-dir .asid --parent-json parent-envelope.json \
  --child-system-id spiffe://example.org/agent/child --scopes orders.read
```

---

## Demos

[`DEMO.md`](DEMO.md) walks through three demo paths, ordered by setup cost:

| Demo | Setup | Audience |
|---|---|---|
| Terminal walkthrough — A2A federation + LangGraph multi-agent | 5 min | technical screen-share |
| Langfuse UI — same scripts, visual trace tree | 15 min | CISO / non-engineer audience |
| Langflow visual flow — IdentityAgent component, 5-agent chain | 30 min | "make it real" audience |

---

## Configuration

YAML config in lieu of code:

```yaml
identity:
  adapter: spiffe        # or "merkle_chain"
storage:
  backend: file          # file | sqlite | postgres | memory
  data_dir: .asid
crypto:
  private_key_pem: .asid/signing_key.pem   # optional; generated on first use
```

```python
identity = AutonomousIdentity.from_config("identity.yaml")
```

See [`examples/identity_adapter_config.yaml`](examples/identity_adapter_config.yaml).

---

## Optional extras

- `pip install autonomous-identity[langchain]` — LangChain tool wrapper.
- `pip install autonomous-identity[langgraph]` — LangGraph multi-agent
  demo and MCP-backed research example.
- `pip install autonomous-identity[postgres]` — Postgres lifecycle + audit stores.
- `pip install autonomous-identity[a2a]` — A2A sample server and executor.
- `pip install autonomous-identity[tracing-langfuse]` — Langfuse tracer.
- `pip install autonomous-identity[tracing-otel]` — OpenTelemetry tracer (reserved).

---

## Architecture

```
core/             envelope types, validators, hashing, delegation helpers (no I/O frameworks)
application/      AutonomousIdentity facade; issue_and_delegate_tree helper
adapters/         IdentityAdapter implementations + registry
storage/          LifecycleStore / AuditStore protocols + file/sqlite/postgres/memory
integrations/     LangChain, LangGraph, Langflow helpers
tracing/          Tracer protocol, ConsoleTracer, LangfuseTracer, TracedIdentity wrapper
crypto/           Ed25519 signer
cli/              `asid` command
```

The boundary that matters: `core/` has no framework imports.
Everything else builds on it.

---

## Roadmap

Status, in rough priority order. PRs welcome on any of these.

- **Written threat model** — what is in scope (stolen signing key,
  compromised lifecycle store, injected delegation edge, audit-log
  tampering by operators) and what is not.
- **SPIRE Workload API adapter** (`spire`) — talks to a SPIRE Agent socket
  for real X.509-SVID / JWT-SVID material and federation trust bundles.
  Slot is reserved in the SPIFFE adapter's metadata.
- **DID + Verifiable Credentials adapter** — cross-organization composition
  where multiple authorities issue claims about a stable DID subject.
- **DAG adapter** — multi-parent action attestation for graph-shaped agent
  flows (action co-asserted by orchestrator + policy + retrieval).
- **Automatic provenance binding from CI/CD** — the envelope has the
  `code_hash` / `model_hash` / `policy_bundle_hash` fields; nothing fills
  them today. A CI hook signing the commit hash into the issue context at
  build time turns provenance from ceremony into evidence.
- **`wrap_tools_for_identity` rewrite** — current implementation mutates
  `BaseTool.invoke`, which pydantic v2 rejects. Should return a wrapped
  tool instance instead.
- **Scope-namespace convention RFC** — scopes are free-form strings today.
  At scale across organizations they will collide. Document an IAM-style
  namespace before the collision happens.
- **Hardware attestation** — bind envelopes to a measured execution
  environment so host compromise is in scope.
- **Threshold / BLS signatures** — multi-party action authorization where
  no single principal can act alone.

---

## License

Apache-2.0
