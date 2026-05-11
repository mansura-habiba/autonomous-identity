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

See `examples/` for storage swaps, LangChain, and Langflow notes.

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

## Configuration

- **Storage:** `file` (default under `data_dir`), `sqlite`, `postgres` (requires `pip install autonomous-identity[postgres]`), or `memory` (tests).
- **Identity adapter:** `identity.adapter` in YAML; v0.1 ships **`merkle_chain`** only. Unknown adapters fail at startup with a clear error.

Example: `examples/identity_adapter_config.yaml`.

## Optional extras

- `pip install autonomous-identity[langchain]` — LangChain tool wrapper (`identity_protected_tool`).
- `pip install autonomous-identity[postgres]` — PostgreSQL lifecycle + audit stores.
- Langflow: see `examples/langflow/README.md` and `wrap_tools_for_identity`.

## Architecture

- `core/` — envelope types, validation, hashing (no I/O frameworks).
- `application/` — `AutonomousIdentity` facade.
- `adapters/` — `IdentityAdapter` implementations + registry.
- `storage/` — `LifecycleStore` / `AuditStore` protocols + file/sqlite/postgres.
- `integrations/` — LangChain / Langflow helpers.

## Roadmap

Future work includes **multi-principal handoff** (user or peer system → agent) with **delegation reflected** on the envelope and in append-only audit, plus DAG-style evidence for cross-system flows. See [ROADMAP.md](ROADMAP.md).

## License

Apache-2.0
