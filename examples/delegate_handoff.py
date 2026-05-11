"""Parent issue with optional root issuer_scopes; delegate narrows grants on the child edge."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.core.scope_convention import build_scope_v1
from autonomous_identity.core.serialize import envelope_to_serializable

identity = AutonomousIdentity.local(Path(".asid-delegate-demo"), strictness=ValidatorStrictness.STRICT)

_NS = "team-demo"
S_ORDERS_READ = build_scope_v1(_NS, "orders", "read")
S_ORDERS_WRITE = build_scope_v1(_NS, "orders", "write")
S_ADMIN = build_scope_v1(_NS, "admin", "full")

parent = identity.issue_envelope(
    {
        "system_identifier": "agent://demo/parent",
        "instance_id": "inst-1",
        "deployment_id": "deploy-1",
        "owner_id": "team:demo",
        "provenance": {"code_hash": "sha256:abc", "policy_bundle_hash": "sha256:def"},
        "attestation_chain": ["local:bootstrap"],
        "issuer_scopes": [S_ORDERS_READ, S_ORDERS_WRITE, S_ADMIN],
    }
)

exp = datetime.now(timezone.utc) + timedelta(hours=8)
child = identity.delegate(
    parent,
    "agent://demo/child",
    [S_ORDERS_READ],
    {"max_rows": 100},
    expires_at=exp,
)


@identity.material_action(action_type="orders.query", required_scope=S_ORDERS_READ)
def fetch_orders(limit: int) -> dict:
    return {"rows": [], "limit": limit}


with identity.exercise(child):
    out = fetch_orders(10)
    print("business:", out["result"])
    print("audit_ref:", out["audit_ref"])

# Optional: write parent envelope for `asid delegate --parent-json`
Path(".asid-delegate-demo/parent-envelope.json").write_text(
    json.dumps(envelope_to_serializable(parent), indent=2),
    encoding="utf-8",
)
