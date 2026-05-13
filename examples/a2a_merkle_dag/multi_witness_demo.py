"""A2A multi-party co-assertion demo using the Merkle DAG adapter.

Three principals collaborate on a privileged action — approving a customer
refund — and the audit row records that the action was **co-asserted** by
all three. The chain adapter would have to flatten this into a sequence
(``actor → policy → evidence → action``) and lose the fact that policy
and evidence are siblings, not ancestors. The DAG adapter preserves the
real dependency graph.

Topology
========

::

    refund-bot                       (actor, proposes the refund)
        │
        ├── A2A: policy.check ────► refund-rules service
        │                              ◄── returns envelope JSON in metadata
        │
        ├── A2A: evidence.fetch ──► customer-history service
        │                              ◄── returns envelope JSON in metadata
        │
        └── refund.approve ────► audit row with previous_hashes = [
                                     refund-bot-tip,
                                     refund-rules-tip,
                                     customer-history-tip
                                 ]

A2A metadata channel
====================

Each "service" responds with its envelope serialized via
``envelope_to_serializable`` under the metadata key
``autonomous_identity.envelope_json`` — the same key the single-trust-domain
A2A executor in ``examples/a2a_identity_agent/`` already uses. The actor
collects those metadata blobs, deserializes them, and hands the resulting
envelopes to ``adapter.audit(..., witnesses=[...])``.

Run
===

::

    pip install -e .
    python examples/a2a_merkle_dag/multi_witness_demo.py

What this proves
================

* The audit row for ``refund.approve`` commits to **three parent hashes**,
  not one.
* Verifying the approval row passes against the un-tampered chain.
* Tampering with the policy service's audit row breaks
  ``verify_chain_event`` on that row.
* Witnesses that weren't issued by this DAG adapter are rejected at the
  ``audit()`` call, before any row is written.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.core.envelope import (
    IdentityEnvelope,
    OwnerBinding,
    ProvenanceReference,
    RuntimeInstance,
)
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.core.serialize import (
    envelope_from_serializable,
    envelope_to_serializable,
)
from datetime import datetime, timezone

# Same A2A metadata key the single-TD executor uses. This demo transplants
# directly onto a real A2A server pair without rewiring.
METADATA_ENVELOPE_JSON = "autonomous_identity.envelope_json"


# ----- envelope issuance for each principal ---------------------------------


def _issue_for(
    identity: AutonomousIdentity, sid: str, scopes: list[str]
) -> IdentityEnvelope:
    return identity.issue_envelope(
        {
            "system_identifier": sid,
            "instance_id": sid.rsplit("/", 1)[-1],
            "deployment_id": "demo-1",
            "owner_id": "team:" + sid.split("/")[-2],
            "provenance": {
                "code_hash": "sha256:" + sid.rsplit("/", 1)[-1],
                "policy_bundle_hash": "sha256:policy-v1",
            },
            "attestation_chain": ["local:bootstrap"],
            "issuer_scopes": scopes,
        }
    )


# ----- "A2A service" responses (in-process; real version is HTTP) -----------


def policy_service_response(
    identity: AutonomousIdentity,
    policy_env: IdentityEnvelope,
    *,
    claim_id: str,
    amount: int,
) -> dict[str, Any]:
    proof = identity.run_material_action(
        policy_env,
        action_type="policy.refund_check",
        required_scope="policy.evaluate",
        fn=lambda: {"claim_id": claim_id, "amount": amount, "verdict": "approved"},
        args=(),
        kwargs={},
    )
    return {
        "result": proof["result"],
        "audit_ref": proof["audit_ref"],
        "metadata": {METADATA_ENVELOPE_JSON: envelope_to_serializable(policy_env)},
    }


def evidence_service_response(
    identity: AutonomousIdentity,
    evidence_env: IdentityEnvelope,
    *,
    customer_id: str,
) -> dict[str, Any]:
    proof = identity.run_material_action(
        evidence_env,
        action_type="evidence.fetch",
        required_scope="evidence.read",
        fn=lambda: {
            "customer_id": customer_id,
            "lifetime_value": 4200,
            "prior_refunds_30d": 0,
        },
        args=(),
        kwargs={},
    )
    return {
        "result": proof["result"],
        "audit_ref": proof["audit_ref"],
        "metadata": {METADATA_ENVELOPE_JSON: envelope_to_serializable(evidence_env)},
    }


# ----- the actor: refund-bot, collecting witnesses --------------------------


def refund_bot_approve(
    identity: AutonomousIdentity,
    actor_env: IdentityEnvelope,
    *,
    claim_id: str,
    amount: int,
    customer_id: str,
    policy_response: dict[str, Any],
    evidence_response: dict[str, Any],
) -> dict[str, Any]:
    """Refund-bot performs the approval, witnessed by the two peer envelopes."""
    policy_env = envelope_from_serializable(
        policy_response["metadata"][METADATA_ENVELOPE_JSON]
    )
    evidence_env = envelope_from_serializable(
        evidence_response["metadata"][METADATA_ENVELOPE_JSON]
    )

    # Direct adapter call so we can pass witnesses (DAG-specific concept).
    adapter = identity._adapter  # noqa: SLF001
    ref = adapter.audit(
        actor_env,
        {
            "action_type": "refund.approve",
            "required_scope": "refund.approve",
            "input_hash": f"claim:{claim_id}:amount:{amount}:customer:{customer_id}",
            "output_hash": "refund_approved",
            "claim_id": claim_id,
            "amount": amount,
        },
        witnesses=[policy_env, evidence_env],
    )
    return {
        "audit_ref": ref,
        "witnesses": [policy_env.system_identifier, evidence_env.system_identifier],
    }


# ----- demo orchestration ----------------------------------------------------


def _print_separator(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> int:
    # Use a fresh temp dir so reruns always start clean.
    data_dir = Path(
        os.environ.get("ASID_DAG_DATA_DIR")
        or tempfile.mkdtemp(prefix="asid-dag-a2a-")
    )
    if data_dir.exists() and "asid-dag-a2a-" in data_dir.name:
        shutil.rmtree(data_dir, ignore_errors=True)
        data_dir.mkdir(parents=True, exist_ok=True)

    identity = AutonomousIdentity.local(
        data_dir,
        adapter_name="merkle_dag",
        strictness=ValidatorStrictness.STRICT,
    )

    _print_separator("Three principals issued")
    refund_bot = _issue_for(
        identity, "agent://corp/agents/refund-bot", ["refund.approve"]
    )
    refund_policy = _issue_for(
        identity, "agent://corp/policies/refund-rules", ["policy.evaluate"]
    )
    customer_evidence = _issue_for(
        identity, "agent://corp/evidence/customer-history", ["evidence.read"]
    )
    print(f"  actor:    {refund_bot.system_identifier}")
    print(f"  policy:   {refund_policy.system_identifier}")
    print(f"  evidence: {customer_evidence.system_identifier}")
    print(f"  audit:    {data_dir / 'audit.jsonl'}")

    _print_separator("Refund-bot fans out (simulated A2A peer calls)")
    policy_resp = policy_service_response(
        identity, refund_policy, claim_id="claim-7", amount=129
    )
    evidence_resp = evidence_service_response(
        identity, customer_evidence, customer_id="cust-42"
    )
    print(f"  policy verdict:  {policy_resp['result']}")
    print(f"  policy audit:    {policy_resp['audit_ref']}")
    print(f"  evidence:        {evidence_resp['result']}")
    print(f"  evidence audit:  {evidence_resp['audit_ref']}")
    print(f"  each envelope arrived under metadata[{METADATA_ENVELOPE_JSON!r}]")

    _print_separator("Refund-bot performs refund.approve with both as witnesses")
    outcome = refund_bot_approve(
        identity,
        refund_bot,
        claim_id="claim-7",
        amount=129,
        customer_id="cust-42",
        policy_response=policy_resp,
        evidence_response=evidence_resp,
    )
    print(f"  audit_ref:    {outcome['audit_ref']}")
    print(f"  witnesses:    {outcome['witnesses']}")

    _print_separator("Audit-row inspection for the approval")
    approve_row = identity._adapter._audit_store.get(  # noqa: SLF001
        outcome["audit_ref"]
    )
    parents = approve_row["node"]["previous_hashes"]
    print(f"  kind:             {approve_row['kind']}")
    print(f"  subject:          {approve_row['system_identifier']}")
    print(f"  previous_hashes:  {len(parents)} parents")
    for h in parents:
        print(f"     - {h[:48]}…")
    print(f"  witness subjects: {approve_row['witness_subjects']}")

    _print_separator("Independent verification of the approval row")
    identity._adapter.verify_chain_event(outcome["audit_ref"])  # noqa: SLF001
    print("  verify_chain_event(refund.approve): OK")

    _print_separator(
        "Negative case 1: tamper with the policy service's audit row"
    )
    # Mutate the policy row's signature on disk; re-verifying it must fail.
    audit_path = data_dir / "audit.jsonl"
    rows = [json.loads(line) for line in audit_path.read_text().splitlines()]
    policy_idx = next(
        i for i, r in enumerate(rows)
        if (r.get("action") or {}).get("action_type") == "policy.refund_check"
    )
    rows[policy_idx]["node"]["signature"] = "AAAA"
    audit_path.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n",
        encoding="utf-8",
    )
    rejected = False
    try:
        identity._adapter.verify_chain_event(  # noqa: SLF001
            policy_resp["audit_ref"]
        )
    except VerificationError as exc:
        print(f"  verify_chain_event(policy.refund_check): rejected — {exc}")
        rejected = True
    if not rejected:
        print("  UNEXPECTED: tampered policy row verified")
        return 2

    _print_separator(
        "Negative case 2: witness from outside this adapter is refused"
    )
    bogus_env = IdentityEnvelope(
        system_identifier="agent://stranger/peer",
        runtime_instance=RuntimeInstance(
            instance_id="x", deployment_id="x", environment="dev", region="local"
        ),
        owner_binding=OwnerBinding(
            owner_id="stranger", owner_type="team", responsibility_scope="x"
        ),
        attestation_chain=["foreign:bootstrap"],
        provenance=ProvenanceReference(code_hash="sha256:foreign"),
        lifecycle_state="active",
        issued_at=datetime.now(timezone.utc),
        verified_at=None,
        audit_ref=None,
        signature_chain=[],
    )
    rejected = False
    try:
        identity._adapter.audit(  # noqa: SLF001
            refund_bot, {"action_type": "should.not.run"}, witnesses=[bogus_env]
        )
    except VerificationError as exc:
        print(f"  audit(...witnesses=[foreign env]): rejected — {exc}")
        rejected = True
    if not rejected:
        print("  UNEXPECTED: foreign witness accepted")
        return 2

    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
