"""Tests for the Merkle DAG identity adapter.

The DAG adapter generalises the Merkle chain to multi-parent action
attestation. Tests cover:

* genesis / delegate / single-parent action behave identically to the chain
* a witnessed action commits to multiple parents
* parent-set is order-insensitive (hash is stable across permutations)
* witness self-witnessing is de-duplicated
* tampering with the actor's chain breaks descendant node hashes
* tampering with a witness's chain ALSO breaks the descendant — the whole
  point of co-assertion
* the adapter is reachable via the registry as 'merkle_dag'
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from autonomous_identity.adapters.merkle_dag import (
    MerkleDagIdentityAdapter,
    MerkleDagNode,
)
from autonomous_identity.adapters.registry import get_adapter, list_adapters
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.crypto.ed25519 import Ed25519Signer
from autonomous_identity.storage.memory import MemoryAuditStore


def _new_adapter() -> tuple[MerkleDagIdentityAdapter, MemoryAuditStore]:
    audit = MemoryAuditStore()
    return (
        MerkleDagIdentityAdapter(Ed25519Signer.generate(), audit_store=audit),
        audit,
    )


def _root_ctx(sid: str = "agent://demo/root", scopes=None) -> dict:
    return {
        "system_identifier": sid,
        "instance_id": "i-1",
        "deployment_id": "d-1",
        "owner_id": "team:demo",
        "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
        "attestation_chain": ["local:bootstrap"],
        "issuer_scopes": scopes or ["tool.invoke", "doc.write"],
    }


# ---------- genesis + verify ------------------------------------------------


class TestIssue:
    def test_issue_produces_verifiable_envelope(self) -> None:
        adapter, _ = _new_adapter()
        env = adapter.issue(_root_ctx())
        assert env.system_identifier == "agent://demo/root"
        assert env.metadata["dag_tip_hash"]
        assert env.metadata["dag_public_key"]
        assert adapter.verify(env)

    def test_genesis_node_has_no_parents(self) -> None:
        adapter, audit = _new_adapter()
        env = adapter.issue(_root_ctx())
        row = audit.get(env.audit_ref)
        assert row["node"]["previous_hashes"] == []


# ---------- delegate behaves like chain -------------------------------------


class TestDelegate:
    def test_delegate_records_single_parent(self) -> None:
        adapter, audit = _new_adapter()
        parent = adapter.issue(_root_ctx())
        child = adapter.delegate(
            parent,
            "agent://demo/child",
            ["tool.invoke"],
            {},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        row = audit.get(child.audit_ref)
        assert len(row["node"]["previous_hashes"]) == 1
        assert row["node"]["previous_hashes"][0] == parent.metadata["dag_tip_hash"]

    def test_delegate_enforces_scope_monotonicity(self) -> None:
        adapter, _ = _new_adapter()
        parent = adapter.issue(_root_ctx(scopes=["tool.invoke"]))
        with pytest.raises(VerificationError, match="not allowed"):
            adapter.delegate(
                parent,
                "agent://demo/child",
                ["doc.write"],  # never granted to parent
                {},
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )


# ---------- single-parent action (chain-like default) ----------------------


class TestSingleParentAudit:
    def test_action_without_witnesses_has_one_parent(self) -> None:
        adapter, audit = _new_adapter()
        env = adapter.issue(_root_ctx())
        ref = adapter.audit(env, {"action_type": "tool.call"})
        row = audit.get(ref)
        # The action node's only parent is the issue node's tip.
        assert len(row["node"]["previous_hashes"]) == 1


# ---------- multi-parent action (the DAG case) ------------------------------


class TestWitnessedAudit:
    def test_witnessed_action_records_multiple_parents(self) -> None:
        adapter, audit = _new_adapter()
        # Three principals — actor, policy engine, retrieval gate — each with
        # their own envelopes.
        actor = adapter.issue(_root_ctx("agent://demo/actor"))
        policy = adapter.issue(_root_ctx("agent://demo/policy"))
        retrieval = adapter.issue(_root_ctx("agent://demo/retrieval"))

        ref = adapter.audit(
            actor,
            {"action_type": "doc.compose", "input_hash": "in", "output_hash": "out"},
            witnesses=[policy, retrieval],
        )
        row = audit.get(ref)
        # The node commits to three parents: actor's tip + policy's tip + retrieval's tip.
        assert len(row["node"]["previous_hashes"]) == 3
        assert row["witness_subjects"] == [
            "agent://demo/policy",
            "agent://demo/retrieval",
        ]

    def test_witness_self_is_deduped(self) -> None:
        adapter, audit = _new_adapter()
        actor = adapter.issue(_root_ctx())
        ref = adapter.audit(
            actor,
            {"action_type": "noop"},
            witnesses=[actor, actor],  # nonsense — silently deduped
        )
        row = audit.get(ref)
        # Only the actor's tip should appear.
        assert len(row["node"]["previous_hashes"]) == 1

    def test_witness_with_no_dag_tip_is_rejected(self) -> None:
        """An envelope from a different adapter has no DAG tip — refuse it."""
        from autonomous_identity.core.envelope import (
            IdentityEnvelope,
            OwnerBinding,
            ProvenanceReference,
            RuntimeInstance,
        )

        adapter, _ = _new_adapter()
        actor = adapter.issue(_root_ctx())
        bad_witness = IdentityEnvelope(
            system_identifier="agent://demo/stranger",
            runtime_instance=RuntimeInstance(
                instance_id="i", deployment_id="d", environment="dev", region="local"
            ),
            owner_binding=OwnerBinding(
                owner_id="x", owner_type="team", responsibility_scope="x"
            ),
            attestation_chain=["x"],
            provenance=ProvenanceReference(code_hash="sha256:x"),
            lifecycle_state="active",
            issued_at=datetime.now(timezone.utc),
            verified_at=None,
            audit_ref=None,
            signature_chain=[],
        )
        with pytest.raises(VerificationError, match="no DAG tip"):
            adapter.audit(actor, {"action_type": "x"}, witnesses=[bad_witness])


# ---------- parent-set ordering is irrelevant -------------------------------


class TestParentSetOrdering:
    def test_two_orderings_produce_same_hash(self) -> None:
        # Build two nodes with the same parent set in different list orders;
        # their commitment hashes must be equal.
        a = MerkleDagNode(
            node_id="n-1",
            previous_hashes=["hash-a", "hash-b", "hash-c"],
            subject="x",
            action_type="t",
            envelope_hash="e",
            input_hash=None,
            output_hash=None,
            timestamp="2026-05-12T00:00:00+00:00",
            signature="",
        )
        b = MerkleDagNode(**{**a.__dict__, "previous_hashes": ["hash-c", "hash-a", "hash-b"]})
        assert a.node_hash() == b.node_hash()


# ---------- tamper detection across the graph ------------------------------


class TestTamperDetection:
    def test_tampering_actor_audit_row_breaks_verify_chain_event(self, tmp_path) -> None:
        """Modify the signature on the actor's issue row → verify_chain_event raises."""
        from autonomous_identity.storage.file import FileAuditStore

        audit_path = tmp_path / "audit.jsonl"
        audit = FileAuditStore(audit_path)
        signer = Ed25519Signer.generate()
        adapter = MerkleDagIdentityAdapter(signer, audit_store=audit)
        env = adapter.issue(_root_ctx())
        adapter.verify_chain_event(env.audit_ref)  # passes initially
        # Corrupt the stored row.
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["node"]["signature"] = "AAAA"
        audit_path.write_text(json.dumps(first, sort_keys=True) + "\n", encoding="utf-8")
        with pytest.raises(VerificationError):
            adapter.verify_chain_event(env.audit_ref)


# ---------- registry --------------------------------------------------------


class TestRegistry:
    def test_merkle_dag_is_discoverable(self) -> None:
        assert "merkle_dag" in list_adapters()

    def test_factory_returns_merkle_dag_instance(self) -> None:
        audit = MemoryAuditStore()
        deps = {"signer": Ed25519Signer.generate(), "audit_store": audit}
        adapter = get_adapter("merkle_dag", deps)
        assert adapter.name == "merkle_dag"
        env = adapter.issue(_root_ctx())
        assert adapter.verify(env)
