"""Tests for the composite SPIFFE + Merkle DAG identity adapter."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from autonomous_identity.adapters.composite import CompositeIdentityAdapter
from autonomous_identity.adapters.registry import get_adapter, list_adapters
from autonomous_identity.core.delegation_util import effective_scopes_for_actor
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.crypto.ed25519 import Ed25519Signer
from autonomous_identity.storage.memory import MemoryAuditStore


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _new_adapter(svid_ttl_hours: float = 1.0) -> tuple[
    CompositeIdentityAdapter, MemoryAuditStore
]:
    audit = MemoryAuditStore()
    adapter = CompositeIdentityAdapter(
        Ed25519Signer.generate(),
        audit_store=audit,
        svid_ttl=timedelta(hours=svid_ttl_hours),
    )
    return adapter, audit


def _root_ctx(
    sid: str = "spiffe://example.org/agents/root",
    scopes: list[str] | None = None,
) -> dict:
    return {
        "system_identifier": sid,
        "instance_id": "i-1",
        "deployment_id": "d-1",
        "owner_id": "team:demo",
        "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
        "attestation_chain": ["local:bootstrap"],
        "issuer_scopes": scopes or ["tool.invoke", "doc.write", "web.read"],
    }


# ---------- both artifacts present + verifiable -----------------------------


class TestBothArtifacts:
    def test_envelope_carries_dag_node_and_svid_jws(self) -> None:
        adapter, _ = _new_adapter()
        env = adapter.issue(_root_ctx())
        # DAG side
        assert env.metadata["dag_tip_hash"]
        assert env.metadata["dag_public_key"]
        # SPIFFE side
        assert env.metadata["spiffe.svid_jws"].count(".") == 2
        assert env.metadata["spiffe.kid"]
        assert env.metadata["spiffe.jwks"]
        assert env.metadata["spiffe.trust_domain"] == "example.org"
        # signature_chain has BOTH the DAG node signature and the SVID JWS
        assert len(env.signature_chain) == 2

    def test_verify_passes_both_paths(self) -> None:
        adapter, _ = _new_adapter()
        env = adapter.issue(_root_ctx())
        assert adapter.verify(env) is True

    def test_svid_payload_binds_to_spiffe_strict_commitment(self) -> None:
        adapter, _ = _new_adapter()
        env = adapter.issue(_root_ctx())
        # Decode the SVID payload manually.
        _, payload_b64, _ = env.metadata["spiffe.svid_jws"].split(".")
        payload = json.loads(_b64url_decode(payload_b64))
        assert payload["sub"] == env.system_identifier
        assert payload["commitment_hash"]


# ---------- SPIFFE addressing enforced --------------------------------------


class TestSpiffeAddressing:
    def test_non_spiffe_id_rejected(self) -> None:
        adapter, _ = _new_adapter()
        with pytest.raises(VerificationError, match="Not a SPIFFE ID"):
            adapter.issue(
                {
                    **_root_ctx(),
                    "system_identifier": "agent://example.org/x",
                }
            )

    def test_id_can_be_built_from_trust_domain_path(self) -> None:
        adapter, _ = _new_adapter()
        env = adapter.issue(
            {
                "spiffe_trust_domain": "example.org",
                "spiffe_path": "/agents/builder",
                "instance_id": "i",
                "deployment_id": "d",
                "owner_id": "team:x",
                "provenance": {"code_hash": "sha256:a"},
                "attestation_chain": ["local:x"],
                "issuer_scopes": ["tool.invoke"],
            }
        )
        assert env.system_identifier == "spiffe://example.org/agents/builder"
        assert adapter.verify(env)


# ---------- delegation ------------------------------------------------------


class TestDelegate:
    def test_same_trust_domain_delegation_succeeds(self) -> None:
        adapter, _ = _new_adapter()
        parent = adapter.issue(_root_ctx())
        child = adapter.delegate(
            parent,
            "spiffe://example.org/agents/child",
            ["tool.invoke"],
            {},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert adapter.verify(child)
        # Child has its own SVID, and the SVID's subject is the child ID.
        _, payload_b64, _ = child.metadata["spiffe.svid_jws"].split(".")
        payload = json.loads(_b64url_decode(payload_b64))
        assert payload["sub"] == "spiffe://example.org/agents/child"

    def test_scope_narrowing_enforced(self) -> None:
        adapter, _ = _new_adapter()
        parent = adapter.issue(_root_ctx(scopes=["tool.invoke"]))
        with pytest.raises(VerificationError, match="not allowed"):
            adapter.delegate(
                parent,
                "spiffe://example.org/agents/child",
                ["doc.write"],
                {},
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )

    def test_cross_trust_domain_rejected_without_caveat(self) -> None:
        adapter, _ = _new_adapter()
        parent = adapter.issue(_root_ctx())
        with pytest.raises(VerificationError, match="Cross-trust-domain"):
            adapter.delegate(
                parent,
                "spiffe://other.example/agents/peer",
                ["tool.invoke"],
                {},
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )

    def test_cross_trust_domain_succeeds_with_caveat(self) -> None:
        adapter, audit = _new_adapter()
        parent = adapter.issue(_root_ctx())
        child = adapter.delegate(
            parent,
            "spiffe://other.example/agents/peer",
            ["tool.invoke"],
            {"spiffe.allow_cross_trust_domain": True},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert adapter.verify(child)
        # Federation marker lands on the delegation row's caveats.
        federation_delegation = child.delegations[-1]
        assert federation_delegation.caveats["spiffe.federation"] is True


# ---------- multi-parent action attestation (DAG layer) ---------------------


class TestWitnessedActions:
    def test_action_with_witnesses_records_multiple_parents(self) -> None:
        adapter, audit = _new_adapter()
        actor = adapter.issue(_root_ctx("spiffe://example.org/agents/actor"))
        policy = adapter.issue(_root_ctx("spiffe://example.org/agents/policy"))
        retrieval = adapter.issue(
            _root_ctx("spiffe://example.org/agents/retrieval")
        )

        ref = adapter.audit(
            actor,
            {"action_type": "doc.compose"},
            witnesses=[policy, retrieval],
        )
        row = audit.get(ref)
        assert len(row["node"]["previous_hashes"]) == 3
        assert sorted(row["witness_subjects"]) == sorted(
            [
                "spiffe://example.org/agents/policy",
                "spiffe://example.org/agents/retrieval",
            ]
        )


# ---------- SVID expiry -----------------------------------------------------


class TestRepeatedActionsKeepEnvelopeValid:
    """Regression: the DAG-tip pointer mutates after every material action.

    The SVID claim binds to a commitment hash computed from envelope content
    excluding both SVID metadata AND the DAG-tip metadata, so the same
    envelope can be exercised many times without the SVID being invalidated.
    """

    def test_envelope_verifies_after_multiple_audit_rounds(self) -> None:
        adapter, _ = _new_adapter()
        env = adapter.issue(_root_ctx())
        # The first verify passes — that part was always true.
        assert adapter.verify(env)
        # The interesting case: audit a few times and re-verify between each.
        for i in range(5):
            adapter.audit(env, {"action_type": f"bench.op.{i}"})
            assert adapter.verify(env), f"envelope failed verify after action {i}"


class TestSvidExpiry:
    def test_expired_svid_fails_verify(self) -> None:
        audit = MemoryAuditStore()
        adapter = CompositeIdentityAdapter(
            Ed25519Signer.generate(),
            audit_store=audit,
            svid_ttl=timedelta(seconds=0),  # exp == iat
        )
        env = adapter.issue(_root_ctx())
        # DAG node is fine, SVID is expired ⇒ composite verify fails.
        assert adapter.verify(env) is False


# ---------- tamper detection ------------------------------------------------


class TestTamper:
    def test_tampered_svid_payload_breaks_verify(self) -> None:
        adapter, _ = _new_adapter()
        env = adapter.issue(_root_ctx())
        h, _p, s = env.metadata["spiffe.svid_jws"].split(".")
        forged = json.dumps({"sub": "spoofed"}, separators=(",", ":")).encode()
        env.metadata["spiffe.svid_jws"] = (
            f"{h}.{base64.urlsafe_b64encode(forged).rstrip(b'=').decode('ascii')}.{s}"
        )
        assert adapter.verify(env) is False


# ---------- registry --------------------------------------------------------


class TestRegistry:
    def test_composite_is_discoverable(self) -> None:
        assert "composite" in list_adapters()

    def test_factory_returns_composite_instance(self) -> None:
        deps = {
            "signer": Ed25519Signer.generate(),
            "audit_store": MemoryAuditStore(),
        }
        adapter = get_adapter("composite", deps)
        assert adapter.name == "composite"
        env = adapter.issue(_root_ctx())
        assert adapter.verify(env)
