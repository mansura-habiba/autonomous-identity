"""Tests for the SPIFFE identity adapter.

Covers:
    * SPIFFE ID parsing / validation (valid + invalid forms)
    * Issuance produces a verifiable JWT-SVID embedded in the envelope
    * Delegation narrows scope and rejects escalation
    * Delegation within one trust domain succeeds without federation caveat
    * Cross-trust-domain delegation is rejected by default and requires the
      explicit ``spiffe.allow_cross_trust_domain`` caveat
    * Tampering with the SVID payload fails ``verify()``
    * ``verify_chain_event`` validates audit-store rows and detects tampering
    * The adapter is reachable through the registry as ``"spiffe"``
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from autonomous_identity.adapters.registry import get_adapter, list_adapters
from autonomous_identity.adapters.spiffe import (
    SpiffeIdentityAdapter,
    build_spiffe_id,
    is_spiffe_id,
    parse_spiffe_id,
)
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.crypto.ed25519 import Ed25519Signer
from autonomous_identity.storage.memory import MemoryAuditStore


# ---------- helpers ----------------------------------------------------------


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _new_adapter(svid_ttl_hours: float = 1.0) -> tuple[SpiffeIdentityAdapter, MemoryAuditStore]:
    audit = MemoryAuditStore()
    adapter = SpiffeIdentityAdapter(
        Ed25519Signer.generate(),
        audit_store=audit,
        svid_ttl=timedelta(hours=svid_ttl_hours),
    )
    return adapter, audit


def _issue_root(
    adapter: SpiffeIdentityAdapter,
    *,
    spiffe_id: str = "spiffe://example.org/agent/planner",
    issuer_scopes: list[str] | None = None,
):
    return adapter.issue(
        {
            "system_identifier": spiffe_id,
            "instance_id": "i-1",
            "deployment_id": "d-1",
            "owner_id": "team:demo",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local:bootstrap"],
            "issuer_scopes": issuer_scopes or [
                "tool.invoke",
                "agent.invoke",
                "web.read",
                "doc.write",
            ],
        }
    )


# ---------- SPIFFE ID parsing -----------------------------------------------


class TestSpiffeIdParsing:
    def test_valid_ids(self) -> None:
        assert parse_spiffe_id("spiffe://example.org") == ("example.org", "")
        assert parse_spiffe_id("spiffe://example.org/x") == ("example.org", "/x")
        assert parse_spiffe_id("spiffe://a.b-c_d.e/p1/p2") == (
            "a.b-c_d.e",
            "/p1/p2",
        )

    def test_is_spiffe_id_helpers(self) -> None:
        assert is_spiffe_id("spiffe://example.org/foo")
        assert not is_spiffe_id("agent://example.org/foo")
        assert not is_spiffe_id("spiffe://EXAMPLE.org/foo")  # uppercase TD rejected

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "spiffe://",  # empty trust domain
            "spiffe://EXAMPLE.org",  # uppercase
            "spiffe://example.org?x=1",  # query
            "spiffe://example.org#frag",  # fragment
            "spiffe://example.org/has space",  # invalid segment
            "agent://example.org",
        ],
    )
    def test_invalid_ids_raise(self, bad: str) -> None:
        with pytest.raises(VerificationError):
            parse_spiffe_id(bad)

    def test_build_spiffe_id(self) -> None:
        assert build_spiffe_id("example.org") == "spiffe://example.org"
        assert build_spiffe_id("example.org", "agent/x") == "spiffe://example.org/agent/x"
        with pytest.raises(VerificationError):
            build_spiffe_id("BAD")  # uppercase trust domain


# ---------- issuance ---------------------------------------------------------


class TestIssue:
    def test_issue_produces_verifiable_svid(self) -> None:
        adapter, _ = _new_adapter()
        env = _issue_root(adapter)
        assert env.system_identifier == "spiffe://example.org/agent/planner"
        assert env.metadata["spiffe.trust_domain"] == "example.org"
        assert env.metadata["spiffe.svid_jws"].count(".") == 2
        assert adapter.verify(env) is True

    def test_svid_payload_carries_spiffe_claims(self) -> None:
        adapter, _ = _new_adapter()
        env = _issue_root(adapter)
        jws = env.metadata["spiffe.svid_jws"]
        _, payload_b64, _ = jws.split(".")
        payload = json.loads(_b64url_decode(payload_b64))
        assert payload["sub"] == env.system_identifier
        assert "iat" in payload and "exp" in payload and "jti" in payload
        assert payload["exp"] > payload["iat"]
        assert payload["commitment_hash"]  # non-empty

    def test_issue_rejects_non_spiffe_id(self) -> None:
        adapter, _ = _new_adapter()
        with pytest.raises(VerificationError):
            adapter.issue(
                {
                    "system_identifier": "agent://example.org/x",  # wrong scheme
                    "instance_id": "i",
                    "deployment_id": "d",
                    "owner_id": "o",
                    "provenance": {"code_hash": "sha256:a"},
                    "attestation_chain": ["local:x"],
                }
            )

    def test_issue_can_build_id_from_trust_domain(self) -> None:
        adapter, _ = _new_adapter()
        env = adapter.issue(
            {
                "spiffe_trust_domain": "example.org",
                "spiffe_path": "/agent/builder",
                "instance_id": "i",
                "deployment_id": "d",
                "owner_id": "team:x",
                "provenance": {"code_hash": "sha256:a"},
                "attestation_chain": ["local:x"],
                "issuer_scopes": ["tool.invoke"],
            }
        )
        assert env.system_identifier == "spiffe://example.org/agent/builder"


# ---------- delegation -------------------------------------------------------


class TestDelegate:
    def test_delegation_within_trust_domain_succeeds(self) -> None:
        adapter, _ = _new_adapter()
        parent = _issue_root(adapter)
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        child = adapter.delegate(
            parent,
            "spiffe://example.org/agent/researcher",
            ["tool.invoke", "web.read"],
            {"role": "researcher"},
            expires_at=expires,
        )
        assert child.system_identifier == "spiffe://example.org/agent/researcher"
        assert adapter.verify(child)

    def test_delegation_narrows_scope(self) -> None:
        from autonomous_identity.core.delegation_util import effective_scopes_for_actor

        adapter, _ = _new_adapter()
        parent = _issue_root(adapter)
        child = adapter.delegate(
            parent,
            "spiffe://example.org/agent/researcher",
            ["tool.invoke", "web.read"],
            {},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        child_effective = effective_scopes_for_actor(child)
        assert "doc.write" not in child_effective
        assert child_effective == {"tool.invoke", "web.read"}

    def test_scope_escalation_is_rejected(self) -> None:
        adapter, _ = _new_adapter()
        parent = _issue_root(adapter, issuer_scopes=["tool.invoke"])
        with pytest.raises(VerificationError, match="not allowed"):
            adapter.delegate(
                parent,
                "spiffe://example.org/agent/researcher",
                ["doc.write"],  # parent never had it
                {},
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )

    def test_cross_trust_domain_rejected_without_caveat(self) -> None:
        adapter, _ = _new_adapter()
        parent = _issue_root(adapter)
        with pytest.raises(VerificationError, match="Cross-trust-domain"):
            adapter.delegate(
                parent,
                "spiffe://other.example/agent/peer",
                ["tool.invoke"],
                {},  # no allow_cross_trust_domain
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )

    def test_cross_trust_domain_succeeds_with_explicit_federation(self) -> None:
        adapter, audit = _new_adapter()
        parent = _issue_root(adapter)
        child = adapter.delegate(
            parent,
            "spiffe://other.example/agent/peer",
            ["tool.invoke"],
            {"spiffe.allow_cross_trust_domain": True},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert adapter.verify(child)
        last_event = audit.get(child.audit_ref)
        assert last_event["federation"] is True
        assert last_event["parent_trust_domain"] == "example.org"
        assert last_event["child_trust_domain"] == "other.example"
        # The delegation row on the envelope captures the same federation marker.
        federation_delegation = child.delegations[-1]
        assert federation_delegation.caveats["spiffe.federation"] is True

    def test_delegate_rejects_same_subject(self) -> None:
        adapter, _ = _new_adapter()
        parent = _issue_root(adapter)
        with pytest.raises(VerificationError, match="must differ"):
            adapter.delegate(
                parent,
                parent.system_identifier,
                ["tool.invoke"],
                {},
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )


# ---------- verification + tamper detection ----------------------------------


class TestVerifyAndTamper:
    def test_tampered_payload_fails_verify(self) -> None:
        adapter, _ = _new_adapter()
        env = _issue_root(adapter)
        # Forge a new payload but keep the original signature: verify must fail.
        header_b64, _, sig_b64 = env.metadata["spiffe.svid_jws"].split(".")
        forged_payload = {"sub": env.system_identifier, "iat": 0, "exp": 9999999999}
        forged_payload_b64 = _b64url_encode(
            json.dumps(forged_payload, sort_keys=True, separators=(",", ":")).encode()
        )
        env.metadata["spiffe.svid_jws"] = (
            f"{header_b64}.{forged_payload_b64}.{sig_b64}"
        )
        assert adapter.verify(env) is False

    def test_verify_chain_event_detects_tamper(self) -> None:
        adapter, audit = _new_adapter()
        env = _issue_root(adapter)
        adapter.verify_chain_event(env.audit_ref)

        # Mutate the stored SVID in the audit log → re-verification must fail.
        event = audit.get(env.audit_ref)
        parts = event["svid_jws"].split(".")
        forged_payload_b64 = _b64url_encode(
            json.dumps({"sub": "spoofed", "iat": 0, "exp": 9999999999}).encode()
        )
        event["svid_jws"] = ".".join([parts[0], forged_payload_b64, parts[2]])
        with pytest.raises(VerificationError):
            adapter.verify_chain_event(env.audit_ref)

    def test_expired_svid_fails_verify(self) -> None:
        # Issue with a 0-second TTL → exp == iat → verify must fail.
        audit = MemoryAuditStore()
        adapter = SpiffeIdentityAdapter(
            Ed25519Signer.generate(),
            audit_store=audit,
            svid_ttl=timedelta(seconds=0),
        )
        env = adapter.issue(
            {
                "system_identifier": "spiffe://example.org/agent/short",
                "instance_id": "i",
                "deployment_id": "d",
                "owner_id": "team:x",
                "provenance": {"code_hash": "sha256:a"},
                "attestation_chain": ["local:x"],
                "issuer_scopes": ["tool.invoke"],
            }
        )
        assert adapter.verify(env) is False


# ---------- audit material action -------------------------------------------


class TestAuditMaterialAction:
    def test_audit_appends_signed_action_row(self) -> None:
        adapter, audit = _new_adapter()
        env = _issue_root(adapter)
        ref = adapter.audit(
            env,
            {
                "action_type": "tool.call",
                "required_scope": "tool.invoke",
                "input_hash": "in",
                "output_hash": "out",
            },
        )
        row = audit.get(ref)
        assert row["kind"] == "spiffe_action"
        # action_jws must verify against the JWK in the row.
        jwk = row["jwk"]
        pub = _b64url_decode(jwk["x"])
        from autonomous_identity.adapters.spiffe import _jws_verify  # noqa: PLC2701

        payload = _jws_verify(row["action_jws"], pub)
        assert payload["sub"] == env.system_identifier
        assert payload["action_type"] == "tool.call"


# ---------- registry --------------------------------------------------------


class TestRegistry:
    def test_spiffe_adapter_is_discoverable(self) -> None:
        assert "spiffe" in list_adapters()

    def test_get_adapter_returns_spiffe_instance(self) -> None:
        audit = MemoryAuditStore()
        deps = {
            "signer": Ed25519Signer.generate(),
            "audit_store": audit,
        }
        adapter = get_adapter("spiffe", deps)
        assert adapter.name == "spiffe"
        env = adapter.issue(
            {
                "system_identifier": "spiffe://example.org/agent/x",
                "instance_id": "i",
                "deployment_id": "d",
                "owner_id": "team:x",
                "provenance": {"code_hash": "sha256:a"},
                "attestation_chain": ["local:x"],
                "issuer_scopes": ["tool.invoke"],
            }
        )
        assert adapter.verify(env)
