"""Composite SPIFFE + Merkle DAG identity adapter.

This adapter combines two deployable primitives:

* :class:`SpiffeIdentityAdapter`-style JWT-SVID claims for addressable
  workload identity, trust-domain semantics, and token expiry.
* :class:`MerkleDagIdentityAdapter` audit rows for graph-shaped,
  multi-parent attestation.

The composition is intentionally conservative. It provides strong local
cryptographic verification for the envelope and strong local audit-node
verification. It binds provenance references into the envelope commitment,
but it does not itself verify external SLSA/in-toto attestations or
hardware measurements. Those checks require additional adapters/verifiers.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from autonomous_identity.adapters.merkle_dag import MerkleDagIdentityAdapter
from autonomous_identity.adapters.spiffe import (
    _SVID_METADATA_KEYS,
    _jws_sign,
    _jws_verify,
    _jwks_lookup,
    _public_key_to_jwk,
    build_spiffe_id,
    parse_spiffe_id,
)


# Composite audit mutates DAG tip metadata after each action. SVID commitment
# verification must survive those expected mutations.
_COMPOSITE_VOLATILE_METADATA_KEYS: tuple[str, ...] = (
    *_SVID_METADATA_KEYS,
    "dag_tip_node_id",
    "dag_tip_hash",
)


def _composite_strict_commitment_hash(envelope: "IdentityEnvelope") -> str:
    """Hash the envelope view bound by the SVID.

    The SVID view excludes SVID metadata and mutable DAG-tip pointers. It
    still binds the stable identity, runtime, delegation, and provenance
    fields that define the autonomous-system identity at issue/delegation
    time.
    """
    from autonomous_identity.core.hashing import hash_canonical
    from autonomous_identity.core.serialize import envelope_commitment_payload

    payload = envelope_commitment_payload(envelope)
    meta = dict(payload.get("metadata") or {})
    for key in _COMPOSITE_VOLATILE_METADATA_KEYS:
        meta.pop(key, None)
    payload["metadata"] = meta
    return hash_canonical(payload)


from autonomous_identity.core.envelope import IdentityEnvelope
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.core.hashing import hash_canonical
from autonomous_identity.crypto.ed25519 import Ed25519Signer
from autonomous_identity.storage.base import AuditStore


class CompositeIdentityAdapter(MerkleDagIdentityAdapter):
    """SPIFFE + Merkle DAG hybrid.

    ``verify(envelope)`` checks both the current DAG-side proof and the
    embedded SVID. ``verify_chain_event(audit_ref)`` verifies the DAG audit
    row and, for issue/delegate rows produced by this adapter, fails closed
    unless the SVID side of the composite proof is also available and valid.
    """

    name = "composite"

    DEFAULT_SVID_TTL = timedelta(hours=24)
    DEFAULT_AUDIENCE = "spiffe://local"

    def __init__(
        self,
        signer: Ed25519Signer,
        *,
        audit_store: AuditStore,
        svid_ttl: timedelta | None = None,
        default_audience: str | None = None,
    ) -> None:
        super().__init__(signer, audit_store=audit_store)
        self._svid_ttl = svid_ttl if svid_ttl is not None else self.DEFAULT_SVID_TTL
        self._default_audience = default_audience if default_audience is not None else self.DEFAULT_AUDIENCE
        self._public_raw = signer.public_bytes()
        self._jwk = _public_key_to_jwk(self._public_raw)
        self._jwks = {"keys": [self._jwk]}

    def issue(self, context: dict[str, Any]) -> IdentityEnvelope:
        sid = _resolve_spiffe_system_id(context)
        context = dict(context)
        context["system_identifier"] = sid
        trust_domain, _ = parse_spiffe_id(sid)

        envelope = super().issue(context)

        envelope.metadata["spiffe.id"] = sid
        envelope.metadata["spiffe.trust_domain"] = trust_domain
        envelope.metadata["spiffe.kid"] = self._jwk["kid"]
        envelope.metadata["spiffe.jwks"] = self._jwks
        audience = context.get("spiffe_audience", self._default_audience)
        if audience:
            envelope.metadata["spiffe.audience"] = audience
        if "spire_workload_api_socket" in context:
            envelope.metadata["spiffe.workload_api_socket"] = context["spire_workload_api_socket"]

        svid_jws, svid_payload = self._mint_svid(envelope, now=datetime.now(timezone.utc), audience=audience)
        envelope.metadata["spiffe.svid_jws"] = svid_jws
        envelope.metadata["spiffe.svid_iat"] = svid_payload["iat"]
        envelope.metadata["spiffe.svid_exp"] = svid_payload["exp"]
        envelope.metadata["spiffe.svid_jti"] = svid_payload["jti"]
        envelope.signature_chain.append(svid_jws)

        if envelope.audit_ref:
            self._enrich_row_with_svid(envelope, svid_jws, svid_payload)

        return envelope

    def delegate(
        self,
        envelope: IdentityEnvelope,
        child_subject: str,
        allowed_scopes: list[str],
        caveats: dict[str, Any],
        *,
        expires_at: datetime | None = None,
    ) -> IdentityEnvelope:
        parent_td, _ = parse_spiffe_id(envelope.system_identifier)
        child_td, _ = parse_spiffe_id(child_subject)
        cross_td = parent_td != child_td
        allow_cross = bool(caveats.get("spiffe.allow_cross_trust_domain"))
        if cross_td and not allow_cross:
            raise VerificationError(
                f"Cross-trust-domain delegation ({parent_td!r} -> {child_td!r}) "
                "requires caveats['spiffe.allow_cross_trust_domain']=True"
            )

        enriched_caveats = dict(caveats)
        if cross_td:
            enriched_caveats["spiffe.federation"] = True
            enriched_caveats["spiffe.parent_trust_domain"] = parent_td
            enriched_caveats["spiffe.child_trust_domain"] = child_td

        child = super().delegate(envelope, child_subject, allowed_scopes, enriched_caveats, expires_at=expires_at)

        child.metadata["spiffe.id"] = child_subject
        child.metadata["spiffe.trust_domain"] = child_td
        child.metadata["spiffe.kid"] = self._jwk["kid"]
        child.metadata["spiffe.jwks"] = self._jwks
        audience = envelope.metadata.get("spiffe.audience", self._default_audience)
        if audience:
            child.metadata["spiffe.audience"] = audience

        svid_jws, svid_payload = self._mint_svid(child, now=datetime.now(timezone.utc), audience=audience)
        child.metadata["spiffe.svid_jws"] = svid_jws
        child.metadata["spiffe.svid_iat"] = svid_payload["iat"]
        child.metadata["spiffe.svid_exp"] = svid_payload["exp"]
        child.metadata["spiffe.svid_jti"] = svid_payload["jti"]
        child.signature_chain.append(svid_jws)

        if child.audit_ref:
            self._enrich_row_with_svid(child, svid_jws, svid_payload)
            self._enrich_row_with_federation(child, cross_td, parent_td, child_td)

        return child

    def verify(self, envelope: IdentityEnvelope) -> bool:
        if not super().verify(envelope):
            return False
        try:
            self._verify_svid(envelope)
        except VerificationError:
            return False
        return True

    def verify_chain_event(self, audit_ref: str) -> None:
        """Verify the local composite audit evidence for one row.

        This method is intentionally node-local. It verifies the referenced
        DAG node and the SVID proof for composite issue/delegate rows. It
        does not recursively prove the full DAG ancestor closure.
        """
        super().verify_chain_event(audit_ref)
        event = self._audit_store.get(audit_ref)
        if not event:
            raise VerificationError("audit_ref not found")

        svid_jws = event.get("svid_jws")
        enrichment = None
        if not svid_jws:
            enrichment = self._find_composite_enrichment(audit_ref)
            if enrichment:
                svid_jws = enrichment.get("svid_jws")

        if not svid_jws:
            action_type = (event.get("node") or {}).get("action_type")
            if action_type in {"issue", "delegate"}:
                raise VerificationError(
                    "Composite audit row is missing SVID material; refusing to downgrade to DAG-only verification"
                )
            return

        commitment = event.get("envelope_commitment") or {}
        metadata = commitment.get("metadata") or {}
        jwks = metadata.get("spiffe.jwks")
        kid = metadata.get("spiffe.kid")
        if not jwks or not kid:
            if not enrichment:
                enrichment = self._find_composite_enrichment(audit_ref)
            if enrichment:
                jwks = enrichment.get("spiffe_jwks") or jwks
                kid = enrichment.get("spiffe_kid") or kid
        if not jwks or not kid:
            raise VerificationError("Audit row carries SVID but no JWKS/kid to verify it")

        pub_raw = _jwks_lookup(jwks, kid)
        payload = _jws_verify(svid_jws, pub_raw)
        strict_payload = self._strict_payload_from_commitment(commitment)
        if payload.get("commitment_hash") != hash_canonical(strict_payload):
            raise VerificationError("SVID commitment_hash does not match audit row's SPIFFE-strict commitment")

    def _mint_svid(self, envelope: IdentityEnvelope, *, now: datetime, audience: str | None) -> tuple[str, dict[str, Any]]:
        commitment = _composite_strict_commitment_hash(envelope)
        payload: dict[str, Any] = {
            "sub": envelope.system_identifier,
            "aud": audience or self._default_audience,
            "iat": int(now.timestamp()),
            "exp": int((now + self._svid_ttl).timestamp()),
            "jti": str(uuid.uuid4()),
            "commitment_hash": commitment,
        }
        header = {"alg": "EdDSA", "typ": "JWT", "kid": self._jwk["kid"]}
        return _jws_sign(self._signer, header, payload), payload

    def _verify_svid(self, envelope: IdentityEnvelope) -> None:
        jws = envelope.metadata.get("spiffe.svid_jws")
        jwks = envelope.metadata.get("spiffe.jwks")
        kid = envelope.metadata.get("spiffe.kid")
        if not jws or not jwks:
            raise VerificationError("Envelope missing SPIFFE SVID material")
        pub_raw = _jwks_lookup(jwks, kid)
        payload = _jws_verify(jws, pub_raw)
        if payload.get("sub") != envelope.system_identifier:
            raise VerificationError(f"SVID sub {payload.get('sub')!r} != envelope subject {envelope.system_identifier!r}")
        expected = _composite_strict_commitment_hash(envelope)
        if payload.get("commitment_hash") != expected:
            raise VerificationError("SVID commitment_hash does not match envelope commitment")
        now = datetime.now(timezone.utc)
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and exp <= int(now.timestamp()):
            raise VerificationError("SVID has expired")

    def _enrich_row_with_svid(self, envelope: IdentityEnvelope, svid_jws: str, svid_payload: dict[str, Any]) -> None:
        row = self._audit_store.get(envelope.audit_ref or "")
        if not row:
            return

        row["svid_jws"] = svid_jws
        row["svid_payload"] = svid_payload
        row["spiffe_commitment"] = self._strict_payload_from_commitment(row.get("envelope_commitment") or {})

        if self._replace_audit_row_if_mutable(envelope.audit_ref or "", row):
            return

        self._audit_store.append(
            {
                "kind": "composite_enrich",
                "for_audit_ref": envelope.audit_ref,
                "system_identifier": envelope.system_identifier,
                "svid_jws": svid_jws,
                "svid_payload": svid_payload,
                "spiffe_jwks": envelope.metadata.get("spiffe.jwks"),
                "spiffe_kid": envelope.metadata.get("spiffe.kid"),
                "spiffe_commitment": row["spiffe_commitment"],
            }
        )

    def _enrich_row_with_federation(self, envelope: IdentityEnvelope, cross_td: bool, parent_td: str, child_td: str) -> None:
        if not cross_td:
            return
        row = self._audit_store.get(envelope.audit_ref or "")
        if not row:
            return
        row["federation"] = True
        row["parent_trust_domain"] = parent_td
        row["child_trust_domain"] = child_td
        self._replace_audit_row_if_mutable(envelope.audit_ref or "", row)

    def _replace_audit_row_if_mutable(self, audit_ref: str, row: dict[str, Any]) -> bool:
        """Best-effort replacement for mutable in-memory audit stores."""
        for attr in ("_events", "_records"):
            store = getattr(self._audit_store, attr, None)
            if isinstance(store, dict):
                store[audit_ref] = row
                return True
        return False

    def _find_composite_enrichment(self, audit_ref: str) -> dict[str, Any] | None:
        """Find append-only enrichment rows for stores the library ships today."""
        for attr in ("_events", "_records"):
            store = getattr(self._audit_store, attr, None)
            if isinstance(store, dict):
                for row in store.values():
                    if row.get("kind") == "composite_enrich" and row.get("for_audit_ref") == audit_ref:
                        return row

        path = getattr(self._audit_store, "_path", None)
        if path:
            p = Path(path)
            if p.exists():
                with p.open(encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        row = json.loads(line)
                        if row.get("kind") == "composite_enrich" and row.get("for_audit_ref") == audit_ref:
                            return row
        return None

    @staticmethod
    def _strict_payload_from_commitment(commitment: dict[str, Any]) -> dict[str, Any]:
        metadata = dict((commitment or {}).get("metadata") or {})
        for key in _COMPOSITE_VOLATILE_METADATA_KEYS:
            metadata.pop(key, None)
        return {**(commitment or {}), "metadata": metadata}


def _resolve_spiffe_system_id(context: dict[str, Any]) -> str:
    sid = context.get("system_identifier")
    if isinstance(sid, str) and sid:
        parse_spiffe_id(sid)
        return sid
    td = context.get("spiffe_trust_domain")
    if not td:
        raise VerificationError(
            "Composite adapter requires either a 'system_identifier' shaped spiffe://<trust_domain>/<path> "
            "or 'spiffe_trust_domain' (+ optional 'spiffe_path') in the issue context"
        )
    return build_spiffe_id(td, context.get("spiffe_path"))
