"""Composite SPIFFE + Merkle DAG identity adapter.

The single-primitive adapters each have known weak axes per Table 8.2 of
``primary-idea.md``:

* :class:`SpiffeIdentityAdapter` is **medium** on owner-bound, provenance,
  and audit.
* :class:`MerkleDagIdentityAdapter` is **medium** on lifecycle control.

Their weaknesses are complementary. This adapter composes them so the
envelope is strong on all eight properties.

Composition strategy
====================

Subclass the DAG adapter (so multi-parent audit comes for free) and
overlay SPIFFE SVID claims onto every issue / delegate. Each envelope
carries both signature artifacts simultaneously:

* ``signature_chain[0]`` — the DAG node signature (binds the action and
  the envelope commitment hash). Verifiable from the audit store row.
* ``signature_chain[1]`` — the JWT-SVID compact JWS (binds the SPIFFE
  ID, audience, expiry, and a SPIFFE-strict commitment hash). Verifiable
  from the envelope's embedded JWKS.

Verifiers requiring either artifact can use either. Verifiers requiring
both must validate both. ``verify()`` on this adapter checks both.

Field mapping vs single-primitive adapters
==========================================

============================ ============= ============ ============
Property                      SPIFFE        DAG          **This**
============================ ============= ============ ============
Persistent                    Strong        Strong       Strong
Addressable                   Strong        Strong       Strong (SPIFFE ID)
Verifiable                    Strong        Strong       Strong (JWS + Merkle)
Owner-bound                   Medium        Strong       Strong (TD + caveats)
Instance-specific             Strong        Strong       Strong (SVID + node)
Provenance-aware              Medium        Very strong  Very strong (provenance + DAG witnesses)
Lifecycle-controlled          Strong        Medium       Strong (SVID TTL + lifecycle store)
Auditable                     Medium        Very strong  Very strong (DAG + JWS)
============================ ============= ============ ============

What this adapter does NOT yet do
=================================

The remaining three property "Very strong" cells from Table 8.2 require
sub-primitives the library does not ship yet:

* **Hardware-rooted attestation** for "Very strong" instance specificity.
  The adapter carries ``metadata['spiffe.workload_api_socket']`` and the
  envelope's ``runtime_instance.attestation_ref`` forward, but does not
  itself verify hardware measurements. A future ``spire`` adapter or
  ``tee`` adapter slots in via composition.
* **in-toto / SLSA** for "Very strong" provenance. The envelope carries
  ``provenance.slsa_attestation_ref`` and
  ``provenance.in_toto_statement_ref`` fields forward, but does not yet
  verify the referenced attestations. A future ``slsa`` adapter
  composes here too.
* **Verifiable Credentials + DIDs** for cross-organization owner
  composition. SPIFFE federation handles the cross-trust-domain case
  for now; cross-issuer composition is a separate axis.

The composite adapter's contract is "strong on all eight as of today,
with hooks reserved for very-strong upgrades when those adapters ship".
"""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any

from autonomous_identity.adapters.merkle_dag import (
    MerkleDagIdentityAdapter,
    MerkleDagNode,
    _node_from_dict,
)
from autonomous_identity.adapters.spiffe import (
    _SVID_METADATA_KEYS,
    _b64url_decode,
    _b64url_encode,
    _jws_sign,
    _jws_verify,
    _jwks_lookup,
    _public_key_to_jwk,
    build_spiffe_id,
    parse_spiffe_id,
)


# Composite adapter inherits the DAG adapter's audit mechanism, which
# mutates ``dag_tip_node_id`` / ``dag_tip_hash`` on the envelope metadata
# after every material action. The SVID's ``commitment_hash`` claim must
# bind to a view of the envelope that survives those mutations — otherwise
# the SVID minted at issue time stops matching after the first audit row
# is appended. We exclude both the SVID material AND the DAG tip pointers
# from the commitment used by the SVID claim.
_COMPOSITE_VOLATILE_METADATA_KEYS: tuple[str, ...] = (
    *_SVID_METADATA_KEYS,
    "dag_tip_node_id",
    "dag_tip_hash",
)


def _composite_strict_commitment_hash(envelope: "IdentityEnvelope") -> str:
    """Envelope commitment with SVID + DAG-tip metadata stripped.

    Distinct from the standalone SPIFFE adapter's strict commitment because
    this composite uses both SVID artifacts and a mutating DAG tip pointer.
    Without this exclusion the SVID is invalidated by every material
    action that audits a new DAG node.
    """
    from autonomous_identity.core.hashing import hash_canonical
    from autonomous_identity.core.serialize import envelope_commitment_payload

    payload = envelope_commitment_payload(envelope)
    meta = dict(payload.get("metadata") or {})
    for key in _COMPOSITE_VOLATILE_METADATA_KEYS:
        meta.pop(key, None)
    payload["metadata"] = meta
    return hash_canonical(payload)
from autonomous_identity.core.delegation_util import effective_scopes_for_actor
from autonomous_identity.core.envelope import (
    Delegation,
    IdentityEnvelope,
)
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.core.hashing import hash_canonical
from autonomous_identity.core.serialize import (
    envelope_commitment_payload,
)
from autonomous_identity.crypto.ed25519 import Ed25519Signer
from autonomous_identity.storage.base import AuditStore


class CompositeIdentityAdapter(MerkleDagIdentityAdapter):
    """SPIFFE + Merkle DAG hybrid. Strong on all eight properties.

    Inherits multi-parent audit semantics from the DAG adapter; layers
    SPIFFE SVID claims, trust-domain enforcement, and SVID-expiry checks
    on top.
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
        self._default_audience = (
            default_audience if default_audience is not None else self.DEFAULT_AUDIENCE
        )
        self._public_raw = signer.public_bytes()
        self._jwk = _public_key_to_jwk(self._public_raw)
        self._jwks = {"keys": [self._jwk]}

    # ----- issuance ---------------------------------------------------------

    def issue(self, context: dict[str, Any]) -> IdentityEnvelope:
        # Resolve the SPIFFE ID (or build one from spiffe_trust_domain +
        # spiffe_path) before the DAG adapter sees the context, so the
        # system_identifier is in canonical SPIFFE form.
        sid = _resolve_spiffe_system_id(context)
        context = dict(context)
        context["system_identifier"] = sid
        trust_domain, _ = parse_spiffe_id(sid)

        # Let the DAG adapter mint the envelope and the genesis DAG node.
        envelope = super().issue(context)

        # Overlay SPIFFE SVID material. This becomes the second artifact
        # on the envelope, alongside the DAG node signature.
        envelope.metadata["spiffe.id"] = sid
        envelope.metadata["spiffe.trust_domain"] = trust_domain
        envelope.metadata["spiffe.kid"] = self._jwk["kid"]
        envelope.metadata["spiffe.jwks"] = self._jwks
        audience = context.get("spiffe_audience", self._default_audience)
        if audience:
            envelope.metadata["spiffe.audience"] = audience

        # Forward hooks for the future SPIRE / hardware-attestation adapter.
        if "spire_workload_api_socket" in context:
            envelope.metadata["spiffe.workload_api_socket"] = context[
                "spire_workload_api_socket"
            ]

        # Mint the SVID. Its `commitment_hash` binds to the SPIFFE-strict
        # commitment (excludes SVID material from metadata) so we don't
        # hit the circular-dependency trap the SPIFFE adapter solved.
        svid_jws, svid_payload = self._mint_svid(
            envelope, now=datetime.now(timezone.utc), audience=audience
        )
        envelope.metadata["spiffe.svid_jws"] = svid_jws
        envelope.metadata["spiffe.svid_iat"] = svid_payload["iat"]
        envelope.metadata["spiffe.svid_exp"] = svid_payload["exp"]
        envelope.metadata["spiffe.svid_jti"] = svid_payload["jti"]

        # Append the SVID to the signature chain so verifiers can pull
        # either artifact off the envelope.
        envelope.signature_chain.append(svid_jws)

        # Update the audit row in place with the SVID claims so an
        # auditor reading from cold storage sees both artifacts.
        if envelope.audit_ref:
            self._enrich_row_with_svid(envelope, svid_jws, svid_payload)

        return envelope

    # ----- delegation -------------------------------------------------------

    def delegate(
        self,
        envelope: IdentityEnvelope,
        child_subject: str,
        allowed_scopes: list[str],
        caveats: dict[str, Any],
        *,
        expires_at: datetime | None = None,
    ) -> IdentityEnvelope:
        # SPIFFE-style trust-domain enforcement happens BEFORE the DAG
        # adapter touches the child. Cross-TD requires the explicit
        # federation caveat.
        parent_td, _ = parse_spiffe_id(envelope.system_identifier)
        child_td, _ = parse_spiffe_id(child_subject)
        cross_td = parent_td != child_td
        allow_cross = bool(caveats.get("spiffe.allow_cross_trust_domain"))
        if cross_td and not allow_cross:
            raise VerificationError(
                f"Cross-trust-domain delegation ({parent_td!r} -> {child_td!r}) "
                "requires caveats['spiffe.allow_cross_trust_domain']=True "
                "(SPIFFE federation must be explicit)"
            )

        # Enrich caveats so the audit row makes federation operationally visible.
        enriched_caveats = dict(caveats)
        if cross_td:
            enriched_caveats["spiffe.federation"] = True
            enriched_caveats["spiffe.parent_trust_domain"] = parent_td
            enriched_caveats["spiffe.child_trust_domain"] = child_td

        # Let the DAG adapter do scope-monotonicity + delegation mechanics.
        child = super().delegate(
            envelope,
            child_subject,
            allowed_scopes,
            enriched_caveats,
            expires_at=expires_at,
        )

        # Overlay SVID material onto the child envelope.
        child.metadata["spiffe.id"] = child_subject
        child.metadata["spiffe.trust_domain"] = child_td
        child.metadata["spiffe.kid"] = self._jwk["kid"]
        child.metadata["spiffe.jwks"] = self._jwks
        audience = envelope.metadata.get("spiffe.audience", self._default_audience)
        if audience:
            child.metadata["spiffe.audience"] = audience

        svid_jws, svid_payload = self._mint_svid(
            child, now=datetime.now(timezone.utc), audience=audience
        )
        child.metadata["spiffe.svid_jws"] = svid_jws
        child.metadata["spiffe.svid_iat"] = svid_payload["iat"]
        child.metadata["spiffe.svid_exp"] = svid_payload["exp"]
        child.metadata["spiffe.svid_jti"] = svid_payload["jti"]

        child.signature_chain.append(svid_jws)

        if child.audit_ref:
            self._enrich_row_with_svid(child, svid_jws, svid_payload)
            self._enrich_row_with_federation(child, cross_td, parent_td, child_td)

        return child

    # ----- verification -----------------------------------------------------

    def verify(self, envelope: IdentityEnvelope) -> bool:
        # Both artifacts must validate. Either one missing or wrong = fail.
        if not super().verify(envelope):
            return False
        try:
            self._verify_svid(envelope)
        except VerificationError:
            return False
        return True

    def verify_chain_event(self, audit_ref: str) -> None:
        """Verify a composite audit row.

        Checks the DAG node signature AND (when the row carries SVID
        material) the embedded JWT-SVID against the audit row's JWKS.
        """
        # DAG-side check: signature on the node hash, envelope commitment matches.
        super().verify_chain_event(audit_ref)

        # SPIFFE-side check, when present.
        event = self._audit_store.get(audit_ref)
        if not event:
            raise VerificationError("audit_ref not found")
        svid_jws = event.get("svid_jws")
        if not svid_jws:
            return  # action rows without SVID claims are fine
        commitment = event.get("envelope_commitment") or {}
        metadata = commitment.get("metadata") or {}
        jwks = metadata.get("spiffe.jwks")
        if not jwks:
            raise VerificationError("Audit row carries SVID but no JWKS to verify it")
        kid = metadata.get("spiffe.kid")
        pub_raw = _jwks_lookup(jwks, kid)
        payload = _jws_verify(svid_jws, pub_raw)

        # The SVID's commitment_hash binds to the SPIFFE-strict commitment,
        # which excludes SVID metadata. Compare against the row's
        # commitment with SVID keys stripped (matches the SPIFFE adapter's
        # behaviour for backward compat with rows that don't carry a
        # separate spiffe_commitment view).
        strip = {
            k: v
            for k, v in metadata.items()
            if k not in _COMPOSITE_VOLATILE_METADATA_KEYS
        }
        strict_payload = {**commitment, "metadata": strip}
        if payload.get("commitment_hash") != hash_canonical(strict_payload):
            raise VerificationError(
                "SVID commitment_hash does not match audit row's SPIFFE-strict commitment"
            )

    # ----- helpers ----------------------------------------------------------

    def _mint_svid(
        self,
        envelope: IdentityEnvelope,
        *,
        now: datetime,
        audience: str | None,
    ) -> tuple[str, dict[str, Any]]:
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
            raise VerificationError(
                f"SVID sub {payload.get('sub')!r} != envelope subject "
                f"{envelope.system_identifier!r}"
            )
        expected = _composite_strict_commitment_hash(envelope)
        if payload.get("commitment_hash") != expected:
            raise VerificationError(
                "SVID commitment_hash does not match envelope commitment"
            )
        # SVID expiry
        now = datetime.now(timezone.utc)
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and exp <= int(now.timestamp()):
            raise VerificationError("SVID has expired")

    def _enrich_row_with_svid(
        self,
        envelope: IdentityEnvelope,
        svid_jws: str,
        svid_payload: dict[str, Any],
    ) -> None:
        """Update the audit store row in place with SVID material.

        The DAG adapter wrote a base row when it called the audit store.
        We need that row to also carry the SVID so a verifier reading from
        cold storage sees the full composite artifact.
        """
        row = self._audit_store.get(envelope.audit_ref or "")
        if not row:
            return
        # Keep ``kind == "dag_node"`` so the inherited DAG verify() finds the
        # row and validates the node signature. We add SVID fields alongside;
        # the composite verify_chain_event() picks them up by direct field
        # lookup, not by ``kind``.
        row["svid_jws"] = svid_jws
        row["svid_payload"] = svid_payload
        # Keep both commitments in the row so verifiers can pick the right
        # one. The DAG node committed to the full envelope; the SVID
        # commits to the SPIFFE-strict view.
        row["spiffe_commitment"] = {
            "metadata": {
                k: v
                for k, v in (row.get("envelope_commitment") or {}).get("metadata", {}).items()
                if k not in _SVID_METADATA_KEYS
            },
            **{
                k: v
                for k, v in (row.get("envelope_commitment") or {}).items()
                if k != "metadata"
            },
        }
        # Some audit stores are immutable; for those (file/sqlite/postgres)
        # the row is written once. We instead append an enrichment record.
        if hasattr(self._audit_store, "_records") and isinstance(
            getattr(self._audit_store, "_records"), dict
        ):
            # MemoryAuditStore: mutate in place is fine.
            self._audit_store._records[envelope.audit_ref] = row  # noqa: SLF001
        else:
            # FileAuditStore: row is already written. Append an enrichment
            # row so a verifier can find the SVID material later.
            self._audit_store.append(
                {
                    "kind": "composite_enrich",
                    "for_audit_ref": envelope.audit_ref,
                    "system_identifier": envelope.system_identifier,
                    "svid_jws": svid_jws,
                    "svid_payload": svid_payload,
                }
            )

    def _enrich_row_with_federation(
        self,
        envelope: IdentityEnvelope,
        cross_td: bool,
        parent_td: str,
        child_td: str,
    ) -> None:
        if not cross_td:
            return
        row = self._audit_store.get(envelope.audit_ref or "")
        if not row:
            return
        row["federation"] = True
        row["parent_trust_domain"] = parent_td
        row["child_trust_domain"] = child_td
        if hasattr(self._audit_store, "_records") and isinstance(
            getattr(self._audit_store, "_records"), dict
        ):
            self._audit_store._records[envelope.audit_ref] = row  # noqa: SLF001


def _resolve_spiffe_system_id(context: dict[str, Any]) -> str:
    sid = context.get("system_identifier")
    if isinstance(sid, str) and sid:
        parse_spiffe_id(sid)
        return sid
    td = context.get("spiffe_trust_domain")
    if not td:
        raise VerificationError(
            "Composite adapter requires either a 'system_identifier' shaped "
            "spiffe://<trust_domain>/<path> or 'spiffe_trust_domain' "
            "(+ optional 'spiffe_path') in the issue context"
        )
    return build_spiffe_id(td, context.get("spiffe_path"))
