"""Cross-trust-domain trust bundles for SPIFFE federation.

In real SPIFFE deployments, federation requires each trust domain to publish a
JWKS that peer trust domains consume (e.g. via SPIRE's federation API or static
out-of-band exchange). This module models that out-of-band exchange in the
demo: each tenant exposes its JWKS, peers store the published JWKS in their
local trust bundle, and inbound envelopes are verified against the bundle
**before** any work is performed.

For the demo this is just an in-memory map. In production it would be:
    - SPIRE's federation API (``spire-server federation``)
    - A static JSON file mounted into the workload
    - A trust-bundle distribution service
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

from autonomous_identity.core.envelope import IdentityEnvelope
from autonomous_identity.core.exceptions import VerificationError


@dataclass
class TrustBundle:
    """Trust-domain → expected JWKS (set of allowed public keys)."""

    name: str  # the local trust domain this bundle belongs to
    bundles: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add_peer(self, peer_trust_domain: str, jwks: dict[str, Any]) -> None:
        self.bundles[peer_trust_domain] = jwks

    def has_peer(self, peer_trust_domain: str) -> bool:
        return peer_trust_domain in self.bundles

    def jwks_for(self, peer_trust_domain: str) -> dict[str, Any] | None:
        return self.bundles.get(peer_trust_domain)


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def verify_federated_envelope(
    envelope: IdentityEnvelope,
    *,
    expected_trust_domain: str,
    trust_bundle: TrustBundle,
) -> dict[str, Any]:
    """Independent receiver-side verification for a cross-TD envelope.

    Performs:
        1. SPIFFE ID parses and is in ``expected_trust_domain`` (the receiver's TD).
        2. The delegation chain crosses into ``expected_trust_domain`` and carries
           the ``spiffe.federation: True`` caveat.
        3. The envelope's embedded JWKS matches the JWKS we already trust for
           the parent trust domain (loaded out-of-band into ``trust_bundle``).
        4. The SVID's signature verifies against that trusted JWKS.

    Returns a structured verification record. Raises :class:`VerificationError`
    if any check fails.
    """
    from autonomous_identity.adapters.spiffe import (  # noqa: PLC0415
        _jws_verify,
        _spiffe_commitment_hash,
        parse_spiffe_id,
    )

    # 1. Subject is a SPIFFE ID in our trust domain.
    td, _ = parse_spiffe_id(envelope.system_identifier)
    if td != expected_trust_domain:
        raise VerificationError(
            f"Envelope is for trust domain {td!r}, not this receiver's "
            f"{expected_trust_domain!r}"
        )

    # 2. Find a federation-marked delegation ending in our TD.
    federation_edge = None
    for d in envelope.delegations:
        try:
            parent_td, _ = parse_spiffe_id(d.parent_subject)
            child_td, _ = parse_spiffe_id(d.child_subject)
        except VerificationError:
            continue
        if (
            child_td == expected_trust_domain
            and parent_td != expected_trust_domain
            and d.caveats.get("spiffe.federation") is True
        ):
            federation_edge = d
            break
    if federation_edge is None:
        raise VerificationError(
            "No federated delegation edge crosses into "
            f"trust domain {expected_trust_domain!r}"
        )

    parent_td, _ = parse_spiffe_id(federation_edge.parent_subject)

    # 3. Trust bundle lookup. The envelope must use the JWKS we already trust
    #    for the parent trust domain; otherwise a malicious sender could
    #    embed their own JWKS and forge envelopes.
    if not trust_bundle.has_peer(parent_td):
        raise VerificationError(
            f"No trust-bundle entry for peer trust domain {parent_td!r}. "
            "Federation requires the parent trust domain's JWKS to be "
            "exchanged out-of-band before any envelope is accepted."
        )
    trusted_jwks = trust_bundle.jwks_for(parent_td) or {}
    sent_jwks = envelope.metadata.get("spiffe.jwks") or {}
    trusted_kids = {k.get("kid") for k in trusted_jwks.get("keys", [])}
    sent_kids = {k.get("kid") for k in sent_jwks.get("keys", [])}
    if not (sent_kids & trusted_kids):
        raise VerificationError(
            f"Envelope JWKS for {parent_td!r} (kids={sorted(sent_kids)}) does not "
            f"match the trust bundle (trusted kids={sorted(trusted_kids)})"
        )

    # 4. Verify the SVID directly against the trusted JWKS.
    jws = envelope.metadata.get("spiffe.svid_jws")
    if not jws:
        raise VerificationError("Envelope missing spiffe.svid_jws")
    kid = envelope.metadata.get("spiffe.kid")
    pub_raw = None
    for jwk in trusted_jwks.get("keys", []):
        if kid is None or jwk.get("kid") == kid:
            x = jwk.get("x")
            if isinstance(x, str):
                pub_raw = _b64url_decode(x)
                break
    if pub_raw is None:
        raise VerificationError(
            f"Trust bundle has no JWK matching kid={kid!r} for {parent_td!r}"
        )
    payload = _jws_verify(jws, pub_raw)

    # 5. Bind the SVID's commitment_hash to the envelope's current commitment.
    if payload.get("commitment_hash") != _spiffe_commitment_hash(envelope):
        raise VerificationError(
            "Federated envelope commitment does not match SVID payload"
        )

    return {
        "parent_trust_domain": parent_td,
        "child_trust_domain": expected_trust_domain,
        "federation_edge": {
            "parent": federation_edge.parent_subject,
            "child": federation_edge.child_subject,
            "scopes": list(federation_edge.allowed_scopes),
            "caveats": dict(federation_edge.caveats),
        },
        "svid_kid": kid,
        "svid_payload": payload,
    }


def jwks_only(adapter_jwks: dict[str, Any]) -> dict[str, Any]:
    """Strip any private material from a JWKS before publishing it.

    Our local SPIFFE adapter already only stores public JWKs in metadata, but
    this helper exists so the published-trust-bundle code path is explicit
    and survives future adapters that might mistakenly add private fields.
    """
    keys: list[dict[str, Any]] = []
    for k in adapter_jwks.get("keys", []):
        keys.append({field: k[field] for field in ("kty", "crv", "x", "kid", "alg", "use") if field in k})
    return {"keys": keys}


if __name__ == "__main__":  # pragma: no cover
    print(json.dumps({"trust_bundle_module": "ok"}))
