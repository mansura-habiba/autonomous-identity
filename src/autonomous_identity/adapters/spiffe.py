"""SPIFFE-compatible identity adapter.

What this adapter is
--------------------
A local, self-contained adapter that mints **JWT-SVID-shaped** identity
envelopes for autonomous systems whose ``system_identifier`` is a valid
SPIFFE ID (``spiffe://<trust_domain>/<path>``). It signs with the repo's
existing Ed25519 signer, exposes the public key as a JWK / JWKS in
envelope metadata, and enforces trust-domain scoping on every delegation.

What this adapter is **not** (yet)
----------------------------------
It is **not** a SPIRE Workload API client. There is no socket talk, no
SVID rotation poll, no upstream SPIFFE CA path. The metadata field
``spiffe.workload_api_socket`` is reserved so a future ``spire`` adapter
can plug in without breaking envelopes issued by this one.

Why this shape
--------------
SPIFFE's value to autonomous-system identity is three things:

1. A standardized, addressable, URI-shaped system identifier per workload.
2. Trust-domain boundaries that govern federation.
3. Cryptographically verifiable identity material (JWT-SVID / X509-SVID).

This adapter delivers all three locally so flows, tests, and the Langflow
demo can exercise the SPIFFE wire format and trust-domain rules without
operating a SPIRE deployment.

Envelope shape
--------------
Every envelope this adapter produces carries the following metadata keys:

- ``spiffe.id`` — the canonical SPIFFE ID, equal to ``system_identifier``.
- ``spiffe.trust_domain`` — parsed trust-domain string.
- ``spiffe.svid_jws`` — JWT-SVID compact JWS over the envelope commitment
  hash plus standard claims (``sub`` = SPIFFE ID, ``aud``, ``iat``, ``exp``,
  ``jti``).
- ``spiffe.jwks`` — JSON Web Key Set with the signer's public key. Verifiers
  use this to validate ``svid_jws`` without holding the signer.
- ``spiffe.kid`` — key ID (sha256 truncation of the raw public key).

When delegation crosses trust domains, the new delegation row's caveats
carry ``"spiffe.federation": True`` and the parent / child trust domains so
the audit trail makes federation explicit.
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any

from autonomous_identity.core.delegation_util import effective_scopes_for_actor
from autonomous_identity.core.envelope import (
    Delegation,
    IdentityEnvelope,
    OwnerBinding,
    ProvenanceReference,
    RuntimeInstance,
)
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.core.hashing import hash_canonical
from autonomous_identity.core.serialize import (
    envelope_commitment_hash,
    envelope_commitment_payload,
)


# Metadata keys carrying SVID material itself. They must be excluded from the
# envelope commitment that the SVID binds to, otherwise the SVID hash binds
# to a payload that the SVID is then written into — a circular dependency
# that would make every envelope fail verify() right after issue().
_SVID_METADATA_KEYS = (
    "spiffe.svid_jws",
    "spiffe.svid_iat",
    "spiffe.svid_exp",
    "spiffe.svid_jti",
)


def _spiffe_commitment_payload(envelope: IdentityEnvelope) -> dict[str, Any]:
    """Envelope commitment with SVID material stripped from metadata.

    Mirrors :func:`envelope_commitment_payload` but additionally removes the
    fields that are themselves derived from the commitment. The result is the
    canonical payload the SVID's ``commitment_hash`` claim binds to.
    """
    payload = envelope_commitment_payload(envelope)
    meta = dict(payload.get("metadata") or {})
    for key in _SVID_METADATA_KEYS:
        meta.pop(key, None)
    payload["metadata"] = meta
    return payload


def _spiffe_commitment_hash(envelope: IdentityEnvelope) -> str:
    return hash_canonical(_spiffe_commitment_payload(envelope))
from autonomous_identity.crypto.ed25519 import Ed25519Signer
from autonomous_identity.storage.base import AuditStore

# ----- SPIFFE ID parsing / validation ---------------------------------------

# Per the SPIFFE specification:
#   trust domain: 1..255 chars, lowercase letters, digits, '.', '-', '_'
#   path:         optional; segments separated by '/'; each segment uses
#                 RFC 3986 unreserved + sub-delims subset (we restrict to
#                 [A-Za-z0-9._:-]+ which is the safe intersection used by
#                 SPIRE in practice).
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9._-]{1,255}$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._:\-]+$")


def parse_spiffe_id(spiffe_id: str) -> tuple[str, str]:
    """Return ``(trust_domain, path)``; raise :class:`VerificationError` if malformed.

    ``path`` is the portion after the trust domain INCLUDING the leading slash,
    or ``""`` if the SPIFFE ID has no path. Examples::

        spiffe://example.org              -> ("example.org", "")
        spiffe://example.org/workload/abc -> ("example.org", "/workload/abc")
    """
    if not isinstance(spiffe_id, str) or not spiffe_id.startswith("spiffe://"):
        raise VerificationError(f"Not a SPIFFE ID: {spiffe_id!r}")
    rest = spiffe_id[len("spiffe://"):]
    if "?" in rest or "#" in rest or "@" in rest:
        raise VerificationError("SPIFFE ID may not contain '?', '#', or '@'")
    if "/" in rest:
        trust_domain, path = rest.split("/", 1)
        path = "/" + path
    else:
        trust_domain, path = rest, ""
    if not _TRUST_DOMAIN_RE.match(trust_domain):
        raise VerificationError(f"Invalid SPIFFE trust domain: {trust_domain!r}")
    if path:
        segments = path[1:].split("/")
        for seg in segments:
            if not _PATH_SEGMENT_RE.match(seg):
                raise VerificationError(f"Invalid SPIFFE path segment: {seg!r}")
    return trust_domain, path


def is_spiffe_id(spiffe_id: str) -> bool:
    try:
        parse_spiffe_id(spiffe_id)
        return True
    except VerificationError:
        return False


def build_spiffe_id(trust_domain: str, path: str | None = None) -> str:
    if not _TRUST_DOMAIN_RE.match(trust_domain):
        raise VerificationError(f"Invalid trust domain: {trust_domain!r}")
    if not path:
        return f"spiffe://{trust_domain}"
    if not path.startswith("/"):
        path = "/" + path
    sid = f"spiffe://{trust_domain}{path}"
    parse_spiffe_id(sid)  # validate path
    return sid


# ----- minimal JWS Compact Serialization (no extra deps) ---------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _jws_sign(signer: Ed25519Signer, header: dict[str, Any], payload: dict[str, Any]) -> str:
    header_b64 = _b64url_encode(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = signer.sign(signing_input)
    sig_b64 = _b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _jws_verify(jws_compact: str, public_key_raw: bytes) -> dict[str, Any]:
    """Return the parsed payload if the signature is valid; raise otherwise."""
    parts = jws_compact.split(".")
    if len(parts) != 3:
        raise VerificationError("Malformed JWS (expected 3 dot-separated parts)")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as exc:
        raise VerificationError(f"Malformed JWS header/payload: {exc}") from exc
    if header.get("alg") != "EdDSA":
        raise VerificationError(
            f"JWS alg must be 'EdDSA', got {header.get('alg')!r}"
        )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = _b64url_decode(sig_b64)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pub = Ed25519PublicKey.from_public_bytes(public_key_raw)
    try:
        pub.verify(sig, signing_input)
    except Exception as exc:
        raise VerificationError(f"JWS signature verification failed: {exc}") from exc
    return payload


def _public_key_to_jwk(public_key_raw: bytes) -> dict[str, str]:
    """Encode an Ed25519 raw public key as a JWK per RFC 8037 (OKP / Ed25519)."""
    kid = sha256(public_key_raw).hexdigest()[:16]
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url_encode(public_key_raw),
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
    }


def _jwks_lookup(jwks: dict[str, Any], kid: str | None) -> bytes:
    """Locate the JWK with this kid in a JWKS and return its raw public-key bytes."""
    if not isinstance(jwks, dict) or "keys" not in jwks:
        raise VerificationError("Envelope has no SPIFFE JWKS in metadata")
    for jwk in jwks.get("keys", []):
        if not isinstance(jwk, dict):
            continue
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            continue
        if kid is None or jwk.get("kid") == kid:
            x = jwk.get("x")
            if not isinstance(x, str):
                raise VerificationError("JWK missing 'x' component")
            return _b64url_decode(x)
    raise VerificationError(f"No matching JWK in JWKS for kid={kid!r}")


# ----- the adapter -----------------------------------------------------------


class SpiffeIdentityAdapter:
    """JWT-SVID-shaped identity adapter; local trust root via Ed25519 signer."""

    name = "spiffe"

    DEFAULT_SVID_TTL = timedelta(hours=24)
    DEFAULT_AUDIENCE = "spiffe://local"  # overridden via context["spiffe_audience"]

    def __init__(
        self,
        signer: Ed25519Signer,
        *,
        audit_store: AuditStore,
        svid_ttl: timedelta | None = None,
        default_audience: str | None = None,
    ) -> None:
        self._signer = signer
        self._audit_store = audit_store
        # ``timedelta(seconds=0)`` is falsy, so use explicit None checks to
        # let tests force an already-expired SVID.
        self._svid_ttl = svid_ttl if svid_ttl is not None else self.DEFAULT_SVID_TTL
        self._default_audience = (
            default_audience if default_audience is not None else self.DEFAULT_AUDIENCE
        )
        self._public_raw = signer.public_bytes()
        self._jwk = _public_key_to_jwk(self._public_raw)
        self._jwks = {"keys": [self._jwk]}

    # ----- issuance ---------------------------------------------------------

    def issue(self, context: dict[str, Any]) -> IdentityEnvelope:
        now = datetime.now(timezone.utc)
        system_id = _resolve_system_id_from_context(context)
        trust_domain, _ = parse_spiffe_id(system_id)

        provenance = ProvenanceReference(**context.get("provenance", {}))
        envelope = IdentityEnvelope(
            system_identifier=system_id,
            runtime_instance=RuntimeInstance(
                instance_id=context["instance_id"],
                deployment_id=context["deployment_id"],
                environment=context.get("environment", "dev"),
                region=context.get("region", "local"),
                attestation_ref=context.get("attestation_ref"),
                started_at=context.get("started_at"),
            ),
            owner_binding=OwnerBinding(
                owner_id=context["owner_id"],
                owner_type=context.get("owner_type", "team"),
                responsibility_scope=context.get(
                    "responsibility_scope", "unspecified"
                ),
            ),
            attestation_chain=list(context.get("attestation_chain", [])),
            provenance=provenance,
            lifecycle_state=context.get("lifecycle_state", "active"),
            issued_at=context.get("issued_at", now),
            verified_at=None,
            audit_ref=None,
            signature_chain=[],
            delegations=list(context.get("delegations", [])),
            metadata=_merge_metadata(context, trust_domain, self._jwk, self._jwks),
        )

        # Mint the JWT-SVID over the envelope commitment hash.
        svid_jws, svid_payload = self._mint_svid(
            envelope,
            now=now,
            audience=context.get("spiffe_audience", self._default_audience),
        )
        envelope.metadata["spiffe.svid_jws"] = svid_jws
        envelope.metadata["spiffe.svid_iat"] = svid_payload["iat"]
        envelope.metadata["spiffe.svid_exp"] = svid_payload["exp"]
        envelope.metadata["spiffe.svid_jti"] = svid_payload["jti"]
        envelope.signature_chain = [svid_jws]

        ref = self._audit_store.append(
            {
                "kind": "spiffe_issue",
                "system_identifier": envelope.system_identifier,
                "trust_domain": trust_domain,
                "svid_jws": svid_jws,
                "svid_payload": svid_payload,
                "jwk": self._jwk,
                "envelope_commitment": envelope_commitment_payload(envelope),
                "spiffe_commitment": _spiffe_commitment_payload(envelope),
            }
        )
        envelope.audit_ref = ref
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
        now = datetime.now(timezone.utc)
        if child_subject == envelope.system_identifier:
            raise VerificationError(
                "child_subject must differ from current system_identifier"
            )
        if not allowed_scopes:
            raise VerificationError("allowed_scopes must be non-empty")
        if expires_at is not None and expires_at <= now:
            raise VerificationError("expires_at must be in the future")

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

        effective = effective_scopes_for_actor(envelope)
        if not effective:
            raise VerificationError(
                "Cannot delegate: set metadata['issuer_scopes'] on the root envelope, "
                "or delegate from an envelope that already has a narrower grant"
            )
        for s in allowed_scopes:
            if s not in effective:
                raise VerificationError(
                    f"Scope {s!r} is not allowed (not in parent effective scopes "
                    f"{sorted(effective)})"
                )

        delegation_caveats = dict(caveats)
        if cross_td:
            delegation_caveats["spiffe.federation"] = True
            delegation_caveats["spiffe.parent_trust_domain"] = parent_td
            delegation_caveats["spiffe.child_trust_domain"] = child_td

        new_del = Delegation(
            parent_subject=envelope.system_identifier,
            child_subject=child_subject,
            allowed_scopes=list(allowed_scopes),
            caveats=delegation_caveats,
            expires_at=expires_at,
        )

        child = replace(
            envelope,
            system_identifier=child_subject,
            delegations=[*envelope.delegations, new_del],
            signature_chain=[],
            audit_ref=None,
            verified_at=None,
            issued_at=now,
            metadata={
                **envelope.metadata,
                "spiffe.id": child_subject,
                "spiffe.trust_domain": child_td,
                "spiffe.kid": self._jwk["kid"],
                "spiffe.jwks": self._jwks,
                "delegated_from": envelope.system_identifier,
            },
        )

        svid_jws, svid_payload = self._mint_svid(
            child,
            now=now,
            audience=envelope.metadata.get("spiffe.audience", self._default_audience),
        )
        child.metadata["spiffe.svid_jws"] = svid_jws
        child.metadata["spiffe.svid_iat"] = svid_payload["iat"]
        child.metadata["spiffe.svid_exp"] = svid_payload["exp"]
        child.metadata["spiffe.svid_jti"] = svid_payload["jti"]
        child.signature_chain = [svid_jws]

        ref = self._audit_store.append(
            {
                "kind": "spiffe_delegate",
                "system_identifier": child_subject,
                "parent_subject": envelope.system_identifier,
                "parent_trust_domain": parent_td,
                "child_trust_domain": child_td,
                "federation": cross_td,
                "svid_jws": svid_jws,
                "svid_payload": svid_payload,
                "delegation": {
                    "parent_subject": new_del.parent_subject,
                    "child_subject": new_del.child_subject,
                    "allowed_scopes": new_del.allowed_scopes,
                    "caveats": new_del.caveats,
                    "expires_at": (
                        new_del.expires_at.isoformat() if new_del.expires_at else None
                    ),
                },
                "envelope_commitment": envelope_commitment_payload(child),
            }
        )
        child.audit_ref = ref
        return child

    # ----- verification -----------------------------------------------------

    def verify(self, envelope: IdentityEnvelope) -> bool:
        try:
            self._verify_or_raise(envelope)
        except VerificationError:
            return False
        return True

    def verify_chain_event(self, audit_ref: str) -> None:
        event = self._audit_store.get(audit_ref)
        if not event or event.get("kind") not in ("spiffe_issue", "spiffe_delegate"):
            raise VerificationError("Audit event is not a SPIFFE envelope event")
        jwk = event.get("jwk")
        jws = event.get("svid_jws")
        if jwk is None:
            commitment = event.get("envelope_commitment") or {}
            metadata = commitment.get("metadata") or {}
            jwks = metadata.get("spiffe.jwks")
            if not jwks:
                raise VerificationError("Audit event missing JWK / JWKS")
            jwk = (jwks.get("keys") or [None])[0]
        if not jws or not jwk:
            raise VerificationError("Audit event missing SVID material")
        pub_raw = _b64url_decode(jwk["x"])
        payload = _jws_verify(jws, pub_raw)
        # SVID's commitment_hash binds to the SPIFFE-strict commitment that
        # excludes SVID material from the metadata. Compare against the row's
        # spiffe_commitment (falling back to envelope_commitment for older
        # rows that did not record the strict view separately).
        strict_payload = event.get("spiffe_commitment") or event.get(
            "envelope_commitment"
        )
        if strict_payload is None:
            raise VerificationError("Audit event missing envelope commitment")
        # Strip SVID metadata before hashing — handles old rows that only
        # captured envelope_commitment.
        metadata = dict(strict_payload.get("metadata") or {})
        for k in _SVID_METADATA_KEYS:
            metadata.pop(k, None)
        strict_payload = {**strict_payload, "metadata": metadata}
        expected = hash_canonical(strict_payload)
        if payload.get("commitment_hash") != expected:
            raise VerificationError(
                "Audit event commitment hash does not match SVID payload"
            )

    # ----- revocation / audit ----------------------------------------------

    def revoke(self, system_identifier: str, reason: str) -> None:
        # Adapter-side revocation is a no-op; the facade flips the lifecycle
        # state in the lifecycle store and the validator picks it up at
        # ensure_active_or_raise() time. This mirrors the merkle_chain adapter.
        return None

    def audit(self, envelope: IdentityEnvelope, action: dict[str, Any]) -> str:
        now = datetime.now(timezone.utc)
        env_hash = envelope_commitment_hash(envelope)

        # Sign the action row with a compact JWS over a deterministic payload
        # so each material action is independently verifiable.
        action_payload = {
            "sub": envelope.system_identifier,
            "iat": int(now.timestamp()),
            "jti": str(uuid.uuid4()),
            "action_type": str(action.get("action_type", "material_action")),
            "required_scope": action.get("required_scope"),
            "input_hash": action.get("input_hash"),
            "output_hash": action.get("output_hash"),
            "envelope_commitment_hash": env_hash,
            "svid_jti": envelope.metadata.get("spiffe.svid_jti"),
        }
        header = {"alg": "EdDSA", "typ": "JOSE+JSON", "kid": self._jwk["kid"]}
        action_jws = _jws_sign(self._signer, header, action_payload)
        envelope.signature_chain = [*envelope.signature_chain, action_jws]
        envelope.verified_at = now
        ref = self._audit_store.append(
            {
                "kind": "spiffe_action",
                "system_identifier": envelope.system_identifier,
                "action": action,
                "action_jws": action_jws,
                "action_payload": action_payload,
                "jwk": self._jwk,
                "envelope_commitment": envelope_commitment_payload(envelope),
                "spiffe_commitment": _spiffe_commitment_payload(envelope),
            }
        )
        envelope.audit_ref = ref
        return ref

    # ----- internals --------------------------------------------------------

    def _mint_svid(
        self,
        envelope: IdentityEnvelope,
        *,
        now: datetime,
        audience: str,
    ) -> tuple[str, dict[str, Any]]:
        env_hash = _spiffe_commitment_hash(envelope)
        payload: dict[str, Any] = {
            "sub": envelope.system_identifier,
            "aud": audience,
            "iat": int(now.timestamp()),
            "exp": int((now + self._svid_ttl).timestamp()),
            "jti": str(uuid.uuid4()),
            "commitment_hash": env_hash,
        }
        header = {"alg": "EdDSA", "typ": "JWT", "kid": self._jwk["kid"]}
        jws = _jws_sign(self._signer, header, payload)
        return jws, payload

    def _verify_or_raise(self, envelope: IdentityEnvelope) -> None:
        jws = envelope.metadata.get("spiffe.svid_jws")
        jwks = envelope.metadata.get("spiffe.jwks")
        kid = envelope.metadata.get("spiffe.kid")
        if not jws or not jwks:
            raise VerificationError("Envelope is missing SPIFFE SVID material")

        pub_raw = _jwks_lookup(jwks, kid)
        payload = _jws_verify(jws, pub_raw)

        if payload.get("sub") != envelope.system_identifier:
            raise VerificationError(
                f"SVID subject {payload.get('sub')!r} does not match "
                f"system_identifier {envelope.system_identifier!r}"
            )

        # Confirm the SVID was minted for this envelope's current commitment.
        # Use the SPIFFE-specific commitment that excludes the SVID material
        # itself so the hash is stable across the (mint → write back into
        # metadata → verify) round-trip.
        expected_commitment = _spiffe_commitment_hash(envelope)
        if payload.get("commitment_hash") != expected_commitment:
            raise VerificationError(
                "SVID commitment hash does not match envelope commitment"
            )

        # SVID expiry.
        now = datetime.now(timezone.utc)
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and exp <= int(now.timestamp()):
            raise VerificationError("SVID has expired")


# ----- helpers ---------------------------------------------------------------


def _resolve_system_id_from_context(context: dict[str, Any]) -> str:
    sid = context.get("system_identifier")
    if isinstance(sid, str) and sid:
        parse_spiffe_id(sid)
        return sid
    trust_domain = context.get("spiffe_trust_domain")
    if not trust_domain:
        raise VerificationError(
            "SPIFFE adapter requires either a 'system_identifier' shaped "
            "spiffe://<trust_domain>/<path> or 'spiffe_trust_domain' (+ optional "
            "'spiffe_path') in the issue context"
        )
    return build_spiffe_id(trust_domain, context.get("spiffe_path"))


def _merge_metadata(
    context: dict[str, Any],
    trust_domain: str,
    jwk: dict[str, str],
    jwks: dict[str, Any],
) -> dict[str, Any]:
    meta: dict[str, Any] = dict(context.get("metadata", {}))
    if "issuer_scopes" in context:
        meta["issuer_scopes"] = list(context["issuer_scopes"])
    meta["spiffe.id"] = context.get("system_identifier") or build_spiffe_id(
        trust_domain, context.get("spiffe_path")
    )
    meta["spiffe.trust_domain"] = trust_domain
    meta["spiffe.kid"] = jwk["kid"]
    meta["spiffe.jwks"] = jwks
    if "spiffe_audience" in context:
        meta["spiffe.audience"] = context["spiffe_audience"]
    if "spire_workload_api_socket" in context:
        # Reserved for the future SPIRE adapter; pure local adapter ignores it
        # but carries it forward so a workload-API verifier could pick it up.
        meta["spiffe.workload_api_socket"] = context["spire_workload_api_socket"]
    return meta
