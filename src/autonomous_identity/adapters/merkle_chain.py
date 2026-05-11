from __future__ import annotations

import uuid
from dataclasses import dataclass, fields, replace
from datetime import datetime, timezone
from typing import Any

from autonomous_identity.core.delegation_util import effective_scopes_for_actor
from autonomous_identity.core.envelope import (
    Delegation,
    IdentityEnvelope,
    OwnerBinding,
    ProvenanceReference,
    RuntimeInstance,
)
from autonomous_identity.core.hashing import hash_canonical
from autonomous_identity.core.serialize import envelope_commitment_hash, envelope_commitment_payload
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.crypto.ed25519 import Ed25519Signer
from autonomous_identity.storage.base import AuditStore


@dataclass
class MerkleIdentityNode:
    node_id: str
    previous_hash: str | None
    subject: str
    action_type: str
    envelope_hash: str
    input_hash: str | None
    output_hash: str | None
    timestamp: str
    signature: str

    def commitment(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "previous_hash": self.previous_hash,
            "subject": self.subject,
            "action_type": self.action_type,
            "envelope_hash": self.envelope_hash,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "timestamp": self.timestamp,
        }

    def node_hash(self) -> str:
        return hash_canonical(self.commitment())


class MerkleChainIdentityAdapter:
    name = "merkle_chain"

    def __init__(self, signer: Ed25519Signer, *, audit_store: AuditStore) -> None:
        self._signer = signer
        self._audit_store = audit_store
        self._tips: dict[str, str | None] = {}

    def issue(self, context: dict[str, Any]) -> IdentityEnvelope:
        now = datetime.now(timezone.utc)
        provenance = ProvenanceReference(**context.get("provenance", {}))
        envelope = IdentityEnvelope(
            system_identifier=context["system_identifier"],
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
                responsibility_scope=context.get("responsibility_scope", "unspecified"),
            ),
            attestation_chain=list(context.get("attestation_chain", [])),
            provenance=provenance,
            lifecycle_state=context.get("lifecycle_state", "active"),
            issued_at=context.get("issued_at", now),
            verified_at=None,
            audit_ref=None,
            signature_chain=[],
            delegations=list(context.get("delegations", [])),
            metadata=_merge_metadata(context),
        )
        env_hash = envelope_commitment_hash(envelope)
        node = MerkleIdentityNode(
            node_id=str(uuid.uuid4()),
            previous_hash=None,
            subject=envelope.system_identifier,
            action_type="issue",
            envelope_hash=env_hash,
            input_hash=None,
            output_hash=None,
            timestamp=now.isoformat(),
            signature="",
        )
        nh = node.node_hash()
        node.signature = self._signer.sign_b64(nh.encode("utf-8"))
        envelope.signature_chain = [node.signature]
        envelope.metadata = {
            **envelope.metadata,
            "merkle_public_key": self._signer.public_bytes().hex(),
            "merkle_tip_node_id": node.node_id,
            "merkle_tip_hash": nh,
        }
        self._tips[envelope.system_identifier] = nh
        ref = self._audit_store.append(
            {
                "kind": "merkle_node",
                "system_identifier": envelope.system_identifier,
                "node": {**node.__dict__, "node_hash": nh},
                "envelope_commitment": envelope_commitment_payload(envelope),
            }
        )
        envelope.audit_ref = ref
        self._tips[envelope.system_identifier] = nh
        return envelope

    def verify(self, envelope: IdentityEnvelope) -> bool:
        pub_hex = envelope.metadata.get("merkle_public_key")
        if not pub_hex or not envelope.signature_chain:
            return False
        pub = bytes.fromhex(pub_hex)
        if not envelope.metadata.get("merkle_tip_node_id"):
            return False
        last_sig = envelope.signature_chain[-1]
        event = self._audit_store.get(envelope.audit_ref or "")
        if not event or event.get("kind") != "merkle_node":
            return self._verify_tip_only(envelope, last_sig, pub)
        node_raw = event["node"]
        node = _node_from_dict(node_raw)
        nh = node.node_hash()
        return self._signer.verify_b64(nh.encode("utf-8"), node.signature, pub)

    def _verify_tip_only(self, envelope: IdentityEnvelope, last_sig: str, pub: bytes) -> bool:
        """When audit_ref missing, verify last signature against tip hash bytes message."""
        tip_hash = envelope.metadata.get("merkle_tip_hash")
        if not tip_hash:
            return False
        return self._signer.verify_b64(str(tip_hash).encode("utf-8"), last_sig, pub)

    def verify_chain_event(self, audit_ref: str) -> None:
        """Verify merkle node in audit store and Ed25519 signature over node_hash."""
        event = self._audit_store.get(audit_ref)
        if not event or event.get("kind") != "merkle_node":
            raise VerificationError("Audit event is not a merkle node")
        node_raw = event["node"]
        node = _node_from_dict(node_raw)
        nh = node.node_hash()
        ec = event.get("envelope_commitment") or {}
        md = ec.get("metadata") or {}
        pub_hex = md.get("merkle_public_key")
        if not pub_hex:
            raise VerificationError("Missing public key in audit event")
        pub = bytes.fromhex(str(pub_hex))
        if not self._signer.verify_b64(nh.encode("utf-8"), node.signature, pub):
            raise VerificationError("Invalid node signature")

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
            raise VerificationError("child_subject must differ from current system_identifier")
        if expires_at is not None and expires_at <= now:
            raise VerificationError("expires_at must be in the future")

        effective = effective_scopes_for_actor(envelope)
        if allowed_scopes:
            if not effective:
                raise VerificationError(
                    "Cannot delegate with non-empty allowed_scopes: parent has no effective "
                    "authorization (for a root actor set context['issuer_scopes'] at issue time; "
                    "for a delegated actor ensure a prior edge granted non-empty allowed_scopes)."
                )
            for s in allowed_scopes:
                if s not in effective:
                    raise VerificationError(
                        f"Scope {s!r} is not allowed (not in parent effective scopes {sorted(effective)})"
                    )

        parent_tip = envelope.metadata.get("merkle_tip_hash")
        if not parent_tip:
            raise VerificationError("Parent envelope has no merkle tip")

        new_del = Delegation(
            parent_subject=envelope.system_identifier,
            child_subject=child_subject,
            allowed_scopes=list(allowed_scopes),
            caveats=dict(caveats),
            expires_at=expires_at,
        )
        # Strip root ``issuer_scopes`` so capability/authorization for this actor comes only
        # from ``Delegation.allowed_scopes`` (identity proof stays on the envelope core).
        child_meta = {**envelope.metadata, "delegated_from": envelope.system_identifier}
        child_meta.pop("issuer_scopes", None)
        child = replace(
            envelope,
            system_identifier=child_subject,
            delegations=[*envelope.delegations, new_del],
            signature_chain=[],
            audit_ref=None,
            verified_at=None,
            issued_at=now,
            metadata=child_meta,
        )
        env_hash = envelope_commitment_hash(child)
        node = MerkleIdentityNode(
            node_id=str(uuid.uuid4()),
            previous_hash=str(parent_tip),
            subject=child_subject,
            action_type="delegate",
            envelope_hash=env_hash,
            input_hash=None,
            output_hash=None,
            timestamp=now.isoformat(),
            signature="",
        )
        nh = node.node_hash()
        node.signature = self._signer.sign_b64(nh.encode("utf-8"))
        pub_hex = envelope.metadata.get("merkle_public_key") or child.metadata.get("merkle_public_key")
        if not pub_hex:
            raise VerificationError("Missing merkle_public_key on parent envelope")
        child.signature_chain = [node.signature]
        child.metadata = {
            **child.metadata,
            "merkle_public_key": pub_hex,
            "merkle_tip_node_id": node.node_id,
            "merkle_tip_hash": nh,
        }
        self._tips[child_subject] = nh
        ref = self._audit_store.append(
            {
                "kind": "merkle_node",
                "system_identifier": child_subject,
                "node": {**node.__dict__, "node_hash": nh},
                "delegation": {
                    "parent_subject": new_del.parent_subject,
                    "child_subject": new_del.child_subject,
                    "allowed_scopes": new_del.allowed_scopes,
                    "caveats": new_del.caveats,
                    "expires_at": new_del.expires_at.isoformat() if new_del.expires_at else None,
                },
                "envelope_commitment": envelope_commitment_payload(child),
            }
        )
        child.audit_ref = ref
        return child

    def revoke(self, system_identifier: str, reason: str) -> None:
        return None

    def audit(self, envelope: IdentityEnvelope, action: dict[str, Any]) -> str:
        now = datetime.now(timezone.utc)
        env_hash = envelope_commitment_hash(envelope)
        prev = self._tips.get(envelope.system_identifier)
        node = MerkleIdentityNode(
            node_id=str(uuid.uuid4()),
            previous_hash=prev,
            subject=envelope.system_identifier,
            action_type=str(action.get("action_type", "material_action")),
            envelope_hash=env_hash,
            input_hash=action.get("input_hash"),
            output_hash=action.get("output_hash"),
            timestamp=now.isoformat(),
            signature="",
        )
        nh = node.node_hash()
        node.signature = self._signer.sign_b64(nh.encode("utf-8"))
        envelope.signature_chain = [*envelope.signature_chain, node.signature]
        envelope.metadata = {
            **envelope.metadata,
            "merkle_tip_node_id": node.node_id,
            "merkle_tip_hash": nh,
        }
        ref = self._audit_store.append(
            {
                "kind": "merkle_node",
                "system_identifier": envelope.system_identifier,
                "node": {**node.__dict__, "node_hash": nh},
                "action": action,
                "envelope_commitment": envelope_commitment_payload(envelope),
            }
        )
        envelope.audit_ref = ref
        envelope.verified_at = now
        self._tips[envelope.system_identifier] = nh
        return ref


def _node_from_dict(node_raw: dict[str, Any]) -> MerkleIdentityNode:
    allowed = {f.name for f in fields(MerkleIdentityNode)}
    return MerkleIdentityNode(**{k: v for k, v in node_raw.items() if k in allowed})


def _merge_metadata(context: dict[str, Any]) -> dict[str, Any]:
    meta = dict(context.get("metadata", {}))
    if "issuer_scopes" in context:
        meta["issuer_scopes"] = list(context["issuer_scopes"])
    return meta
