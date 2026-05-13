"""Merkle DAG identity adapter — multi-parent attestation for graph-shaped flows.

The chain adapter (:mod:`autonomous_identity.adapters.merkle_chain`) forces
every node to commit to exactly one parent. That topology is fine for
issue → delegate → action flows that look like a sequence. It is
**wrong** for the case the design notes call out: a material action that
is co-asserted by an actor, a policy engine, a retrieval gate, and a
runtime attestor at the same moment. Flattening that co-assertion into a
sequence loses the real dependency graph.

This adapter generalises the chain along one axis: each node commits to
**multiple** parents rather than one. The envelope shape is unchanged,
the Ed25519 signing is unchanged, the audit-store contract is unchanged.
Only the node's parent set is a list now.

API shape
=========

For ``issue`` and ``delegate``, multi-parent topology is meaningless (you
cannot co-issue the same envelope), so those work identically to the
chain adapter: zero parents for genesis, one parent for delegation.

For ``audit``, this adapter accepts an optional ``witnesses`` keyword:

    proof = adapter.audit(
        envelope,
        {"action_type": "doc.compose", "input_hash": "...", "output_hash": "..."},
        witnesses=[orchestrator_env, policy_env, retrieval_env],
    )

Each witness contributes its **current tip hash** to the new node's
``previous_hashes`` list, in addition to the actor's own tip. The audit
row that lands carries the full parent set, so a verifier looking at the
row knows which principals were at which point in their own chains at
the moment this action was attested.

The receiver-side checks are unchanged: a tampered ancestor breaks every
descendant's hash, exactly as in the chain. The graph just preserves the
real dependency structure instead of forcing it into a sequence.
"""

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
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.core.hashing import hash_canonical
from autonomous_identity.core.serialize import (
    envelope_commitment_hash,
    envelope_commitment_payload,
)
from autonomous_identity.crypto.ed25519 import Ed25519Signer
from autonomous_identity.storage.base import AuditStore


@dataclass
class MerkleDagNode:
    """A node in the identity DAG. Commits to zero or more parent hashes."""

    node_id: str
    previous_hashes: list[str]
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
            # Sorted to keep the commitment hash stable independent of the
            # witness ordering at the call site. A node with parents [A, B]
            # must hash identically to a node with parents [B, A] — the set
            # is what matters, not the order.
            "previous_hashes": sorted(self.previous_hashes),
            "subject": self.subject,
            "action_type": self.action_type,
            "envelope_hash": self.envelope_hash,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "timestamp": self.timestamp,
        }

    def node_hash(self) -> str:
        return hash_canonical(self.commitment())


class MerkleDagIdentityAdapter:
    """Multi-parent generalisation of the Merkle chain adapter."""

    name = "merkle_dag"

    def __init__(self, signer: Ed25519Signer, *, audit_store: AuditStore) -> None:
        self._signer = signer
        self._audit_store = audit_store
        # subject -> current tip hash (the most recent node for that subject).
        # Witnesses are read from this map.
        self._tips: dict[str, str | None] = {}

    # ----- issue ------------------------------------------------------------

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
        node = MerkleDagNode(
            node_id=str(uuid.uuid4()),
            previous_hashes=[],            # genesis
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
            "dag_public_key": self._signer.public_bytes().hex(),
            "dag_tip_node_id": node.node_id,
            "dag_tip_hash": nh,
        }
        self._tips[envelope.system_identifier] = nh
        ref = self._audit_store.append(
            {
                "kind": "dag_node",
                "system_identifier": envelope.system_identifier,
                "node": {**node.__dict__, "node_hash": nh},
                "envelope_commitment": envelope_commitment_payload(envelope),
            }
        )
        envelope.audit_ref = ref
        return envelope

    # ----- delegate ---------------------------------------------------------

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
        if not allowed_scopes:
            raise VerificationError("allowed_scopes must be non-empty")
        if expires_at is not None and expires_at <= now:
            raise VerificationError("expires_at must be in the future")

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

        parent_tip = envelope.metadata.get("dag_tip_hash")
        if not parent_tip:
            raise VerificationError("Parent envelope has no dag tip")

        new_del = Delegation(
            parent_subject=envelope.system_identifier,
            child_subject=child_subject,
            allowed_scopes=list(allowed_scopes),
            caveats=dict(caveats),
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
                "delegated_from": envelope.system_identifier,
            },
        )
        env_hash = envelope_commitment_hash(child)
        node = MerkleDagNode(
            node_id=str(uuid.uuid4()),
            previous_hashes=[str(parent_tip)],
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
        pub_hex = (
            envelope.metadata.get("dag_public_key")
            or child.metadata.get("dag_public_key")
        )
        if not pub_hex:
            raise VerificationError("Missing dag_public_key on parent envelope")
        child.signature_chain = [node.signature]
        child.metadata = {
            **child.metadata,
            "dag_public_key": pub_hex,
            "dag_tip_node_id": node.node_id,
            "dag_tip_hash": nh,
        }
        self._tips[child_subject] = nh
        ref = self._audit_store.append(
            {
                "kind": "dag_node",
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

    # ----- audit (the DAG-specific behaviour) -------------------------------

    def audit(
        self,
        envelope: IdentityEnvelope,
        action: dict[str, Any],
        *,
        witnesses: list[IdentityEnvelope] | None = None,
    ) -> str:
        """Record a signed action node, optionally co-asserted by other principals.

        ``witnesses`` is a list of :class:`IdentityEnvelope` objects whose
        current tip hashes will be added to this node's ``previous_hashes``
        set, alongside the actor's own tip. The audit row that lands
        captures the multi-parent dependency graph; tampering with any
        ancestor (actor or witness) breaks the descendant's hash.

        When ``witnesses`` is omitted or empty, this adapter behaves
        identically to :class:`MerkleChainIdentityAdapter` — a single-parent
        chain. That is the right default for actions taken without
        co-assertion.
        """
        now = datetime.now(timezone.utc)
        env_hash = envelope_commitment_hash(envelope)
        parents: list[str] = []
        actor_prev = self._tips.get(envelope.system_identifier)
        if actor_prev:
            parents.append(actor_prev)

        if witnesses:
            seen: set[str] = set(parents)
            for w in witnesses:
                w_tip = (w.metadata or {}).get("dag_tip_hash") or self._tips.get(
                    w.system_identifier
                )
                if not w_tip:
                    raise VerificationError(
                        f"Witness {w.system_identifier!r} has no DAG tip; only "
                        "envelopes issued by this adapter can witness an action"
                    )
                if w.system_identifier == envelope.system_identifier:
                    continue  # self-witness is meaningless
                if w_tip in seen:
                    continue  # de-duplicate
                seen.add(w_tip)
                parents.append(w_tip)

        node = MerkleDagNode(
            node_id=str(uuid.uuid4()),
            previous_hashes=parents,
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
            "dag_tip_node_id": node.node_id,
            "dag_tip_hash": nh,
        }
        ref = self._audit_store.append(
            {
                "kind": "dag_node",
                "system_identifier": envelope.system_identifier,
                "node": {**node.__dict__, "node_hash": nh},
                "action": action,
                "witness_subjects": [w.system_identifier for w in (witnesses or [])],
                "envelope_commitment": envelope_commitment_payload(envelope),
            }
        )
        envelope.audit_ref = ref
        envelope.verified_at = now
        self._tips[envelope.system_identifier] = nh
        return ref

    # ----- revoke (no-op, matches chain) ------------------------------------

    def revoke(self, system_identifier: str, reason: str) -> None:
        return None

    # ----- verification -----------------------------------------------------

    def verify(self, envelope: IdentityEnvelope) -> bool:
        pub_hex = envelope.metadata.get("dag_public_key")
        if not pub_hex or not envelope.signature_chain:
            return False
        pub = bytes.fromhex(pub_hex)
        if not envelope.metadata.get("dag_tip_node_id"):
            return False
        last_sig = envelope.signature_chain[-1]
        event = self._audit_store.get(envelope.audit_ref or "")
        if not event or event.get("kind") != "dag_node":
            tip_hash = envelope.metadata.get("dag_tip_hash")
            if not tip_hash:
                return False
            return self._signer.verify_b64(
                str(tip_hash).encode("utf-8"), last_sig, pub
            )
        node_raw = event["node"]
        node = _node_from_dict(node_raw)
        nh = node.node_hash()
        return self._signer.verify_b64(nh.encode("utf-8"), node.signature, pub)

    def verify_chain_event(self, audit_ref: str) -> None:
        """Verify the node referenced by audit_ref and its signature.

        Multi-parent verification is structural — the node's hash includes
        the sorted parent set, so tampering with any parent breaks this
        node's hash. The verifier can recursively walk parents via the
        audit store if it wants to validate the full DAG; this method
        only checks the single node.
        """
        event = self._audit_store.get(audit_ref)
        if not event or event.get("kind") != "dag_node":
            raise VerificationError("Audit event is not a DAG node")
        node_raw = event["node"]
        node = _node_from_dict(node_raw)
        nh = node.node_hash()
        ec = event.get("envelope_commitment") or {}
        md = ec.get("metadata") or {}
        pub_hex = md.get("dag_public_key")
        if not pub_hex:
            raise VerificationError("Missing public key in audit event")
        pub = bytes.fromhex(str(pub_hex))
        if not self._signer.verify_b64(nh.encode("utf-8"), node.signature, pub):
            raise VerificationError("Invalid node signature")


def _node_from_dict(node_raw: dict[str, Any]) -> MerkleDagNode:
    allowed = {f.name for f in fields(MerkleDagNode)}
    # Audit rows from older versions may carry `previous_hash` (singular);
    # tolerate that and migrate to the new list shape on read.
    if "previous_hashes" not in node_raw and "previous_hash" in node_raw:
        ph = node_raw.get("previous_hash")
        node_raw = {**node_raw, "previous_hashes": [ph] if ph else []}
    return MerkleDagNode(**{k: v for k, v in node_raw.items() if k in allowed})


def _merge_metadata(context: dict[str, Any]) -> dict[str, Any]:
    meta = dict(context.get("metadata", {}))
    if "issuer_scopes" in context:
        meta["issuer_scopes"] = list(context["issuer_scopes"])
    return meta
