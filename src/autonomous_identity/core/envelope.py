from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

LifecycleState = Literal["active", "restricted", "suspended", "revoked", "retired"]


@dataclass
class OwnerBinding:
    owner_id: str
    owner_type: str
    responsibility_scope: str


@dataclass
class RuntimeInstance:
    instance_id: str
    deployment_id: str
    environment: str
    region: str
    attestation_ref: str | None = None
    started_at: datetime | None = None


@dataclass
class ProvenanceReference:
    code_hash: str | None = None
    model_hash: str | None = None
    config_hash: str | None = None
    policy_bundle_hash: str | None = None
    build_artifact_ref: str | None = None
    deployment_manifest_hash: str | None = None
    slsa_attestation_ref: str | None = None
    in_toto_statement_ref: str | None = None


@dataclass
class Delegation:
    """Handoff edge. ``allowed_scopes`` may be empty for identity-only delegation (no auth strings)."""

    parent_subject: str
    child_subject: str
    allowed_scopes: list[str]
    caveats: dict[str, Any] = field(default_factory=dict)
    expires_at: datetime | None = None


@dataclass
class IdentityEnvelope:
    system_identifier: str
    runtime_instance: RuntimeInstance
    owner_binding: OwnerBinding
    attestation_chain: list[str]
    provenance: ProvenanceReference
    lifecycle_state: LifecycleState
    issued_at: datetime
    verified_at: datetime | None
    audit_ref: str | None
    signature_chain: list[str]
    delegations: list[Delegation] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
