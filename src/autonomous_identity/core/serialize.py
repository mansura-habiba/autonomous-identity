from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any

from autonomous_identity.core.envelope import (
    Delegation,
    IdentityEnvelope,
    OwnerBinding,
    ProvenanceReference,
    RuntimeInstance,
)


def _json_safe(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    return obj


def envelope_commitment_payload(envelope: IdentityEnvelope) -> dict[str, Any]:
    """Stable dict for hashing/signing (excludes volatile proof fields)."""
    d = asdict(envelope)
    d.pop("signature_chain", None)
    d.pop("audit_ref", None)
    d.pop("verified_at", None)
    return _json_safe(d)


def envelope_commitment_hash(envelope: IdentityEnvelope) -> str:
    from autonomous_identity.core.hashing import hash_canonical

    return hash_canonical(envelope_commitment_payload(envelope))


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    raise TypeError(f"Expected datetime or str, got {type(value)}")


def envelope_to_serializable(envelope: IdentityEnvelope) -> dict[str, Any]:
    """JSON-friendly dict (ISO datetimes) for export / CLI."""
    return _json_safe(asdict(envelope))


def envelope_from_serializable(data: dict[str, Any]) -> IdentityEnvelope:
    """Rebuild envelope from ``envelope_to_serializable`` output."""
    ri = data["runtime_instance"]
    ob = data["owner_binding"]
    prov = data["provenance"]
    delegations: list[Delegation] = []
    for raw in data.get("delegations", []):
        delegations.append(
            Delegation(
                parent_subject=raw["parent_subject"],
                child_subject=raw["child_subject"],
                allowed_scopes=list(raw["allowed_scopes"]),
                caveats=dict(raw.get("caveats", {})),
                expires_at=_parse_dt(raw.get("expires_at")),
            )
        )
    return IdentityEnvelope(
        system_identifier=data["system_identifier"],
        runtime_instance=RuntimeInstance(
            instance_id=ri["instance_id"],
            deployment_id=ri["deployment_id"],
            environment=ri["environment"],
            region=ri["region"],
            attestation_ref=ri.get("attestation_ref"),
            started_at=_parse_dt(ri.get("started_at")),
        ),
        owner_binding=OwnerBinding(
            owner_id=ob["owner_id"],
            owner_type=ob["owner_type"],
            responsibility_scope=ob["responsibility_scope"],
        ),
        attestation_chain=list(data.get("attestation_chain", [])),
        provenance=ProvenanceReference(
            code_hash=prov.get("code_hash"),
            model_hash=prov.get("model_hash"),
            config_hash=prov.get("config_hash"),
            policy_bundle_hash=prov.get("policy_bundle_hash"),
            build_artifact_ref=prov.get("build_artifact_ref"),
            deployment_manifest_hash=prov.get("deployment_manifest_hash"),
            slsa_attestation_ref=prov.get("slsa_attestation_ref"),
            in_toto_statement_ref=prov.get("in_toto_statement_ref"),
        ),
        lifecycle_state=data["lifecycle_state"],
        issued_at=_parse_dt(data["issued_at"]),  # type: ignore[arg-type]
        verified_at=_parse_dt(data.get("verified_at")),
        audit_ref=data.get("audit_ref"),
        signature_chain=list(data.get("signature_chain", [])),
        delegations=delegations,
        metadata=dict(data.get("metadata", {})),
    )
