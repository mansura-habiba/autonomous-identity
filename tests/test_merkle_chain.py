from datetime import datetime, timezone

import pytest

from autonomous_identity.adapters.merkle_chain import MerkleChainIdentityAdapter
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.crypto.ed25519 import Ed25519Signer
from autonomous_identity.storage.memory import MemoryAuditStore, MemoryLifecycleStore


def test_merkle_issue_verify_and_audit() -> None:
    signer = Ed25519Signer.generate()
    audit = MemoryAuditStore()
    adapter = MerkleChainIdentityAdapter(signer, audit_store=audit)
    env = adapter.issue(
        {
            "system_identifier": "agent://t/a",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "o1",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local:x"],
        }
    )
    assert adapter.verify(env)
    ref = adapter.audit(
        env,
        {"action_type": "tool", "input_hash": "in", "output_hash": "out"},
    )
    assert ref.startswith("audit://")
    assert adapter.verify(env)


def test_verify_chain_event_tamper(tmp_path) -> None:
    signer = Ed25519Signer.generate()
    from autonomous_identity.storage.file import FileAuditStore

    audit = FileAuditStore(tmp_path / "audit.jsonl")
    adapter = MerkleChainIdentityAdapter(signer, audit_store=audit)
    env = adapter.issue(
        {
            "system_identifier": "agent://t/b",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "o1",
            "provenance": {"code_hash": "sha256:a", "policy_bundle_hash": "sha256:b"},
            "attestation_chain": ["local:x"],
        }
    )
    ref = env.audit_ref
    adapter.verify_chain_event(ref)
    import json

    line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()[0]
    obj = json.loads(line)
    obj["node"]["signature"] = "AAAA"
    (tmp_path / "audit.jsonl").write_text(json.dumps(obj, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(VerificationError):
        adapter.verify_chain_event(ref)
