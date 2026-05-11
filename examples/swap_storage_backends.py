"""Run the same issuance using different storage backends (file vs sqlite)."""

from pathlib import Path

from autonomous_identity import AutonomousIdentity


def run(backend: str, root: Path) -> None:
    cfg = {
        "identity": {"adapter": "merkle_chain"},
        "storage": {"backend": backend, "data_dir": str(root / backend), "path": str(root / backend / "store.sqlite3")},
    }
    if backend == "sqlite":
        cfg["storage"] = {"backend": "sqlite", "path": str(root / backend / "store.sqlite3")}
    identity = AutonomousIdentity.from_config_dict(cfg)
    env = identity.issue_envelope(
        {
            "system_identifier": f"agent://swap/{backend}",
            "instance_id": "i1",
            "deployment_id": "d1",
            "owner_id": "team:demo",
            "provenance": {"code_hash": "sha256:aa", "policy_bundle_hash": "sha256:bb"},
            "attestation_chain": ["local:x"],
        }
    )
    print(backend, env.audit_ref)


if __name__ == "__main__":
    base = Path(".asid-swap-demo")
    base.mkdir(exist_ok=True)
    run("file", base)
    run("sqlite", base)
