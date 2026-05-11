"""Minimal local identity + one material action."""

from pathlib import Path

from autonomous_identity import AutonomousIdentity, ValidatorStrictness

identity = AutonomousIdentity.local(Path(".asid-demo"), strictness=ValidatorStrictness.STRICT)

envelope = identity.issue_envelope(
    {
        "system_identifier": "agent://demo/minimal",
        "instance_id": "inst-1",
        "deployment_id": "deploy-1",
        "owner_id": "team:demo",
        "provenance": {"code_hash": "sha256:abc", "policy_bundle_hash": "sha256:def"},
        "attestation_chain": ["local:bootstrap"],
    }
)


@identity.material_action(action_type="demo.echo")
def echo(msg: str) -> str:
    return msg


with identity.exercise(envelope):
    out = echo("hello")
    print(out)
