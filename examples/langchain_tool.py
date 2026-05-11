"""LangChain tool protected by autonomous-identity (requires langchain-core)."""

from pathlib import Path

from autonomous_identity import AutonomousIdentity
from autonomous_identity.integrations.langchain import identity_protected_tool

identity = AutonomousIdentity.local(Path(".asid-langchain-demo"))

envelope = identity.issue_envelope(
    {
        "system_identifier": "agent://demo/langchain",
        "instance_id": "inst-1",
        "deployment_id": "deploy-1",
        "owner_id": "team:demo",
        "provenance": {"code_hash": "sha256:aa", "policy_bundle_hash": "sha256:bb"},
        "attestation_chain": ["local:x"],
    }
)


@identity_protected_tool(identity=identity, action_type="demo.add", required_scope=None)
def add(a: int, b: int) -> int:
    return a + b


with identity.exercise(envelope):
    print(add.invoke({"a": 2, "b": 3}))
