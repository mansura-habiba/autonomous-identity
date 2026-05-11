"""Print a JSON envelope suitable for A2A ``SendMessageRequest.metadata``.

Usage (from repo root)::

    uv run python examples/a2a_identity_agent/bootstrap_envelope.py > /tmp/env.json
    # then pass the file contents as the string value for metadata key
    # ``autonomous_identity.envelope_json`` (see demo_client.py).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.core.serialize import envelope_to_serializable


def _demo_data_dir() -> Path:
    """Match ``server.py`` so lifecycle + keys stay in one tree (default: repo ``.asid-a2a-demo``)."""
    override = os.environ.get("ASID_A2A_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / ".asid-a2a-demo"


def main() -> None:
    identity = AutonomousIdentity.local(_demo_data_dir(), strictness=ValidatorStrictness.STRICT)
    envelope = identity.issue_envelope(
        {
            "system_identifier": "agent://a2a/echo-demo",
            "instance_id": "a2a-1",
            "deployment_id": "d1",
            "owner_id": "team:demo",
            "provenance": {"code_hash": "sha256:a2a", "policy_bundle_hash": "sha256:pol"},
            "attestation_chain": ["local:a2a-bootstrap"],
        }
    )
    sys.stdout.write(json.dumps(envelope_to_serializable(envelope), separators=(",", ":")))


if __name__ == "__main__":
    main()
