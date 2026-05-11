"""A2A federation demo across two SPIFFE trust domains.

This script demonstrates the full sequence:

    1. ``tenant-a`` publishes its JWKS into ``tenant-b``'s trust bundle
       (out-of-band exchange — the demo does this in memory).

    2. ``tenant-a`` issues a root envelope (``spiffe://tenant-a.example/agents/initiator#root``)
       and self-delegates into ``spiffe://tenant-a.example/agents/initiator`` with
       a broad scope set.

    3. ``tenant-a`` mints a **federated child envelope** for
       ``spiffe://tenant-b.example/agents/processor`` using
       ``caveats={'spiffe.allow_cross_trust_domain': True}``. The new envelope's
       scope set is monotone-decreasing (strictly a subset of the parent's).

    4. ``tenant-a`` serialises the envelope to JSON and stashes it under the
       same A2A metadata key the existing executor expects
       (``autonomous_identity.envelope_json``).

    5. ``tenant-b`` runs the receiver-side checks BEFORE any work:
         - SPIFFE ID is in ``tenant-b.example``
         - delegation chain contains a federation edge into ``tenant-b.example``
         - the embedded JWKS matches what tenant-b has in its trust bundle
         - SVID signature verifies against the trusted JWKS
         - commitment_hash binds to the current envelope contents

    6. tenant-b exercises the envelope and runs ONE audited material action.
       The audit_ref is returned to tenant-a as proof of execution.

Run::

    uv run python examples/a2a_spiffe_federation/federation_demo.py

What about real HTTP? See README.md in this folder — the in-process demo uses
the same envelope-on-metadata pattern as ``examples/a2a_identity_agent/`` so
it transplants directly onto a JSONRPC server pair (one per trust domain).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Allow running this file directly without installing the package as a script.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from autonomous_identity import AutonomousIdentity, ValidatorStrictness
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.core.serialize import (
    envelope_from_serializable,
    envelope_to_serializable,
)
from autonomous_identity.tracing import TracedIdentity

from trust_bundle import TrustBundle, jwks_only, verify_federated_envelope

# Add the examples dir to sys.path so we can import _demo_support whether
# this script is run as a module or as a path.
_EXAMPLES_DIR = Path(__file__).resolve().parents[1]
if str(_EXAMPLES_DIR) not in sys.path:
    sys.path.insert(0, str(_EXAMPLES_DIR))
from _demo_support import build_tracer, wait_for_flush  # noqa: E402


METADATA_ENVELOPE_JSON = "autonomous_identity.envelope_json"


def _build_tracer(tenant: str):
    """Wrapper kept for symmetry with the rest of the demo."""
    return build_tracer(trace_name=f"asid-fed-{tenant}")


# ----- tenant setup ----------------------------------------------------------


def _build_tenant(name: str, data_dir: Path) -> TracedIdentity:
    """Each tenant owns its own data dir → its own signing key + audit store."""
    data_dir.mkdir(parents=True, exist_ok=True)
    return TracedIdentity.local(
        data_dir,
        adapter_name="spiffe",
        strictness=ValidatorStrictness.STRICT,
        tracer=_build_tracer(name),
    )


# ----- tenant-a: issue, self-delegate, federate ------------------------------


def tenant_a_prepare_federated_envelope(identity: TracedIdentity) -> dict[str, Any]:
    """Run on the tenant-a side: produce the envelope to send to tenant-b."""
    expires = datetime.now(timezone.utc) + timedelta(hours=8)

    # 1. Root issuance with the broad scope set.
    root = identity.issue_envelope(
        {
            # SPIFFE IDs disallow '#' fragments, so use a path segment to
            # distinguish the issuer from the actor.
            "system_identifier": "spiffe://tenant-a.example/agents/initiator/root",
            "instance_id": "i-1",
            "deployment_id": "d-1",
            "owner_id": "tenant-a:platform",
            "provenance": {
                "code_hash": "sha256:tenant-a",
                "policy_bundle_hash": "sha256:pol-a",
            },
            "attestation_chain": ["local:bootstrap"],
            "issuer_scopes": [
                "a2a.send",       # NOT delegated across the federation boundary
                "work.request",   # what tenant-b will actually run
                "ops.read",       # NOT delegated across the federation boundary
            ],
        }
    )

    # 2. Internal self-delegation: initiator on tenant-a holds the full set.
    initiator = identity.delegate(
        root,
        "spiffe://tenant-a.example/agents/initiator",
        ["a2a.send", "work.request", "ops.read"],
        {"caller_subject": "user:alice", "role": "initiator"},
        expires_at=expires,
    )

    # 3. Federated child envelope: only the scope tenant-b actually needs.
    federated = identity.delegate(
        initiator,
        "spiffe://tenant-b.example/agents/processor",
        ["work.request"],  # strictly narrower than initiator
        {
            "spiffe.allow_cross_trust_domain": True,
            "purpose": "process invoice batch",
        },
        expires_at=expires,
    )

    # 4. Serialise for the wire — same key the existing A2A executor reads.
    wire = envelope_to_serializable(federated)
    return {
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [{"text": "process invoice batch 42"}],
            },
            "metadata": {METADATA_ENVELOPE_JSON: json.dumps(wire)},
        },
    }


# ----- tenant-b: receive, verify, exercise -----------------------------------


def tenant_b_handle(
    request: dict[str, Any],
    *,
    identity: TracedIdentity,
    trust_bundle: TrustBundle,
) -> dict[str, Any]:
    """Run on the tenant-b side. Validates federation BEFORE doing any work."""
    metadata = request["params"]["metadata"]
    raw = metadata.get(METADATA_ENVELOPE_JSON)
    if not raw:
        raise VerificationError(
            f"Missing A2A metadata key {METADATA_ENVELOPE_JSON!r}"
        )

    envelope = envelope_from_serializable(json.loads(raw))

    # (a) Cross-TD verification against tenant-b's trust bundle. This is the
    #     critical step the existing single-TD executor doesn't perform.
    fed_record = verify_federated_envelope(
        envelope,
        expected_trust_domain="tenant-b.example",
        trust_bundle=trust_bundle,
    )

    # (b) Standard envelope sanity (signed claims, lifecycle, scopes).
    if not identity._adapter.verify(envelope):  # noqa: SLF001
        raise VerificationError("Envelope failed local cryptographic verification")

    # (b.1) Admit the federated subject into the receiver's lifecycle store.
    #       Cross-TD envelopes were minted by the peer, so the receiver's
    #       lifecycle ledger has no record for the SPIFFE ID until we add
    #       one. SPIRE federation handles this via the federation API; here
    #       we do it explicitly on first sight after verification.
    if identity._lifecycle.get_lifecycle(envelope.system_identifier) is None:  # noqa: SLF001
        identity._lifecycle.set_lifecycle(  # noqa: SLF001
            envelope.system_identifier,
            envelope.lifecycle_state,
            reason="admitted via federation",
        )

    # (c) Exercise the envelope and run the requested action audited against it.
    user_text = " ".join(p["text"] for p in request["params"]["message"]["parts"])
    with identity.exercise(envelope):
        proof = identity.run_material_action(
            envelope,
            action_type="tenant_b.process_work",
            required_scope="work.request",
            fn=lambda: f"tenant-b processed: {user_text!r}",
            args=(),
            kwargs={},
        )

    return {
        "result": {
            "artifact": {"text": proof["result"]},
            "metadata": {
                "audit_ref": proof["audit_ref"],
                "actor_spiffe_id": envelope.system_identifier,
                "federation_record": fed_record,
            },
        }
    }


# ----- demo orchestration ----------------------------------------------------


def main() -> int:
    # Use a per-PID temp dir so reruns always start clean and so the demo
    # works on sandboxed filesystems where the cwd may be read-only.
    import os
    import tempfile

    data_root = Path(os.environ.get("ASID_FED_DATA_DIR") or tempfile.mkdtemp(prefix="asid-fed-"))

    tenant_a = _build_tenant("tenant-a", data_root / "tenant-a")
    tenant_b = _build_tenant("tenant-b", data_root / "tenant-b")

    # --- Out-of-band trust bundle exchange ------------------------------------
    # In real life: SPIRE federation API, or a static JWKS file mounted in.
    a_adapter_jwks = tenant_a._adapter._jwks  # noqa: SLF001 (demo introspection)
    b_adapter_jwks = tenant_b._adapter._jwks  # noqa: SLF001
    tenant_b_bundle = TrustBundle(name="tenant-b.example")
    tenant_b_bundle.add_peer("tenant-a.example", jwks_only(a_adapter_jwks))
    print("=== Trust bundle exchange (out-of-band) ===")
    print(
        f"tenant-b trusts tenant-a's JWKS kid="
        f"{[k['kid'] for k in tenant_b_bundle.jwks_for('tenant-a.example')['keys']]}"
    )
    print()

    # --- tenant-a side --------------------------------------------------------
    request = tenant_a_prepare_federated_envelope(tenant_a)
    fed_env_serialised = json.loads(
        request["params"]["metadata"][METADATA_ENVELOPE_JSON]
    )
    print("=== Federated envelope tenant-a is sending ===")
    print("  spiffe_id:       ", fed_env_serialised["system_identifier"])
    print("  trust domain:    ", fed_env_serialised["metadata"]["spiffe.trust_domain"])
    print("  effective scopes:", [
        d for d in fed_env_serialised["delegations"][-1]["allowed_scopes"]
    ])
    print(
        "  delegation hops: ",
        len(fed_env_serialised["delegations"]),
        "->",
        [
            f"{d['parent_subject']} → {d['child_subject']}"
            for d in fed_env_serialised["delegations"]
        ],
    )
    print(
        "  federation edge: ",
        "spiffe.federation =",
        fed_env_serialised["delegations"][-1]["caveats"].get("spiffe.federation"),
    )
    print()

    # --- tenant-b side --------------------------------------------------------
    print("=== tenant-b receiver verification + execution ===")
    response = tenant_b_handle(
        request,
        identity=tenant_b,
        trust_bundle=tenant_b_bundle,
    )
    print("  artifact:        ", response["result"]["artifact"]["text"])
    print("  audit_ref:       ", response["result"]["metadata"]["audit_ref"])
    print("  actor spiffe_id: ", response["result"]["metadata"]["actor_spiffe_id"])
    print(
        "  parent TD:       ",
        response["result"]["metadata"]["federation_record"]["parent_trust_domain"],
    )
    print()

    # --- Negative case 1: receiver has not exchanged trust bundle ------------
    print("=== Negative case 1: receiver missing trust bundle entry ===")
    empty_bundle = TrustBundle(name="tenant-b.example")
    try:
        tenant_b_handle(request, identity=tenant_b, trust_bundle=empty_bundle)
        print("  unexpectedly accepted!")
        return 2
    except VerificationError as exc:
        print("  rejected:", exc)
    print()

    # --- Negative case 2: scope escalation across the federation boundary ----
    print("=== Negative case 2: tenant-b attempts to exercise a scope it was not granted ===")
    try:
        envelope_b = envelope_from_serializable(fed_env_serialised)
        with tenant_b.exercise(envelope_b):
            tenant_b.run_material_action(
                envelope_b,
                action_type="tenant_b.escalate",
                required_scope="a2a.send",  # never granted to tenant-b
                fn=lambda: "should not run",
                args=(),
                kwargs={},
            )
        print("  unexpectedly accepted!")
        return 2
    except VerificationError as exc:
        print("  rejected:", exc)
    print()

    # --- Negative case 3: envelope tampered after federation -----------------
    print("=== Negative case 3: SVID tampering breaks federated verification ===")
    tampered = dict(fed_env_serialised)
    tampered["metadata"] = dict(tampered["metadata"])
    # Replace the SVID JWS with garbage in the wire envelope.
    tampered["metadata"]["spiffe.svid_jws"] = "AAAA.AAAA.AAAA"
    tampered_request = {
        "method": "message/send",
        "params": {
            "message": request["params"]["message"],
            "metadata": {METADATA_ENVELOPE_JSON: json.dumps(tampered)},
        },
    }
    try:
        tenant_b_handle(
            tampered_request,
            identity=tenant_b,
            trust_bundle=tenant_b_bundle,
        )
        print("  unexpectedly accepted!")
        return 2
    except VerificationError as exc:
        print("  rejected:", str(exc)[:140])
    print()

    print("ALL FEDERATION CHECKS PASSED")
    # Ensure any background batches in the Langfuse SDK actually leave the
    # process before we exit.
    wait_for_flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
