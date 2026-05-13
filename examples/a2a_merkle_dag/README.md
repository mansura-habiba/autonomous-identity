# A2A multi-party co-assertion (Merkle DAG)

A refund-approval flow where three principals — actor, policy engine,
evidence gate — collaborate on a privileged action over the A2A
metadata channel. The DAG adapter records all three principals'
contributions in a single audit row.

The chain adapter cannot express this case cleanly: it would force
`actor → policy → evidence → action` into a sequence and lose the fact
that policy and evidence are *siblings* of the actor at the moment of
attestation, not ancestors of each other. The DAG preserves the real
dependency graph.

## What it proves

Run `multi_witness_demo.py` and four checks land:

1. **Three principals each issue their own envelope** via the same
   `merkle_dag` adapter and the same audit store.
2. **A2A round trips work via the standard metadata channel.**
   Each "service" responds with its envelope serialised under
   `metadata['autonomous_identity.envelope_json']` — the same key the
   single-trust-domain executor in `examples/a2a_identity_agent/` reads.
3. **The approval action's audit row commits to three parent hashes,**
   not one. The DAG adapter's `audit(envelope, action, witnesses=[...])`
   call records the actor's tip plus each witness's tip, sorted, in the
   node's commitment payload.
4. **Tampering with the policy service's row breaks its own
   verification.** The DAG binds via hash commitments, so any node whose
   stored bytes don't reproduce its committed hash fails
   `verify_chain_event`. A verifier walking the DAG can detect any
   ancestor that's been altered.

The demo also catches a foreign witness — an envelope that wasn't issued
by this adapter has no DAG tip in its metadata, and `audit()` rejects it
at the call rather than producing an unverifiable row.

## Run

```bash
pip install -e .
python examples/a2a_merkle_dag/multi_witness_demo.py
```

No API keys, no external services, no second process — the A2A round
trips are simulated in-process so the demo is self-contained. The
metadata key, the envelope JSON shape, and the witness collection
pattern all map directly onto the HTTP A2A executor.

## What the audit row looks like

```jsonc
{
  "kind": "dag_node",
  "system_identifier": "agent://corp/agents/refund-bot",
  "node": {
    "previous_hashes": [
      "7d35a080d6a536e513e265a9d8ffa623…",   // refund-bot's own tip
      "a68328e6284fe7558a01411064ff5f57…",   // policy service's tip
      "92b5165af271ea779a1ec959c124662a…"    // evidence service's tip
    ],
    "subject": "agent://corp/agents/refund-bot",
    "action_type": "refund.approve",
    "envelope_hash": "…",
    "input_hash": "claim:claim-7:amount:129:customer:cust-42",
    "output_hash": "refund_approved",
    "signature": "…"
  },
  "witness_subjects": [
    "agent://corp/policies/refund-rules",
    "agent://corp/evidence/customer-history"
  ],
  "action": { … },
  "envelope_commitment": { … }
}
```

The `previous_hashes` field is the operational difference from the chain
adapter. A verifier holding this row knows, in one read, which
principals were at which point in their own chains when this approval
fired. A compliance investigation can walk each parent independently.

## Mapping to a real two-server (or three-server) A2A deployment

The in-process demo uses one adapter instance for all three principals
so witnesses share a trust root. To deploy this against three real
processes:

1. **Run three A2A servers**, one per principal — refund-bot,
   refund-rules, customer-history. Each is an HTTP/JSON-RPC service
   built from the template in `examples/a2a_identity_agent/server.py`.
2. **Each service issues its envelope at startup** through its own
   `AutonomousIdentity` instance.
3. **Refund-bot sends two A2A requests** (`policy.check`,
   `evidence.fetch`). Each peer responds with its envelope JSON
   attached as `metadata['autonomous_identity.envelope_json']`, exactly
   like the existing executor.
4. **Refund-bot collects the two envelopes** via
   `envelope_from_serializable(...)` and calls
   `adapter.audit(actor_env, action, witnesses=[policy_env, evidence_env])`.

## The limitation worth understanding

The DAG adapter as shipped today requires witnesses to be issued by the
**same adapter instance** (i.e. signed by the same Ed25519 key). The
check is `metadata['dag_tip_hash']` plus a signature verifiable against
this adapter's signer. Three principals all sharing one signing key is
fine for in-process or single-tenant deployments where the operator
controls the trust root.

It is not yet right for cross-organization DAG attestation. Two
organizations cannot today co-assert a single action through this
adapter because:

- Their adapters use different signing keys.
- The DAG adapter does not yet validate a witness's signature against
  a foreign public key.
- There is no trust-bundle exchange protocol for DAG witnesses (the
  SPIFFE adapter has one, but it operates on JWS-shaped SVIDs, not
  Merkle DAG nodes).

The path to cross-org DAG witnesses is the same path the SPIFFE
adapter already took for federation: an explicit trust-bundle exchange
plus a foreign-witness verification step in `audit()`. That's on the
roadmap; until it ships, treat the DAG adapter as a single-trust-root
construct.

For cross-trust-domain co-assertion **today**, the path is:

1. Use the SPIFFE adapter (which supports federation).
2. Have each foreign principal sign its envelope.
3. Receive the SVIDs at the actor.
4. Audit the action with a single principal (the actor) and reference
   the foreign envelopes in the action's `metadata` or `input_hash`
   rather than as DAG witnesses.

That loses the structural co-assertion of the DAG, but it preserves
auditability across the boundary using primitives the library already
ships.

## When the DAG actually pays off

Three real cases:

- **Agent + policy engine + audit at one moment.** A single audit row
  proves both that the agent decided X and that the policy engine
  authorised it. No join across two logs.
- **Action + retrieval evidence.** The retrieval gate's tip at the moment
  the LLM saw the snapshot becomes a witness on every downstream
  action that depends on that retrieval. If the index is later
  reindexed, the audit row still binds to the snapshot's commitment
  hash, not to "whatever the index says now".
- **Runtime attestation as a witness.** A measured execution environment
  produces an attestation envelope; every privileged action inside that
  measurement window can witness against it. If the measurement
  substrate is later shown to have been compromised, every action that
  witnessed against the compromised attestation is identifiable from
  the audit log in one query.
