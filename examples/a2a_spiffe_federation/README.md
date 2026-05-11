# SPIFFE federation A2A demo

Two tenants in distinct SPIFFE trust domains (`tenant-a.example`,
`tenant-b.example`) exchange an autonomous-system envelope across the
federation boundary. Every check that a production SPIFFE federation deployment
performs at the receiving workload is exercised here.

## What this proves

1. **SPIFFE ID per workload.** Each agent is named `spiffe://<td>/<path>`.
2. **Trust-domain enforcement on delegation.** Cross-TD delegation is rejected
   by default and only succeeds with the explicit
   `spiffe.allow_cross_trust_domain` caveat. The audit row carries
   `federation: True` plus both trust domains.
3. **Out-of-band trust-bundle exchange.** The receiver only trusts JWKS it
   already has in its bundle. An envelope arriving with a stranger's JWKS in
   metadata is rejected even if the JWS would validate against it.
4. **Monotone-decreasing scope across the boundary.** tenant-a's initiator
   holds `[a2a.send, work.request, ops.read]`; the federated child for
   tenant-b receives only `[work.request]`. tenant-b cannot later exercise
   `a2a.send` — the scope check at moment-of-exercise rejects it.
5. **Tamper detection.** Modifying the SVID JWS in transit breaks the
   federated verification at the receiver.

## Run it

From the repo root:

```bash
pip install -e .
python examples/a2a_spiffe_federation/federation_demo.py
```

This is an in-process demo: tenant-a and tenant-b run as separate
`AutonomousIdentity` instances in the same Python process with separate
signing keys, audit stores, and trust bundles. The demo uses the same
`metadata['autonomous_identity.envelope_json']` key the existing
`examples/a2a_identity_agent/` executor reads, so the receiver logic
transplants directly onto a JSONRPC server pair.

## Mapping to real two-server A2A

To run this over real HTTP:

1. Stand up two `AutonomousIdentity` instances, one per trust domain, each in
   its own server process (use `examples/a2a_identity_agent/server.py` as the
   template for each tenant).
2. Exchange the JWKS out-of-band — write `tenant-a`'s JWKS into the receiving
   server's trust bundle on startup (a JSON file mounted as a configmap is
   typical). In SPIRE production, this is handled by the SPIRE Server's
   federation API.
3. Replace `tenant_b_handle()` with a custom `AgentExecutor` (see
   `examples/a2a_identity_agent/agent_executor.py`) that runs
   `verify_federated_envelope()` before invoking the normal
   `identity.exercise(...)` block.

## What this demo does **not** do

- **No SPIRE Workload API.** SVIDs are minted with the repo's local Ed25519
  signer per tenant, not fetched from a SPIRE Agent socket. Use the (future)
  `spire` adapter when integrating with a SPIRE deployment.
- **No X509-SVID.** Only JWT-SVID-shaped envelopes are exercised here. The
  same federation pattern applies to X.509-SVID; the trust-bundle exchange
  shape is identical.
- **No revocation propagation.** Each tenant's lifecycle store is local. A
  real cross-tenant deployment needs to publish revocation state (or use
  short SVID TTLs and refresh).

## Output

Successful run prints:

```
=== Trust bundle exchange (out-of-band) ===
tenant-b trusts tenant-a's JWKS kid=['...']

=== Federated envelope tenant-a is sending ===
  spiffe_id:        spiffe://tenant-b.example/agents/processor
  trust domain:     tenant-b.example
  effective scopes: ['work.request']
  delegation hops:  3 -> [...]
  federation edge:  spiffe.federation = True

=== tenant-b receiver verification + execution ===
  artifact:         tenant-b processed: 'process invoice batch 42'
  audit_ref:        audit://file/...
  actor spiffe_id:  spiffe://tenant-b.example/agents/processor
  parent TD:        tenant-a.example

=== Negative case 1: receiver missing trust bundle entry ===
  rejected: No trust-bundle entry for peer trust domain 'tenant-a.example'. ...

=== Negative case 2: tenant-b attempts to exercise a scope it was not granted ===
  rejected: Required scope 'a2a.send' not in effective scopes ['work.request']

=== Negative case 3: SVID tampering breaks federated verification ===
  rejected: JWS signature verification failed: ...

ALL FEDERATION CHECKS PASSED
```
