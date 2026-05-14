# Federation Authority Concept

> Status: concept only. This document describes a proposed federation package and authority model. It does not describe behavior that is currently implemented in the library.

## Why this concept exists

The current federation examples demonstrate a useful but bounded capability: a cross-trust-domain delegation can carry an explicit federation caveat, and the receiver can verify SPIFFE-style SVID material against a trust bundle. That is a good local safety property, but it is not yet a complete authority semantics for autonomous systems operating across independent organizations.

For autonomous systems, cryptographic validity is necessary but not sufficient. A token can be signed correctly and still be semantically unauthorized for a specific receiver, action, region, scope, or point in time. The question a receiving domain must answer is not only whether the envelope is genuine, but whether this specific autonomous-system authority is acceptable under the receiver's federation policy.

The proposed federation package turns that question into an explicit, auditable decision.

```text
Can a subject from trust domain A exercise this specific authority
inside trust domain B, for this audience, under this policy, at this time?
```

## Non-goals

This concept does not claim to define a universal global federation standard. It is not a replacement for SPIFFE federation, SAML, OIDC, legal trust agreements, or inter-organization governance. It is a bounded authority model that can sit above existing identity primitives and make autonomous-system delegation explicit, testable, and auditable.

The first version should not claim:

- universal inter-organization semantics,
- legal-grade cross-jurisdiction authority,
- automatic policy reconciliation between organizations,
- decentralized trust governance,
- recursive full-DAG closure verification,
- external SLSA or in-toto validation,
- hardware-rooted runtime attestation.

Those may become future extensions, but they are outside the scope of this concept.

## Proposed package boundary

The proposed package would live under:

```text
src/autonomous_identity/federation/
    __init__.py
    model.py
    policy.py
    verifier.py
    revocation.py
    audit.py
```

This package should be separate from the SPIFFE and composite adapters. The adapters mint and verify cryptographic artifacts. The federation package evaluates whether a federated authority should be accepted by a receiving trust domain.

## Core idea

The federation authority layer evaluates a structured policy against an identity envelope. It produces a structured decision rather than a bare boolean.

A decision answers:

- Who is the federated subject?
- Which source trust domain delegated to it?
- Which receiver trust domain is evaluating it?
- Which audience is the envelope intended for?
- Which scope was requested?
- Which local scope does that map to?
- Which checks passed or failed?
- Why was the authority accepted or rejected?

## Semantic checks

A first implementation should evaluate the following checks.

| Check | Purpose |
|---|---|
| Source trust domain is recognized | Prevent unknown organizations or tenants from delegating authority. |
| Receiver trust domain matches the envelope subject | Prevent confused-deputy reuse across domains. |
| Federation caveat is present | Ensure cross-domain delegation was explicit, not accidental. |
| SVID signature verifies against trusted JWKS | Prove the source-domain cryptographic assertion. |
| Audience is allowed | Prevent replay of an envelope intended for a different receiver or service. |
| Scope mapping exists | Avoid assuming that scopes mean the same thing across domains. |
| Mapped scope is allowed | Ensure the receiver permits the translated authority. |
| Delegation remains attenuated | Ensure cross-domain handoff narrows authority rather than expanding it. |
| Subject is not revoked | Allow source or receiver policy to block a subject after issuance. |
| Key ID is not revoked | Allow key-level revocation after compromise or rotation. |
| TTL is within receiver limit | Prevent long-lived federated authority. |
| Jurisdiction constraints pass | Prevent action in disallowed regions or policy zones. |
| Decision is auditable | Preserve why authority was accepted or rejected. |

## Conceptual policy shape

A policy can be represented as JSON or YAML. JSON is enough for a dependency-free first implementation.

```yaml
federation:
  receiver_trust_domain: tenant-b.example

  trusted_domains:
    tenant-a.example:
      status: active
      jwks_ref: file://trust/tenant-a-jwks.json

      allowed_audiences:
        - spiffe://tenant-b.example/agents/processor
        - spiffe://tenant-b.example/services/work-intake

      scope_mappings:
        work.request: intake.submit
        evidence.read: evidence.import

      allowed_target_scopes:
        - intake.submit
        - evidence.import

      max_ttl_seconds: 3600

      jurisdiction:
        allowed_regions:
          - eu-west
          - us-east
        denied_regions:
          - restricted-region

      revocation:
        revoked_subjects: []
        revoked_delegation_ids: []
        revoked_kids: []
```

The important design point is that cross-domain authority is not inferred. It is explicitly translated and constrained by the receiver.

## Conceptual decision object

A verifier should return a structured decision.

```text
FederationDecision
    allowed: bool
    reason: string
    source_trust_domain: string | null
    receiver_trust_domain: string
    subject: string
    audience: string | null
    requested_scope: string | null
    mapped_scope: string | null
    checks: list[FederationCheck]

FederationCheck
    name: string
    passed: bool
    detail: string
```

This structure is intentionally verbose. Federation decisions are governance decisions. They should be inspectable by humans, auditable by systems, and useful in tests.

## Conceptual verification flow

```text
VerifyFederatedAuthority(envelope, receiver_policy, requested_scope, audience, action_region):
    parse envelope subject as SPIFFE ID
    confirm subject belongs to receiver trust domain

    find a delegation edge crossing from a source trust domain into the receiver trust domain
    confirm the delegation has an explicit federation caveat

    load the receiver policy for the source trust domain
    confirm the source domain is trusted and active

    verify the SVID signature using the receiver-pinned JWKS for the source domain
    confirm the SVID subject matches the envelope subject
    confirm the SVID is not expired

    confirm the audience is allowed

    translate the requested source scope into a receiver-local scope
    confirm the mapped scope is allowed by receiver policy
    confirm the mapped scope does not exceed the effective delegated authority

    check subject, delegation, and key revocation lists
    check TTL constraints
    check jurisdiction constraints

    emit a structured allow or deny decision
    optionally append the decision to the audit store
```

## Relationship to existing adapters

The SPIFFE and composite adapters remain responsible for cryptographic envelope construction and verification.

The federation package is responsible for receiver-side authority semantics.

| Layer | Responsibility |
|---|---|
| SPIFFE adapter | Mint and verify SPIFFE-shaped SVID claims. |
| Composite adapter | Combine SVID claims with Merkle-DAG audit evidence. |
| Federation authority layer | Decide whether the receiver accepts the delegated authority. |
| Audit store | Record the decision and evidence. |

This separation keeps the adapter from becoming a policy engine. It also avoids overloading cryptographic identity with business authority semantics.

## Relationship to scope attenuation

The federation verifier should reuse the existing effective-scope calculation. The source domain may delegate `work.request`, but the receiver may only accept it after translating it to a receiver-local scope such as `intake.submit`.

The verifier should ensure:

```text
mapped_scope is allowed by receiver policy
AND
mapped_scope or original requested_scope is present in the effective delegated scope set
```

This maintains the principle that federation cannot create new authority. It can only translate and further constrain authority already delegated.

## Relationship to revocation

The first implementation can use local revocation lists:

- revoked subjects,
- revoked key IDs,
- revoked delegation IDs.

Future implementations may replace these lists with:

- SPIFFE bundle refresh state,
- domain-hosted revocation endpoints,
- transparency logs,
- signed revocation events,
- short-lived federation grants.

The initial design should keep revocation simple and explicit.

## Relationship to jurisdiction

Jurisdiction checks should be treated as receiver-side policy constraints. The envelope does not decide whether an action is allowed in a region. The receiver policy does.

A jurisdiction policy can start with two lists:

```text
allowed_regions
denied_regions
```

If `allowed_regions` is empty, the verifier only enforces the denied list. If `allowed_regions` is non-empty, the action region must appear in the allowed list and must not appear in the denied list.

## Audit semantics

Federation decisions should be auditable even when rejected. A rejected federation decision is often more important than an accepted one because it explains a blocked authority path.

An audit row could look like:

```json
{
  "kind": "federation_decision",
  "decision": {
    "allowed": false,
    "reason": "federated authority rejected",
    "source_trust_domain": "tenant-a.example",
    "receiver_trust_domain": "tenant-b.example",
    "subject": "spiffe://tenant-b.example/agents/processor",
    "audience": "spiffe://tenant-b.example/services/work-intake",
    "requested_scope": "work.request",
    "mapped_scope": "intake.submit",
    "checks": [
      {
        "name": "audience_allowed",
        "passed": true,
        "detail": "audience is allowed"
      },
      {
        "name": "region_not_denied",
        "passed": false,
        "detail": "action_region=restricted-region"
      }
    ]
  }
}
```

## Development guidelines

This package should be developed as a receiver-side authority verifier, not as another identity adapter. The implementation should remain small, dependency-light, and explicit about every trust decision it makes.

### 1. Keep cryptographic identity and authority semantics separate

Do not move federation policy logic into the SPIFFE or composite adapters. The adapters should continue to mint, bind, and verify cryptographic artifacts. The federation layer should decide whether the receiver accepts a federated authority under local policy.

A good boundary is:

```text
adapter.verify(envelope) answers: Is this envelope cryptographically valid?
federation.verify(envelope, policy) answers: Is this federated authority acceptable here?
```

### 2. Prefer structured decisions over exceptions for policy denials

Policy denials should normally return a `FederationDecision` with `allowed=false` and a list of failed checks. Exceptions should be reserved for programmer errors, malformed inputs that cannot be interpreted, or storage/IO failures.

This keeps rejected authority paths auditable and testable.

### 3. Fail closed when federation evidence is missing

If an envelope crosses trust domains but does not carry an explicit federation caveat, the verifier must reject it. If an SVID, key ID, trust bundle, audience, or required scope mapping is missing, the verifier must reject rather than infer intent.

No cross-domain authority should be accepted by default.

### 4. Make scope translation explicit

Do not assume that a scope string has the same meaning in two trust domains. The receiver must explicitly map source-domain scopes into receiver-local scopes.

For example:

```text
source scope: work.request
receiver scope: intake.submit
```

The absence of a mapping should be a denial, not a pass-through.

### 5. Preserve monotone attenuation

Federation must not create authority. It can only translate and further constrain authority that already exists in the delegated envelope.

The verifier should check both:

```text
requested source scope is represented in the delegated authority
mapped receiver scope is allowed by receiver policy
```

If there is ambiguity between source scope and mapped scope, choose the narrower interpretation or reject.

### 6. Treat audience as mandatory for material actions

For low-risk discovery or diagnostics, an omitted audience may be tolerable during development. For material actions, the receiver should require an audience and check it against policy.

This prevents a federated envelope intended for one service from being replayed against another service.

### 7. Keep revocation simple first

The first implementation should use local revocation lists for subjects, key IDs, and delegation IDs. Do not start with distributed revocation protocols, transparency logs, or online status checks unless there is a concrete use case.

The design should allow those mechanisms later through an interface, but the first version should be deterministic and easy to test.

### 8. Make jurisdiction receiver-owned

Jurisdiction constraints should be evaluated by the receiver's policy. The envelope may carry metadata, but the receiver decides whether an action region is acceptable.

When in doubt, reject if the action region is required by policy but missing from the request context.

### 9. Avoid global claims in code and documentation

Do not name the package, classes, or documentation in a way that implies a universal federation standard. Prefer names such as:

```text
FederationAuthorityVerifier
FederationPolicy
FederationDecision
TrustedDomainPolicy
```

Avoid names such as:

```text
GlobalFederationStandard
UniversalTrustVerifier
CompleteFederationSemantics
```

### 10. Keep the first implementation dependency-light

The first implementation should be pure Python and use existing project primitives. Prefer JSON policy loading before YAML unless YAML is already a project dependency.

Do not introduce OPA, Cedar, Rego, SPIRE APIs, or cloud KMS dependencies in the first package. Those can be adapters later.

### 11. Test accepted and rejected paths equally

Federation tests should not only prove that happy paths work. They should prove that unsafe paths fail closed.

Required test categories:

- trusted source domain accepted,
- unknown source domain rejected,
- inactive source domain rejected,
- missing federation caveat rejected,
- wrong audience rejected,
- missing audience rejected for material actions,
- unmapped scope rejected,
- mapped scope outside receiver policy rejected,
- attempted scope expansion rejected,
- revoked subject rejected,
- revoked key ID rejected,
- TTL above maximum rejected,
- denied region rejected,
- missing required region rejected,
- structured decision contains every check,
- accepted and rejected decisions can be written to the audit store.

### 12. Keep examples separate from the core package

The package should provide reusable primitives. A2A, LangGraph, MCP, or service-specific federation examples should remain under `examples/`.

The core federation package should not import from example code.

### 13. Make the audit trail useful to humans

Every failed check should include a human-readable detail string. Avoid messages that only say `false` or `not allowed`.

Good:

```text
audience spiffe://tenant-b.example/services/x is not in allowed audiences
```

Weak:

```text
audience failed
```

### 14. Version the policy shape

When the implementation starts, include a policy version field. Federation semantics will evolve, and old policy files should not be silently interpreted under new rules.

Example:

```yaml
federation:
  version: 1
  receiver_trust_domain: tenant-b.example
```

### 15. Document what the implementation does not prove

Every release note or paper section that mentions federation should say what the package does and does not prove.

The first implementation may claim:

```text
bounded receiver-side federation authority verification
```

It should not claim:

```text
complete global federation semantics
```

## Example acceptance case

```text
Source domain: tenant-a.example
Receiver domain: tenant-b.example
Delegated subject: spiffe://tenant-b.example/agents/processor
Requested scope: work.request
Mapped receiver scope: intake.submit
Audience: spiffe://tenant-b.example/services/work-intake
Action region: eu-west
```

The receiver accepts if:

1. `tenant-a.example` is trusted and active.
2. The delegation crosses into `tenant-b.example`.
3. The delegation carries `spiffe.federation=true`.
4. The SVID verifies against tenant B's pinned JWKS for tenant A.
5. The audience is allowed.
6. `work.request` maps to `intake.submit`.
7. `intake.submit` is allowed by tenant B.
8. The subject and key are not revoked.
9. The TTL is within tenant B's maximum.
10. `eu-west` is allowed.

## Example rejection cases

| Case | Expected rejection reason |
|---|---|
| Unknown source domain | Source domain is not configured in receiver policy. |
| Missing federation caveat | Cross-domain delegation was not explicit. |
| Wrong audience | Envelope was not intended for this receiver or service. |
| Unmapped scope | Receiver has no semantic translation for the requested authority. |
| Scope expansion | Requested or mapped scope exceeds delegated authority. |
| Revoked subject | Receiver policy blocks the delegated subject. |
| Revoked key ID | Source-domain signing key is no longer trusted. |
| TTL too long | Federated authority exceeds receiver freshness policy. |
| Denied region | Action region is blocked by receiver jurisdiction policy. |

## Suggested tests for a future implementation

A future source-code implementation should include tests for:

- accepting a trusted source domain with a valid SVID and mapped scope,
- rejecting an unknown source domain,
- rejecting a missing federation caveat,
- rejecting a wrong audience,
- rejecting an unmapped scope,
- rejecting attempted scope expansion,
- rejecting a revoked subject,
- rejecting a revoked key ID,
- rejecting a denied jurisdiction,
- rejecting TTL above the receiver maximum,
- returning a structured decision with all checks,
- recording accepted and rejected decisions to an audit store.

## Research claim enabled by this concept

If implemented, the library could claim:

> The library implements a bounded federation authority verifier for cross-domain autonomous-system delegation. It evaluates trusted domains, explicit federation caveats, SVID validity, audience binding, scope translation, attenuation, local revocation lists, TTL, jurisdiction constraints, and emits a structured decision.

It should still not claim:

> The library defines a universal global federation standard.

The distinction matters. The proposed package gives an executable semantics for a receiver-controlled federation policy. It does not solve the political, legal, and organizational problem of universal federation.
