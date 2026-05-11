# Scope namespace convention (asid v1)

## Identity vs authorization

**Strict identity** (who this credential represents: `system_identifier`, owner binding, runtime, provenance, signatures, lifecycle) does **not** require any scope strings.

**Authorization** (what actions are permitted in flows that use this library) is an **optional** layer: `issuer_scopes` on a **root** envelope only, `allowed_scopes` on each `Delegation`, and optional `required_scope` on material actions. After `delegate`, the Merkle adapter **removes** `issuer_scopes` from the child metadata so downstream actors rely on **delegation edges** for capability strings—identity proofs and auth grants are separated.

Without a shared grammar for those strings, two teams can use the same token for different meanings. This document defines an **optional** **asid scope v1** form so organizations can partition the namespace like IAM partitions actions.

## Grammar (v1)

Each scope is a single ASCII string:

```text
asid:<namespace>:<service>:<capability>
```

| Part | Meaning | Length | Characters |
|------|---------|--------|------------|
| `asid` | Literal scheme (case-insensitive when validating) | 4 | `asid` |
| `namespace` | Tenant / org **partition** (collision boundary vs other orgs) | 1–63 | `a-z`, `0-9`, hyphen (no leading/trailing hyphen) |
| `service` | Product or bounded context | 1–63 | same as namespace |
| `capability` | Hierarchical **action** (IAM “action” analogue) | 1+ dot-separated **segments**, each 1–63 chars | `a-z`, `0-9`, hyphen, underscore |

**Total string length:** at most **512** characters.

**Examples**

- `asid:acme-corp:commerce:orders.read`
- `asid:acme-corp:agent-runtime:tool.invoke`
- `asid:globex:docs:wiki.pages.write`

**Invalid**

- `orders.read` — missing `asid:` partition (legacy free-form; allowed when enforcement is off).
- `asid:acme:svc` — missing capability segment.
- `ASID:acme:svc:read` — prefix is matched case-insensitively for **validation**, but **`build_scope_v1`** emits lowercase `asid`.

## IAM mental model

| IAM-style idea | asid v1 field |
|----------------|---------------|
| Partition / account | `namespace` (derive from org / tenant) |
| Service prefix (e.g. `s3`, `iam`) | `service` |
| Action verb | `capability` (often `resource.operation`) |
| Resource ARN | **Not** in the scope string by default; bind in **`caveats`** (e.g. `resource_arn`, `bucket_id`) or define a longer capability path, e.g. `asid:acme:s3:bucket.mybucket.objects.get` |

Subset semantics for delegation are **unchanged**: when `allowed_scopes` is non-empty, every entry must be in the parent’s **effective** scopes (see `effective_scopes_for_actor`). An **empty** `allowed_scopes` list is allowed for an identity-only edge (no new capability strings on the child).

## Deriving `namespace`

Recommended (pick one per organization):

1. **From `owner_id`:** e.g. `team:acme-platform` → slug `acme-platform` or `team-acme-platform`.
2. **Explicit metadata:** set `metadata["scope_namespace"]` at issue time and copy into every internal doc; **enforcement** still validates the **scope string** shape, not equality to `owner_id`.
3. **Registry:** map `owner_id` → canonical namespace slug in your control plane, then call **`build_scope_v1`**.

Keep namespaces **stable** across deployments so audit and policy lines stay comparable.

## Optional runtime enforcement

By default the library treats scopes as **opaque** strings (backward compatible).

Enable v1 checks when constructing identity:

```python
AutonomousIdentity.local(
    Path(".asid"),
    enforce_scope_convention=True,
)
```

Or YAML:

```yaml
identity:
  adapter: merkle_chain
  enforce_scope_convention: true
```

When enabled:

- **`issue_envelope`**: after the adapter builds the envelope, `issuer_scopes` (if present) must all match v1.
- **`delegate`**: child `allowed_scopes` must each match v1.
- **`IdentityValidator.validate`**: same checks on any envelope under validation.
- **`run_material_action`**: if `required_scope` is set, it must match v1.

Helpers (always available, do not require enforcement):

- `autonomous_identity.core.scope_convention.build_scope_v1(namespace, service, capability)`
- `autonomous_identity.core.scope_convention.is_valid_scope_v1(scope)`

## Backward compatibility

Deployments that already use short names (`doc.write`, `orders.read`) **keep working** until `enforce_scope_convention=True`. Migrate by renaming scopes in issue/delegate flows and re-issuing envelopes.
