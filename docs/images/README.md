# Screenshots referenced by DEMO.md

Drop the Langfuse screenshot the demo produces into this folder so the
README image references resolve.

| File                                         | What it shows |
|----------------------------------------------|---------------|
| `langfuse-asid-delegate-federation.png`      | The `asid.delegate` span for the cross-trust-domain hop in the A2A federation demo (tenant-a → tenant-b). Metadata shows `federation=true`, `scopes=["work.request"]`, parent/child SPIFFE IDs in different trust domains, `audit_ref`, `delegation_depth`, `expires_at`, `lifecycle_state=active`. This is the "all eight identity properties on one screen" pane referenced in DEMO.md. |

## How to capture it

1. Run the federation demo with Langfuse env vars set (see DEMO.md → Demo 2).
2. Open Langfuse → Tracing.
3. Filter by trace name `asid-fed-tenant-a`.
4. Open the `asid.delegate` trace whose metadata shows
   `child_subject` starting with `spiffe://tenant-b.example/`.
5. Switch to the Preview tab (Formatted) so the metadata renders as a table.
6. Screenshot the metadata panel and save as
   `docs/images/langfuse-asid-delegate-federation.png`.
