# A2A + autonomous-identity (demo)

This folder follows the same **HTTP JSON-RPC + Starlette** pattern as
[Google `a2a-samples`](https://github.com/a2aproject/A2A), e.g.
`samples/python/agents/helloworld` and `agents/a2a-mcp-without-framework`, but each
`sendMessage` carries an **`IdentityEnvelope`** on request metadata so the agent
runs an audited **material action** under `identity.exercise(envelope)`.

## Install

From the `autonomous-identity` repo root (with optional extra):

```bash
pip install -e ".[a2a]"
# or
uv sync --extra a2a
```

`server.py` and `demo_client.py` load `a2a_upb_compat.apply()` before other `a2a` imports. That patches `a2a.utils.proto_utils` where upstream still uses `FieldDescriptor.label`, which is missing on some protobuf **upb** builds (for example Python 3.14), so JSON-RPC `SendMessage` validation does not crash.

**Data directory:** identity state defaults to **`<repo>/.asid-a2a-demo`** (resolved from these scripts’ paths, not the shell cwd), so the server and `bootstrap_envelope` / `demo_client` agree on lifecycle records. Override with `ASID_A2A_DATA_DIR` if needed.

## Run

**Terminal 1 — server**

```bash
uv run python examples/a2a_identity_agent/server.py --host 127.0.0.1 --port 9999
```

**Terminal 2 — client** (bootstraps a fresh envelope JSON, then calls the agent)

```bash
uv run python examples/a2a_identity_agent/demo_client.py
```

If something else is already bound to port `9999`, start the server on another port and point the client at it:

```bash
# terminal 1
uv run python examples/a2a_identity_agent/server.py --port 10000

# terminal 2
A2A_DEMO_BASE_URL=http://127.0.0.1:10000 uv run python examples/a2a_identity_agent/demo_client.py
```

**Envelope JSON only** (for your own A2A client):

```bash
uv run python examples/a2a_identity_agent/bootstrap_envelope.py
```

Pipe or copy the single-line JSON into `SendMessageRequest.metadata["autonomous_identity.envelope_json"]`.

## Contract

| Piece | Meaning |
|--------|--------|
| `metadata["autonomous_identity.envelope_json"]` | JSON string from `envelope_to_serializable` / `bootstrap_envelope.py` |
| User text | Normal A2A user message parts (`get_user_input()`) |
| Artifact `greeting` | Text reply; artifact `metadata` includes `audit_ref` and `system_identifier` |

## Relation to A2A samples

- **Transport & task lifecycle**: `a2a-sdk` (`DefaultRequestHandler`, `InMemoryTaskStore`, JSON-RPC routes) — same ideas as `a2a-samples`.
- **Trust / scope / audit at action time**: `autonomous-identity` — not part of the A2A spec; you attach envelopes as **application metadata** (or later as an official extension if you standardize it).

For multi-agent delegation at runtime, reuse `issue_and_delegate_tree` and pass the **leaf** envelope on downstream A2A calls.
