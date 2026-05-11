"""Call the identity A2A agent with an envelope in ``SendMessageRequest.metadata``.

Requires the server from ``server.py`` to be listening (default http://127.0.0.1:9999/).

Run::

    # terminal 1
    uv run python examples/a2a_identity_agent/server.py

    # terminal 2
    uv run python examples/a2a_identity_agent/demo_client.py
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import a2a_upb_compat

a2a_upb_compat.apply()

import httpx

from a2a.client import A2ACardResolver, ClientConfig, create_client
from a2a.helpers import new_text_message
from a2a.types import SendMessageRequest

# Must match ``agent_executor.METADATA_ENVELOPE_JSON`` (keep in sync without package import).
METADATA_ENVELOPE_JSON = "autonomous_identity.envelope_json"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_envelope_json() -> str:
    repo = _repo_root()
    bootstrap = repo / "examples" / "a2a_identity_agent" / "bootstrap_envelope.py"
    env = os.environ.copy()
    src = str(repo / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(bootstrap)],
        cwd=str(repo),
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return proc.stdout.strip()


async def main() -> None:
    base_url = os.environ.get(
        "A2A_DEMO_BASE_URL",
        "http://127.0.0.1:9999",
    )
    envelope_json = _load_envelope_json()
    json.loads(envelope_json)

    async with httpx.AsyncClient() as httpx_client:
        resolver = A2ACardResolver(httpx_client=httpx_client, base_url=base_url)
        card = await resolver.get_agent_card()

    config = ClientConfig(streaming=False)
    client = await create_client(agent=card, client_config=config)

    msg = new_text_message("Hello from the A2A client.")
    req = SendMessageRequest()
    req.message.CopyFrom(msg)
    req.metadata[METADATA_ENVELOPE_JSON] = envelope_json

    print("Sending message with identity metadata…")
    async for chunk in client.send_message(req):
        print(chunk)

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
