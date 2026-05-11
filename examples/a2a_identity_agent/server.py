"""HTTP JSON-RPC A2A server (same wiring style as ``a2a-samples`` ``helloworld`` / ``a2a-mcp-without-framework``).

Run::

    uv run python examples/a2a_identity_agent/server.py --host 127.0.0.1 --port 9999

Then in another shell::

    uv run python examples/a2a_identity_agent/demo_client.py
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def _demo_data_dir() -> Path:
    """Same store as ``bootstrap_envelope`` / ``demo_client`` regardless of process cwd."""
    override = os.environ.get("ASID_A2A_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / ".asid-a2a-demo"

import a2a_upb_compat

a2a_upb_compat.apply()

import uvicorn
from starlette.applications import Starlette

from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentSkill

from autonomous_identity import AutonomousIdentity, ValidatorStrictness

from agent_executor import IdentityEchoA2AExecutor


def _build_app(*, host: str, port: int) -> Starlette:
    skill = AgentSkill(
        id="identity_echo",
        name="Echo with autonomous-identity envelope",
        description=(
            "Requires SendMessageRequest.metadata['autonomous_identity.envelope_json'] "
            "with a serialized IdentityEnvelope; runs one audited material action."
        ),
        tags=["identity", "a2a"],
        examples=["hello"],
    )

    url = f"http://{host}:{port}/"
    agent_card = AgentCard(
        name="Autonomous Identity A2A demo",
        description="Google A2A sample shape + autonomous-identity envelope on each request.",
        supported_interfaces=[
            AgentInterface(
                protocol_binding="JSONRPC",
                url=url,
            )
        ],
        version="0.1.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[skill],
    )

    identity = AutonomousIdentity.local(_demo_data_dir(), strictness=ValidatorStrictness.STRICT)
    handler = DefaultRequestHandler(
        agent_executor=IdentityEchoA2AExecutor(identity),
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )

    routes: list = []
    routes.extend(create_agent_card_routes(agent_card))
    routes.extend(create_jsonrpc_routes(handler, rpc_url="/"))
    return Starlette(routes=routes)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9999)
    args = p.parse_args()
    app = _build_app(host=args.host, port=args.port)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
