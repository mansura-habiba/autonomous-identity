"""A2A ``AgentExecutor`` that runs one **material action** under an ``IdentityEnvelope``.

The envelope is supplied by the **caller** on ``SendMessageRequest.metadata`` under
``autonomous_identity.envelope_json`` (JSON string from :func:`envelope_to_serializable`).
That matches how cross-agent flows work: the **parent** (or policy service) issues or
delegates an envelope and the A2A client attaches it to each ``sendMessage`` call.

This mirrors the structure of ``a2a-samples/samples/python/agents/helloworld`` but adds
``autonomous_identity`` exercise + audit around the agent reply.
"""

from __future__ import annotations

import json

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import Message, Part, Role, Task, TaskState, TaskStatus
from a2a.utils.errors import InternalError, UnsupportedOperationError

from autonomous_identity.application.facade import AutonomousIdentity
from autonomous_identity.core.exceptions import VerificationError
from autonomous_identity.core.serialize import envelope_from_serializable
from autonomous_identity.core.validators import IdentityValidator, ValidatorStrictness

# SendMessageRequest.metadata key (string map in protobuf).
METADATA_ENVELOPE_JSON = "autonomous_identity.envelope_json"


def _agent_text_message(text: str, *, context_id: str, task_id: str) -> Message:
    m = Message()
    m.role = Role.ROLE_AGENT
    m.context_id = context_id
    m.task_id = task_id
    m.parts.append(Part(text=text))
    return m


class IdentityEchoA2AExecutor(AgentExecutor):
    """Validate envelope from metadata, ``exercise``, run a single audited action."""

    def __init__(self, identity: AutonomousIdentity) -> None:
        self._identity = identity
        self._validator = IdentityValidator(strictness=ValidatorStrictness.STRICT)

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        # DefaultRequestHandlerV2 + ActiveTask may run execute before a Task is loaded
        # into ``current_task``; identifiers still live on ``RequestContext`` / the message.
        task_id = context.task_id or (context.message.task_id if context.message else "")
        if not task_id:
            raise InternalError(message="missing task_id on RequestContext")
        context_id = context.context_id or (
            context.message.context_id if context.message else ""
        ) or ""

        # DefaultRequestHandlerV2 requires a ``Task`` before any ``TaskStatusUpdateEvent``
        # (see ``AgentExecutor`` docstring: enqueue Task, then status/artifact events).
        initial = Task(
            id=task_id,
            context_id=context_id,
            status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
        )
        if context.message:
            user_msg = Message()
            user_msg.CopyFrom(context.message)
            initial.history.append(user_msg)
        await event_queue.enqueue_event(initial)

        updater = TaskUpdater(event_queue, task_id, context_id)

        await updater.start_work(message=None)

        raw = context.metadata.get(METADATA_ENVELOPE_JSON)
        if not raw:
            await updater.failed(
                message=_agent_text_message(
                    f"Missing metadata {METADATA_ENVELOPE_JSON!r}. "
                    "Generate JSON with: uv run python examples/a2a_identity_agent/bootstrap_envelope.py",
                    context_id=context_id,
                    task_id=task_id,
                )
            )
            return

        try:
            payload = json.loads(raw) if isinstance(raw, str) else raw
            if not isinstance(payload, dict):
                raise TypeError("envelope JSON must decode to an object")
            envelope = envelope_from_serializable(payload)
            self._validator.validate(envelope)
            if not self._identity._adapter.verify(envelope):
                raise VerificationError("envelope failed cryptographic verification")
        except Exception as e:
            await updater.failed(
                message=_agent_text_message(str(e), context_id=context_id, task_id=task_id)
            )
            return

        user_text = context.get_user_input() or ""

        with self._identity.exercise(envelope):
            proof = self._identity.run_material_action(
                envelope,
                action_type="a2a.echo_greeting",
                required_scope=None,
                fn=lambda: (
                    f"actor={envelope.system_identifier!r} greeting user input: {user_text!r}"
                ),
                args=(),
                kwargs={},
            )

        reply = str(proof["result"])
        audit_ref = str(proof.get("audit_ref") or "")

        await updater.add_artifact(
            [Part(text=reply)],
            name="greeting",
            metadata={"audit_ref": audit_ref, "system_identifier": envelope.system_identifier},
        )
        await updater.complete()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise UnsupportedOperationError(message="cancel is not implemented in this demo")
