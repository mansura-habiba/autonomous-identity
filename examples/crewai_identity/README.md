# CrewAI + autonomous-identity

A working CrewAI integration. Two scripts in this folder:

| File | Needs API key | What it proves |
|---|---|---|
| `crewai_identity_demo.py` | no | The identity gate fires on every CrewAI `BaseTool` call, rejects scopes the envelope didn't receive, and rejects calls after `revoke()`. Runnable end-to-end with no LLM. |
| `crewai_identity_with_crew.py` | yes | Same wrapping pattern handed to a real `Agent` and a `Crew`. The LLM drives the agent; the identity gate fires at every tool invocation regardless. |

## Install

```bash
pip install -e .          # the autonomous-identity library
pip install crewai        # 1.14+ confirmed working
```

## Demo (no API key)

```bash
python examples/crewai_identity/crewai_identity_demo.py
```

Expected output ends with `ALL CHECKS PASSED` and four sections:

1. **`web.read` ALLOWED** — envelope has the scope.
2. **`inbox.label` ALLOWED** — envelope has the scope.
3. **`email.send` REJECTED** — envelope never received this scope; the
   call fails at the moment of exercise with
   `VerificationError: Required scope 'email.send' not in effective scopes
   ['inbox.label', 'web.read']`.
4. **Post-revoke `web.read` REJECTED** — after `identity.revoke(...)` the
   previously-allowed scope also fails with `LifecycleError`. This proves
   the lifecycle check fires at action time, not session start.

Plus an audit-log dump showing 3 signed rows (one issuance + two allowed
actions). Rejected calls do not produce audit rows because they fail
before the action would have been recorded.

## Full crew (needs API key)

```bash
export OPENAI_API_KEY=sk-...        # or ANTHROPIC_API_KEY
python examples/crewai_identity/crewai_identity_with_crew.py
```

A real research-analyst agent is kicked off with two tools (`web_search`,
`summarise`). The LLM picks which tools to call and when; every tool call
goes through the identity gate. At the end the script dumps the audit log
so you can see which tools were actually invoked.

## The integration pattern, in 3 lines

```python
from autonomous_identity.integrations.runtime import IdentityRuntime
from crewai.tools import BaseTool

runtime = IdentityRuntime(identity, envelope)
safe_fn = runtime.wrap_tool(raw_fn, required_scope="web.read")

class MyTool(BaseTool):
    name: str = "my_tool"
    description: str = "..."
    def _run(self, *args, **kwargs):
        return safe_fn(*args, **kwargs)
```

Hand `MyTool()` to your CrewAI `Agent`. Wrap the whole `crew.kickoff()`
call in `with runtime:` so the envelope is active for the duration of
the run.

## Why this works

CrewAI's `BaseTool` is a Pydantic v2 model. The library's older
`wrap_tools_for_identity` helper tries to mutate `BaseTool.invoke`,
which Pydantic v2 rejects with
`ValueError: "StructuredTool" object has no field "invoke"`. The new
`IdentityRuntime.wrap_tool` returns a **new** callable instead of
mutating the original, so it works against any framework whose tool
classes are frozen / strict — including CrewAI, Pydantic AI, and recent
LangChain releases.
