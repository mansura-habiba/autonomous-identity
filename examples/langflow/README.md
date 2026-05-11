# Langflow integration (optional)

Pin a **Langflow** version that matches your checkout (for example `/Users/mansurah/GitHub/langflow`).

1. Install Langflow and this library in the same environment.
2. Subclass the stock `AgentComponent` from `lfx.components.models_and_agents.agent`.
3. After `build_agent()` (or when assembling tools), call:

```python
from autonomous_identity import AutonomousIdentity
from autonomous_identity.integrations.langflow import wrap_tools_for_identity

identity = AutonomousIdentity.local(".asid-flow")
# inside your component, before returning the executor:
agent.tools = wrap_tools_for_identity(identity, list(agent.tools), required_scope="demo.scope")
```

4. Ensure flows that call tools run under `with identity.exercise(envelope):` (set envelope from your issuance step or a dedicated “identity bootstrap” node).

`wrap_tools_for_identity` lives in `autonomous_identity.integrations.langflow.wrap_tools` and only depends on **langchain-core** for `BaseTool` typing.
