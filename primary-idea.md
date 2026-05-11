An autonomous system is not merely a model. It is not merely a workflow. It is not merely software that calls itself a tool. An autonomous system is a computational system that can interpret context, select among possible courses of action, and cause effects without a human specifying every intermediate step. That definition is deliberately broader than “AI agent.” Therefore, the identity architecture must attach not to the model, but to the operational system that can act. An autonomous system identity has at least seven characteristics as follows:
1.	Persistent: The system must have a stable identity across actions, sessions, restarts, and execution environments. The autonomous system has a durable identifier that distinguishes it from other autonomous systems. Without persistence, there is no actor. There are only disconnected executions.
2.	Addressable: The system must be independently referable and addressable as a subject. Other systems, policies, logs, humans, and governance processes must be able to point to it. Identity can be managed through policy, audit, delegation, revocation, and incident response. For example: “agent://tenant-42/procurement/vendor-evaluator”, “spiffe://company.internal/agents/finance/refund-reviewer”. A non-addressable system cannot be governed. It cannot be granted authority cleanly, constrained cleanly, revoked cleanly, or investigated cleanly.
3.	Verifiable: The identity is cryptographically verifiable when used. The chain back to the human principal must be cryptographically verifiable at the moment of exercise. Verifying a system just at the beginning of the session is not enough. An autonomous system that says “I am the finance agent” has not established identity. An autonomous system that proves possession of the finance-agent signing key, under an accepted attestation chain, has.
4.	Attenuable: Every autonomous system identity is anchored to a human, organization, department, developer, operator, or legal entity responsible for its creation, deployment, and authority.  This does not mean the human approves every action. It means the system’s existence and delegated role are attributable. An identity without an accountable owner is an orphaned actor. Orphaned actors are unacceptable in high-consequence environments because no one can answer who authorized them, who maintains them, who can suspend them, or who bears responsibility when they fail. Each hop in the delegation chain may narrow authority, but never expand it. The downstream agent receives at most as much as the upstream agent received. The contract is monotone-decreasing. No agent produces authority. It can only attenuate authority it already received.
5.	Instance-specific: The identity must distinguish not only the class of system, but also the concrete runtime instance when necessary. For example, “Finance assistant” is too broad. “Finance assistant instance 7, running in production, under deployment hash X, in region Y” is governable. This matters because multiple instances may run the same code. One may be compromised. One may be outdated. One may be operating under a different policy bundle. One may be a test instance that should never touch production data.
6.	Provenance-aware: The identity is bound to provenance information about code, model, configuration, policy version, deployment environment, and attestation root. This does not mean every action log must include the full software bill of materials. But the identity must be traceable to the system artefacts that produced the action. A serious identity must answer:
•	Which system was this?
•	Which version?
•	Built from what?
•	Deployed by whom?
•	Running where?
•	Under which policy bundle?
•	Using which model or decision component?
7.	Lifecycle-controlled: The identity can be disabled or invalidated independently of the code that uses it. It must be possible to create, activate, suspend, rotate, constrain, migrate, and retire it. This is essential. An autonomous system may continue to exist after its authority should have ended.
8. Auditable: Actions taken by the autonomous system can be linked back to the system identity, runtime instance, owner, and verification chain. Auditability does not require exposing private reasoning traces. It requires operational attribution.
The envelope for identity is the portable proof of what that principal may do, on whose authority, against which evidence, and under which constraints.  The table below explains the envelope for the identity of any autonomous system:
Table 8.1: Identity envelope must travel with every material action
Field	What it answers	Concrete content
system identifier	What autonomous system is this?	Stable autonomous-system ID, such as SPIFFE ID, workload identity, service principal, or agent URI
runtime instance	Which execution acted?	Instance ID, deployment ID, region, environment, container/workload attestation, start time
owner binding	Who is responsible for this system?	Human, team, department, tenant, organization, controller, or legal entity mapped to the system identity
attestation chain	How do we know this system is genuine?	Signed chain from hardware, workload, service mesh, deployment controller, or identity provider
provenance reference	What produced this system?	Hashes or references for code version, model version, configuration, policy bundle, build artefact, and deployment manifest
lifecycle state	Is this identity still valid?	Active, restricted, suspended, revoked, retired; checked at time of action
timestamp	When was this identity asserted?	Issued-at time and action-time verification time
audit reference	Where is the evidence recorded?	Append-only log pointer, event ID, trace ID, ledger hash, or signed audit receipt
signature chain	Who signed this identity claim?	Detached signatures from the identity provider, deployment authority, attestation service, or HSM-backed key

Every action that changes state, reads sensitive data, invokes a privileged tool, makes a decision, or delegates work must carry an identity envelope. An autonomous system that was valid at 14:07:33 is not necessarily valid at 14:07:34. Between those two timestamps, the system identity may have been suspended, its deployment may have been revoked, its attestation may have expired, its policy bundle may have changed, or its owner may have removed it from service. So, identity is therefore not a property of the session; it is a property of the moment of exercise. 
Also, this envelope is not a JWT, as JWTs are flat, and it claims to live in a single signed blob. However, the delegation for the autonomous system is not flat, and identity is often canonical. We need a mechanism to implement identity that covers the eight properties described earlier in this section.  No single primitive satisfies all eight perfectly. Each construction is strong in some dimensions and weak in others. The right implementation depends on the shape of the autonomous system: linear or graph-based, single-principal or multi-principal, private or cross-domain, low-risk or high-blast-radius.
Table 8.2: Different implementations for identity
Implementation	Persistent	Addressable	Verifiable	Owner-bound	Instance-specific	Provenance-aware	Lifecycle-controlled	Auditable
Merkle chain	Strong	Strong	Strong	Strong	Strong	Strong	Medium	Strong
Merkle DAG / hashgraph	Strong	Strong	Strong	Strong	Strong	Very strong	Medium	Very strong
Verifiable Credentials + DIDs	Strong	Strong	Strong	Strong	Medium	Strong	Medium	Strong
SPIFFE/SPIRE SVIDs	Strong	Strong	Strong	Medium	Strong	Medium	Strong	Medium
Macaroons / Biscuits	Medium	Medium	Strong	Medium	Medium	Medium	Medium	Medium
Nested JWS / COSE_Sign envelopes	Strong	Strong	Strong	Strong	Strong	Medium	Medium	Strong
in-toto / SLSA attestations	Medium	Medium	Strong	Medium	Medium	Very strong	Weak	Very strong
Hardware-rooted attestation	Medium	Medium	Very strong	Medium	Very strong	Strong	Medium	Strong
Threshold / BLS signatures	Strong	Strong	Strong	Strong	Medium	Medium	Medium	Medium

A Merkle chain is the simplest serious identity-envelope construction. Each identity assertion becomes a signed node. Each node commits to the previous node by hash. If any earlier node is modified, every downstream hash breaks. This gives a clean, tamper-evident identity history.
Use a Merkle chain when the autonomous system has a mostly linear identity lineage:
human principal
  → organization identity authority
    → deployment controller
      → runtime attestor
        → autonomous system instance
          → action
Merkle chains are strong for persistence, addressability, verification, owner binding, instance specificity, provenance, and audit. Their weakness is topology. They assume one parent per node. If an agent action is jointly produced by a user, an orchestrator, a policy engine, a retrieval gate, and a runtime attestor, a linear chain forces that graph into a sequence. That flattening loses useful structure.
A Merkle DAG generalizes the Merkle chain. Instead of one parent per node, each node can commit to multiple parents. This is often a better fit for autonomous systems because agent identity is rarely linear. An action may depend simultaneously on a user delegation, a policy-engine decision, a runtime attestation, a retrieval snapshot, and an orchestrator instruction.
Use a Merkle DAG when agents fork, merge, spawn child agents, or act from several parent contexts at once:
user delegation ─────────────┐
policy-engine approval ──────┼── agent action
runtime attestation ─────────┘
Merkle DAGs are especially strong for provenance and audit because they preserve the real dependency graph. Their main weakness is lifecycle control. A DAG can prove that a node existed and was not tampered with, but it does not by itself prove that the identity is still active. The verifier still needs a lifecycle registry, revocation ledger, or freshness proof at action time.
DIDs provide stable identifiers. Verifiable Credentials provide signed claims about those identifiers. In an autonomous-system identity envelope, the agent may have a DID as its durable subject, while different authorities issue credentials about it: ownership, deployment approval, model version, policy scope, runtime environment, or tenant membership.
This works well when identity is assembled from multiple issuers:
DID: did:example:finance-refund-agent-7

Credentials:
- issued by organization: belongs to Finance Operations
- issued by deployment controller: running approved deployment
- issued by model registry: using approved model version
- issued by runtime attestor: active in eu-west-1
- issued by lifecycle registry: not suspended
VCs and DIDs are strong for persistence, addressability, verifiability, owner binding, provenance, and cross-domain composition. Their weakness is freshness. A credential can be cryptographically valid but operationally stale. The verifier must check expiry, credential status, lifecycle state, and revocation at the moment of action. Otherwise the system has documentary identity, not live identity.
SPIFFE/SPIRE provides production-grade workload identity. An SVID binds a cryptographic identity to a workload. For autonomous systems running in cloud, Kubernetes, service meshes, or microservice environments, each agent instance can be treated as a workload with its own SPIFFE ID. For example: spiffe://example.com/agents/finance/refund-reviewer/prod/eu-west-1
SPIFFE is strong for addressable, verifiable, instance-specific runtime identity. It also supports lifecycle control through short-lived credentials and automated rotation. Its limitation is that it proves workload identity, not the full autonomous-system identity story. By itself, SPIFFE does not prove the model version, policy bundle, build provenance, owner chain, user delegation, or retrieval evidence. It is best used as the runtime identity substrate, combined with provenance attestations and action-level audit.
Macaroons and Biscuits are attenuating token systems. Strictly speaking, they are closer to capability delegation than pure identity. But they matter for identity because autonomous systems often spawn child agents or delegate work to sub-agents. Each hop must be able to narrow what the downstream actor can do.
A parent may delegate like this:
root:
  subject = finance-refund-agent
  scope = refund workflows

child caveat:
  only issue-refund-up-to-100-eur

grandchild caveat:
  only for invoice hash H
  only before 14:30
  only when invoked by trace ID abc123
Their strength is verifiable attenuation. No child can expand the parent’s authority; it can only add caveats. Their weakness is that they are not full identity envelopes. They do not naturally provide owner binding, runtime provenance, lifecycle state, or instance-specific attestation unless those are added as caveats or external checks. Use them for the delegation layer, not as the whole identity architecture.
Nested JWS or COSE_Sign envelopes implement identity as a stack of signed wrappers. Each layer signs the previous layer or wraps it with additional claims. This creates a readable sequence of identity assertions. For example:
model provider signs model/runtime claim
  → runtime attestor signs execution claim
    → deployment controller signs deployment claim
      → orchestrator signs invocation claim
        → action service signs action claim
This is pragmatic and inspectable. It works well when the system is mostly linear and the organization already has signing infrastructure. It is strong for verification, owner binding, instance specificity, and audit. Its weakness is structural. Like a Merkle chain, it becomes awkward when identity is graph-shaped. It can represent layers well; it does not naturally represent multiple simultaneous parents without flattening them into one signed blob.
in-toto and SLSA-style attestations bring supply-chain provenance into the identity envelope. They answer questions such as: what code was built, by which process, from which source, under which policy, and with which artefact hashes? For autonomous systems, that matters because “who acted?” is incomplete unless the verifier can also know what produced the actor.
A provenance-aware identity needs to commit to:
code hash
model hash
configuration hash
policy bundle hash
deployment manifest hash
tooling version
build pipeline identity
in-toto and SLSA are very strong for provenance and audit. They are not, by themselves, runtime identity systems. A build attestation can prove how an artefact was produced, but not necessarily which live instance acted, whether that instance was still active, or who delegated authority to it. Use them as the provenance layer inside the identity envelope, not as the whole envelope.
Hardware-rooted attestation anchors identity in a measured execution environment. Instead of trusting a key stored on disk, the verifier receives evidence that the agent ran inside a particular measured runtime, enclave, VM, host, or trusted execution environment. The claim is:
This autonomous system instance ran in this measured environment,
on this hardware-backed root,
with this runtime measurement,
at this time.
This is very strong for verifiability and instance specificity. It is especially useful when host compromise is in scope, or when the system performs high-value actions. Its weakness is that hardware attestation is not ownership, delegation, lifecycle, or policy by itself. It proves the measured environment. It does not prove who owns the agent, whether it should be allowed to act, whether its authority was revoked, or whether the policy bundle was appropriate unless those are bound into the measurement or envelope.
Threshold signatures require a quorum of principals to assert an identity or approve a high-consequence action. BLS aggregation can compress many signatures into a single aggregate proof, which is useful at scale. This fits actions where no single agent or service should be able to act alone:
user agent signs
policy agent signs
risk engine signs
orchestrator signs

valid only if 3 of 4 signatures are present
Threshold signatures are strong for verification, owner binding, and multi-party control. They are useful when the identity claim is not “this one actor acted,” but “this action was co-asserted by the required quorum.” Their weakness is audit opacity. If aggregation hides which parties signed, accountability suffers. A serious design must preserve signer identities, membership state, and lifecycle validity of each signer, even if the cryptographic proof is compact.
