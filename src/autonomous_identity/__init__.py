"""Autonomous identity: verifiable envelopes for material actions."""

from autonomous_identity.application.facade import AutonomousIdentity
from autonomous_identity.core.envelope import (
    Delegation,
    IdentityEnvelope,
    LifecycleState,
    OwnerBinding,
    ProvenanceReference,
    RuntimeInstance,
)
from autonomous_identity.core.exceptions import (
    AdapterNotFoundError,
    LifecycleError,
    ValidationError,
    VerificationError,
)
from autonomous_identity.core.validators import IdentityValidator, ValidatorStrictness
from autonomous_identity.adapters.registry import (
    get_adapter,
    list_adapters,
    register_adapter,
)

__all__ = [
    "AutonomousIdentity",
    "IdentityEnvelope",
    "LifecycleState",
    "OwnerBinding",
    "RuntimeInstance",
    "ProvenanceReference",
    "Delegation",
    "IdentityValidator",
    "ValidatorStrictness",
    "ValidationError",
    "VerificationError",
    "LifecycleError",
    "AdapterNotFoundError",
    "register_adapter",
    "get_adapter",
    "list_adapters",
]
