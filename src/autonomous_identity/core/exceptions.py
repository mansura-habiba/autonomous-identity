class AutonomousIdentityError(Exception):
    """Base error for the library."""


class ValidationError(AutonomousIdentityError):
    """Envelope or context failed identity property validation."""


class VerificationError(AutonomousIdentityError):
    """Cryptographic or chain verification failed."""


class LifecycleError(AutonomousIdentityError):
    """Identity is not valid for action (revoked, suspended, etc.)."""


class AdapterNotFoundError(AutonomousIdentityError):
    """Requested identity adapter is not registered."""
