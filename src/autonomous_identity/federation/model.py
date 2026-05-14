from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class JurisdictionPolicy:
    allowed_regions: list[str] = field(default_factory=list)
    denied_regions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RevocationPolicy:
    revoked_subjects: list[str] = field(default_factory=list)
    revoked_delegation_ids: list[str] = field(default_factory=list)
    revoked_kids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TrustedDomainPolicy:
    trust_domain: str
    jwks: dict[str, Any]
    status: str = "active"
    allowed_audiences: list[str] = field(default_factory=list)
    scope_mappings: dict[str, str] = field(default_factory=dict)
    allowed_target_scopes: list[str] = field(default_factory=list)
    max_ttl_seconds: int | None = None
    jurisdiction: JurisdictionPolicy = field(default_factory=JurisdictionPolicy)
    revocation: RevocationPolicy = field(default_factory=RevocationPolicy)


@dataclass(frozen=True)
class FederationPolicy:
    receiver_trust_domain: str
    trusted_domains: dict[str, TrustedDomainPolicy]


@dataclass(frozen=True)
class FederationCheck:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class FederationDecision:
    allowed: bool
    reason: str
    source_trust_domain: str | None
    receiver_trust_domain: str
    subject: str
    audience: str | None
    requested_scope: str | None
    mapped_scope: str | None
    checks: list[FederationCheck]