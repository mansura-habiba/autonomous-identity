from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from autonomous_identity.adapters.spiffe import (
    _jws_verify,
    _jwks_lookup,
    parse_spiffe_id,
)
from autonomous_identity.core.delegation_util import effective_scopes_for_actor
from autonomous_identity.core.envelope import IdentityEnvelope

from .model import (
    FederationCheck,
    FederationDecision,
    FederationPolicy,
    TrustedDomainPolicy,
)


class FederationAuthorityVerifier:
    def __init__(self, policy: FederationPolicy) -> None:
        self.policy = policy

    def verify(
        self,
        envelope: IdentityEnvelope,
        *,
        requested_scope: str | None = None,
        audience: str | None = None,
        action_region: str | None = None,
    ) -> FederationDecision:
        checks: list[FederationCheck] = []
        mapped_scope: str | None = None
        source_td: str | None = None

        def add(name: str, passed: bool, detail: str) -> bool:
            checks.append(FederationCheck(name=name, passed=passed, detail=detail))
            return passed

        subject = envelope.system_identifier

        try:
            subject_td, _ = parse_spiffe_id(subject)
            add("subject_spiffe_parse", True, f"subject trust domain is {subject_td}")
        except Exception as exc:
            add("subject_spiffe_parse", False, str(exc))
            return self._decision(False, "invalid subject SPIFFE ID", None, subject, audience, requested_scope, None, checks)

        add(
            "receiver_domain_match",
            subject_td == self.policy.receiver_trust_domain,
            f"subject_td={subject_td}, receiver_td={self.policy.receiver_trust_domain}",
        )

        crossing = self._find_cross_domain_delegation(envelope)
        if crossing is None:
            add("cross_domain_delegation", False, "no cross-domain delegation edge found")
            return self._decision(False, "missing cross-domain delegation", None, subject, audience, requested_scope, None, checks)

        parent_td, _ = parse_spiffe_id(crossing.parent_subject)
        child_td, _ = parse_spiffe_id(crossing.child_subject)
        source_td = parent_td

        add(
            "delegation_enters_receiver",
            child_td == self.policy.receiver_trust_domain,
            f"parent_td={parent_td}, child_td={child_td}",
        )

        add(
            "federation_caveat",
            bool(crossing.caveats.get("spiffe.federation")),
            "delegation must include spiffe.federation=true",
        )

        domain_policy = self.policy.trusted_domains.get(source_td)
        if not domain_policy:
            add("source_domain_trusted", False, f"{source_td} is not configured")
            return self._decision(False, "source domain not trusted", source_td, subject, audience, requested_scope, None, checks)

        add("source_domain_trusted", True, f"{source_td} is configured")
        add("source_domain_active", domain_policy.status == "active", f"status={domain_policy.status}")

        self._verify_svid(envelope, domain_policy, checks, add)

        if audience is not None:
            add(
                "audience_allowed",
                audience in domain_policy.allowed_audiences,
                f"audience={audience}",
            )

        if requested_scope is not None:
            mapped_scope = domain_policy.scope_mappings.get(requested_scope)
            add(
                "scope_mapping_exists",
                mapped_scope is not None,
                f"{requested_scope} -> {mapped_scope}",
            )
            if mapped_scope is not None:
                add(
                    "mapped_scope_allowed",
                    mapped_scope in domain_policy.allowed_target_scopes,
                    f"mapped_scope={mapped_scope}",
                )
                effective = effective_scopes_for_actor(envelope)
                add(
                    "scope_attenuation",
                    mapped_scope in effective or requested_scope in effective,
                    f"effective_scopes={sorted(effective)}",
                )

        self._check_revocation(envelope, domain_policy, checks, add)
        self._check_jurisdiction(action_region, domain_policy, checks, add)
        self._check_ttl(envelope, domain_policy, checks, add)

        allowed = all(c.passed for c in checks)
        reason = "federated authority accepted" if allowed else "federated authority rejected"
        return self._decision(allowed, reason, source_td, subject, audience, requested_scope, mapped_scope, checks)

    def _verify_svid(self, envelope: IdentityEnvelope, domain_policy: TrustedDomainPolicy, checks, add) -> None:
        metadata = envelope.metadata or {}
        jws = metadata.get("spiffe.svid_jws")
        kid = metadata.get("spiffe.kid")

        if not add("svid_present", bool(jws), "spiffe.svid_jws must be present"):
            return

        if not add("kid_present", bool(kid), "spiffe.kid must be present"):
            return

        try:
            public_key = _jwks_lookup(domain_policy.jwks, kid)
            add("trusted_kid_lookup", True, f"kid={kid}")
        except Exception as exc:
            add("trusted_kid_lookup", False, str(exc))
            return

        try:
            payload = _jws_verify(jws, public_key)
            add("svid_signature", True, "SVID signature verified")
        except Exception as exc:
            add("svid_signature", False, str(exc))
            return

        add(
            "svid_subject_match",
            payload.get("sub") == envelope.system_identifier,
            f"payload.sub={payload.get('sub')}",
        )

        exp = payload.get("exp")
        now = int(datetime.now(timezone.utc).timestamp())
        add(
            "svid_not_expired",
            isinstance(exp, int) and exp > now,
            f"exp={exp}, now={now}",
        )

    def _check_revocation(self, envelope, domain_policy, checks, add) -> None:
        metadata = envelope.metadata or {}
        kid = metadata.get("spiffe.kid")
        add(
            "subject_not_revoked",
            envelope.system_identifier not in domain_policy.revocation.revoked_subjects,
            f"subject={envelope.system_identifier}",
        )
        if kid:
            add(
                "kid_not_revoked",
                kid not in domain_policy.revocation.revoked_kids,
                f"kid={kid}",
            )

    def _check_jurisdiction(self, action_region, domain_policy, checks, add) -> None:
        if action_region is None:
            add("jurisdiction_not_evaluated", True, "no action_region supplied")
            return

        denied = domain_policy.jurisdiction.denied_regions
        allowed = domain_policy.jurisdiction.allowed_regions

        add(
            "region_not_denied",
            action_region not in denied,
            f"action_region={action_region}",
        )
        if allowed:
            add(
                "region_allowed",
                action_region in allowed,
                f"action_region={action_region}, allowed={allowed}",
            )

    def _check_ttl(self, envelope, domain_policy, checks, add) -> None:
        if domain_policy.max_ttl_seconds is None:
            add("federation_ttl_not_evaluated", True, "no max_ttl_seconds configured")
            return

        metadata = envelope.metadata or {}
        iat = metadata.get("spiffe.svid_iat")
        exp = metadata.get("spiffe.svid_exp")

        if not isinstance(iat, int) or not isinstance(exp, int):
            add("federation_ttl", False, "missing numeric SVID iat/exp")
            return

        add(
            "federation_ttl",
            (exp - iat) <= domain_policy.max_ttl_seconds,
            f"ttl={exp - iat}, max={domain_policy.max_ttl_seconds}",
        )

    @staticmethod
    def _find_cross_domain_delegation(envelope: IdentityEnvelope):
        for delegation in reversed(envelope.delegations or []):
            try:
                parent_td, _ = parse_spiffe_id(delegation.parent_subject)
                child_td, _ = parse_spiffe_id(delegation.child_subject)
            except Exception:
                continue
            if parent_td != child_td:
                return delegation
        return None

    def _decision(
        self,
        allowed: bool,
        reason: str,
        source_td: str | None,
        subject: str,
        audience: str | None,
        requested_scope: str | None,
        mapped_scope: str | None,
        checks: list[FederationCheck],
    ) -> FederationDecision:
        return FederationDecision(
            allowed=allowed,
            reason=reason,
            source_trust_domain=source_td,
            receiver_trust_domain=self.policy.receiver_trust_domain,
            subject=subject,
            audience=audience,
            requested_scope=requested_scope,
            mapped_scope=mapped_scope,
            checks=checks,
        )