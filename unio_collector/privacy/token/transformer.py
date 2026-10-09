"""Value token transformation with the existing canonicalisation and accounting."""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from unio_collector.privacy.canonicalization import canonicalize_value
from unio_collector.privacy.patterns import ACCOUNT_RE, ARN_PART_COUNT, ARN_RE, CIDR_RE, DNS_RE, EMAIL_RE, IP_RE, IPV4_VERSION, RESOURCE_RE

if TYPE_CHECKING:
    from unio_collector.privacy.registry import ClassificationSummary
    from unio_collector.privacy.tokens import TokenService


class PrivacyValueTokens:
    """Apply existing token semantics using one operation's service and summary."""

    def __init__(self, token_service: TokenService, summary: ClassificationSummary) -> None:
        """Share operation-owned token identity and counters without new state."""
        self._token_service = token_service
        self.summary = summary

    def sensitive_string(self, value: str, category: str) -> str:
        """Transform a classified identifier with existing ARN/IP/CIDR semantics."""
        if category == "arn_or_name":
            category = "arn" if value.startswith("arn:") else "resource_name"
        if category == "arn":
            return self._arn(value)
        if category == "cidr":
            return self._cidr(value)
        if category in {"ipv4", "ipv6"}:
            return self._ip(value)
        return self.tokenise(category, value)

    def embedded_values(self, value: str) -> str:
        """Replace recognized identifiers in legacy free-text handling."""
        result = CIDR_RE.sub(lambda match: self._cidr(match.group(0)), value)
        result = ARN_RE.sub(lambda match: self._arn(match.group(0)), result)
        result = EMAIL_RE.sub(lambda match: self.tokenise("email", match.group(0)), result)
        result = ACCOUNT_RE.sub(lambda match: self.tokenise("aws_account_id", match.group(0)), result)
        result = RESOURCE_RE.sub(lambda match: self.tokenise("resource_id", match.group(0)), result)
        result = IP_RE.sub(lambda match: self._ip(match.group(0)), result)
        return DNS_RE.sub(lambda match: self.tokenise("dns_name", match.group(0)), result)

    def _arn(self, value: str) -> str:
        parts = value.split(":", 5)
        if len(parts) != ARN_PART_COUNT or parts[0].lower() != "arn":
            return self.tokenise("arn", value)
        partition, service, region, account, resource = parts[1:]
        protected_account = self.tokenise("aws_account_id", account) if account else ""
        protected_resource = resource if service == "iam" and resource == "root" else self.tokenise("resource_id", resource) if resource else ""
        return f"arn:{partition}:{service}:{region}:{protected_account}:{protected_resource}"

    def _ip(self, value: str) -> str:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return self.tokenise("resource_id", value)
        return self.tokenise("ipv4" if parsed.version == IPV4_VERSION else "ipv6", str(parsed))

    def _cidr(self, value: str) -> str:
        try:
            parsed = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return self.tokenise("resource_id", value)
        return self.tokenise("cidr", str(parsed))

    def tokenise(self, category: str, value: object) -> str:
        """Canonicalize, obtain the stable token and record its category."""
        canonical = canonicalize_value(category, value)
        token = self._token_service.token_for(canonical, observed_value=value)
        self.summary.record_token(canonical.category)
        return token
