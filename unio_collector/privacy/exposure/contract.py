"""Identity-bound admission for actual exposure producers, without dynamic imports."""

from __future__ import annotations

from typing import Any, ClassVar

from unio_collector.privacy.audit.contract import AuditPrivacyContract
from unio_collector.privacy.exposure.fields import SCANNERS, VOCABULARIES

MAX_IP_PROTOCOL = 255
MAX_NETWORK_PORT = 65535


class ExposurePrivacyContract(AuditPrivacyContract):
    """Keep identifiers and diagnostics protected and reject every unknown shape."""

    identities: ClassVar = SCANNERS

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Accept only typed declared controls, including numeric IP protocol values."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "ingress_protocol":
            return isinstance(value, str) and (
                value in {"tcp", "udp", "icmp", "icmpv6", "-1"} or (value.isascii() and value.isdecimal() and 0 <= int(value) <= MAX_IP_PROTOCOL)
            )
        if kind == "port":
            return type(value) is int and -1 <= value <= MAX_NETWORK_PORT
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: Any, member: str, suffix: str = "") -> list[str]:  # noqa: ANN401
        """Tie optional service metadata keys to the record's actual resource kind."""
        failures = super().unknown_paths(value, member, suffix)
        if suffix in {"records[]", "global_records[]"} and isinstance(value, dict):
            keys = {
                "Application or Network Load Balancer": {"type"},
                "API Gateway REST API": {"endpoint_types"},
                "API Gateway HTTP/WebSocket API": {"protocol_type"},
                "CloudFront origin": {"distribution_id"},
            }
            metadata = value.get("metadata")
            if isinstance(metadata, dict):
                failures.extend(
                    member + self.prefix[1:] + "." + suffix + ".metadata." + key
                    for key in metadata
                    if key not in keys.get(str(value.get("resource_type")), set())
                )
        return failures

    def is_literal(self, suffix: str, value: str) -> bool:
        """Normalize only closed controls already validated at the exact field path."""
        spec = self.fields.get(suffix)
        return spec is not None and spec[1] == "safe_metadata" and self._valid(value, spec[0], nullable=spec[2])
