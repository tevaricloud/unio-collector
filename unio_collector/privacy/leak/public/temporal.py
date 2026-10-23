"""Identity-bound temporal roles, never a date-shaped customer-value exemption."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, Self

from unio_collector.collector.bundle.schema import COLLECTION_MODE, PROTECTED_BUNDLE_SCHEMA_VERSION
from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.producer_fields import producer_category, unknown_producer_paths
from unio_collector.privacy.tokens import is_protected_token

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract

MONTH_PRECISION_LENGTH = 7

_OPERATIONAL = {
    "manifest.json": frozenset({"$.generated_at", "$.evidence_generated_at"}),
    "collection-summary.json": frozenset({"$.generated_at"}),
    "permissions-summary.json": frozenset({"$.generated_at"}),
    "scan-result/report-bundle.json": frozenset({"$.generated_at"}),
}


@dataclass(frozen=True)
class TemporalScanPolicy:
    """Carry immutable ownership through the existing structural scan traversal."""

    member: str
    root_owned: bool
    generated_tokens: frozenset[str]
    row_owned: bool = True

    @classmethod
    def create(cls, member: str, value: object, generated_tokens: frozenset[str]) -> Self:
        """Admit actual protocol roots, not arbitrary timestamp-looking strings."""
        owned = isinstance(value, dict) and cls._owned_root(member, value, generated_tokens)
        return cls(member, owned, generated_tokens, member != "permissions/degradation-records.json")

    def for_container(self, path: str, value: dict[str, Any]) -> Self:
        """Keep each degradation row's provider/account identity independent."""
        if (self.member, path) != ("permissions/degradation-records.json", "$.records[]"):
            return self
        owned = (
            self.root_owned
            and value.get("schema_version") == "2026-07"
            and value.get("provider_id") == "aws"
            and self._account(value.get("account_id"), self.generated_tokens)
            and not unknown_producer_paths(value, self.member, path)
        )
        return replace(self, row_owned=owned)

    def is_value(self, path: str, value: object) -> bool:
        """Normalize only an explicitly declared, well-formed temporal value."""
        if not self.root_owned or not self.row_owned:
            return False
        declared = path in _OPERATIONAL.get(self.member, ()) or producer_category(self.member, path) == "timestamp"
        return declared and self.timestamp(value)

    @staticmethod
    def payload_value(contract: ClosedProducerContract, suffix: str, value: object) -> bool:
        """Reuse the admitted producer's exact field/type/category declaration."""
        spec = contract.fields.get(suffix)

        typed_value = value + "-01" if isinstance(value, str) and len(value) == MONTH_PRECISION_LENGTH else value
        return spec is not None and spec[1] == "timestamp" and TemporalScanPolicy.timestamp(value) and not contract.unknown_paths(typed_value, "", suffix)

    @staticmethod
    def timestamp(value: object) -> bool:
        """Accept supported ISO timestamps/dates and strict month precision."""
        if not isinstance(value, str) or not value:
            return False
        try:
            datetime.fromisoformat(value + "-01" if len(value) == MONTH_PRECISION_LENGTH else value)
        except (ValueError, OverflowError):
            return False
        return True

    @staticmethod
    def _account(value: object, generated_tokens: frozenset[str]) -> bool:
        return isinstance(value, str) and value.startswith("ACCOUNT-") and is_protected_token(value) and value in generated_tokens

    @staticmethod
    def _aws_root(member: str, value: dict[str, Any]) -> bool:
        if value.get("provider_id", "aws") != "aws":
            return False

        if member != "scan-result/pricing-context.json" and value.get("provider", "aws") != "aws":
            return False
        context = value.get("account_context", {})
        source = value.get("source", {})
        return isinstance(context, dict) and context.get("provider", "aws") == "aws" and isinstance(source, dict) and source.get("provider_id", "aws") == "aws"

    @classmethod
    def _owned_root(cls, member: str, value: dict[str, Any], tokens: frozenset[str]) -> bool:
        if not cls._aws_root(member, value):
            return False
        context = value.get("account_context", {})
        account = value.get("account_id", context.get("account_id"))
        if member in {"account-scope.json", "permissions-summary.json", "scan-result/report-bundle.json"}:
            return cls._account(account, tokens)
        if member == "manifest.json":
            return (
                cls._account(account, tokens)
                and value.get("bundle_schema_version") == PROTECTED_BUNDLE_SCHEMA_VERSION
                and value.get("collection_mode") == COLLECTION_MODE
            )
        if member == "collection-summary.json":
            return (
                isinstance(value.get("collection_status"), str)
                and value["collection_status"] in {"complete", "partial", "failed", "cancelled"}
                and all(type(value.get(key)) is int and value[key] >= 0 for key in ("scanner_count", "finding_count", "evidence_count"))
            )
        if member == "permissions/degradation-records.json":
            return value.get("schema_version") == "2026-07" and isinstance(value.get("records"), list)
        if member == "collection-log.jsonl":
            return cls._ledger(value) and not unknown_producer_paths(value, member, "$")
        if member == "scan-result/pricing-context.json":
            return value.get("schema_version") == "2026-01" and isinstance(value.get("provider"), str) and isinstance(value.get("usage_records"), list)
        return False

    @staticmethod
    def _ledger(value: dict[str, Any]) -> bool:
        envelope = value.get(UNIO_PROTOCOL.namespace)
        return (
            value.get("eventVersion") == UNIO_PROTOCOL.identifier("1")
            and value.get("eventType") == "AwsApiCall"
            and isinstance(envelope, dict)
            and envelope.get("local_only_audit_record") is True
            and envelope.get("authoritative_cloudtrail") is False
            and envelope.get("credential_material_returned") is False
        )
