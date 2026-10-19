"""Closed privacy contract for factual, versioned service-quota collection."""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, ClassVar, Self

if TYPE_CHECKING:
    from unio_collector.privacy.treatment_decision import PrivacyTreatmentDecision
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.s3.fields import fields
from unio_collector.scanners.scanner.schema import admit_evidence_schema

CHECKS = {
    "ec2-elastic-ips-per-region": ("Amazon EC2", "Elastic IP address", "ec2_describe_addresses_count", "ec2:DescribeAddresses count"),
    "vpc-vpcs-per-region": ("Amazon VPC", "VPC", "ec2_describe_vpcs_count", "ec2:DescribeVpcs count"),
    "vpc-security-groups-per-region": ("Amazon VPC", "Security group", "ec2_describe_security_groups_count", "ec2:DescribeSecurityGroups count"),
    "vpc-nat-gateways-per-az": (
        "Amazon VPC",
        "NAT gateway",
        "ec2_describe_nat_gateways_max_per_az",
        "ec2:DescribeNatGateways max active count per Availability Zone",
    ),
    "elb-application-load-balancers-per-region": (
        "Elastic Load Balancing",
        "Application Load Balancer",
        "elbv2_describe_load_balancers_application_count",
        "elbv2:DescribeLoadBalancers application count",
    ),
    "elb-network-load-balancers-per-region": (
        "Elastic Load Balancing",
        "Network Load Balancer",
        "elbv2_describe_load_balancers_network_count",
        "elbv2:DescribeLoadBalancers network count",
    ),
}
VOCABULARIES = {
    "check": set(CHECKS),
    "service": {v[0] for v in CHECKS.values()},
    "resource": {v[1] for v in CHECKS.values()},
    "method": {method for v in CHECKS.values() for method in v[2:]},
    "confidence": {"high", "medium", "low"},
    "status": {"completed", "completed_with_warnings"},
}
FIELDS = {
    "": ("object", "safe_metadata", False),
    **fields("account_id", "string", "aws_account_id"),
    **fields("collection_evidence_version", "version"),
    **fields("status", "status"),
    **fields("threshold", "threshold", "summary_count", nullable=True),
    **fields("supported_check_count attempted_record_count expected_record_count unavailable_record_count", "count", "summary_count"),
    **fields("selected_regions quota_records warnings limitations", "array"),
    **fields("selected_regions[] quota_records[].region", "string", "region"),
    **fields("warnings[] limitations[]", "string", "free_text"),
    **fields("quota_records[].limitation", "string", "free_text", nullable=True),
    **fields("period quota_records[]", "object"),
    **fields("period.start_date period.end_date", "date", "timestamp"),
    **fields("period.total_cost", "money", "cost"),
    **fields("period.currency", "string", "cost"),
    **fields("quota_records[].check_id", "check"),
    **fields("quota_records[].service", "service"),
    **fields("quota_records[].resource_type", "resource"),
    **fields("quota_records[].confidence", "confidence"),
    **fields("quota_records[].resource_count_method", "method"),
    **fields("quota_records[].quota_name", "string", "resource_name"),
    **fields("quota_records[].quota_code", "string", "resource_id", nullable=True),
    **fields("quota_records[].quota_value", "quantity", "summary_count", nullable=True),
    **fields("quota_records[].quota_found", "boolean"),
    **fields("quota_records[].current_usage", "count", "summary_count", nullable=True),
}


class QuotaPrivacyContract(ClosedProducerContract):
    """Bind exact builtin dictionary identity; do not admit interpreted legacy DTOs."""

    scanner_id: ClassVar[str] = "service-quota-proximity-review"
    fields: ClassVar = FIELDS

    @classmethod
    def for_record(cls, record: dict[str, Any]) -> Self | None:
        """Preserve prior legacy handling; reject forged versioned producer identities."""
        if record.get("scanner_id") != cls.scanner_id:
            return None
        payload = record.get("payload")
        if isinstance(payload, dict) and "collection_evidence_version" not in payload:
            return None
        if (
            admit_evidence_schema(record) is not None
            or record.get("provider_id", "aws") != "aws"
            or (record.get("evidence_module"), record.get("evidence_type")) != ("builtins", "dict")
            or record.get("serialization_status") != "serialized"
            or record.get("serialization_format") != "json-compatible-python-object"
        ):
            message = "Quota privacy requires its matching versioned AWS dictionary identity."
            raise ValueError(message)
        return cls()

    @classmethod
    def _valid(cls, value: object, kind: str, *, nullable: bool) -> bool:
        """Validate only emitted finite controls, dates and nonnegative quantities."""
        if value is None:
            return nullable
        if kind in VOCABULARIES:
            return isinstance(value, str) and value in VOCABULARIES[kind]
        if kind == "version":
            return type(value) is int and value == 1
        if kind == "threshold":
            return type(value) in {int, bool}
        if kind == "quantity":
            return isinstance(value, str) and _finite_quantity(value)
        if kind == "date":
            if not isinstance(value, str):
                return False
            try:
                return date.fromisoformat(value).isoformat() == value
            except ValueError:
                return False
        return super()._valid(value, kind, nullable=nullable)

    def unknown_paths(self, value: object, member: str, suffix: str = "") -> list[str]:
        """Reject cross-check field borrowing even when each literal is recognized."""
        failures = super().unknown_paths(value, member, suffix)
        if suffix == "quota_records[]" and isinstance(value, dict):
            spec = CHECKS.get(str(value.get("check_id")))
            if spec is not None:
                for key, valid in (("service", {spec[0]}), ("resource_type", {spec[1]}), ("resource_count_method", set(spec[2:]))):
                    if not isinstance(value.get(key), str) or value[key] not in valid:
                        failures.append(member + self.prefix[1:] + "." + suffix + "." + key)
        return failures

    def resolve(self, path: str, profile: str) -> PrivacyTreatmentDecision | None:
        """Tokenise arbitrary limitation/warning text under either privacy profile."""
        decision = super().resolve(path, profile)
        return replace(decision, treatment="tokenise") if decision is not None and decision.category == "free_text" else decision

    def is_literal(self, suffix: str, value: str) -> bool:
        """Allow only closed control strings or the exact typed quota quantity field."""
        spec = self.fields.get(suffix)
        return spec is not None and spec[0] in {*VOCABULARIES, "quantity"} and self._valid(value, spec[0], nullable=spec[2])


def _finite_quantity(value: str) -> bool:
    """Keep quota count parsing exact, finite and nonnegative."""
    try:
        number = Decimal(value)
        return number.is_finite() and number >= 0
    except InvalidOperation:
        return False
