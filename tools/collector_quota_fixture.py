"""Actual versioned quota producer with finite offline SDK responses."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import date
from decimal import Decimal
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from tools.collector_audit_fixture import SyntheticAuditSession
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.core.cost_period import CostPeriod
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.service_quota.collector import ServiceQuotaProximityReviewCollector
from unio_collector.scanners.service_quota.supported_checks import SUPPORTED_SERVICE_QUOTA_CHECKS

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

SCANNER = "service-quota-proximity-review"
VARIANTS = (
    "success",
    "empty",
    "no_regions",
    "nullable",
    "partial",
    "denied",
    "unavailable",
    "unsupported",
    "failure",
    "malformed",
    "missing_quota",
    "fallback",
    "ambiguous",
    "collision",
    "negative_threshold",
    "bool_threshold",
    "invalid_threshold",
    "region_failure",
    "paginated_failure",
)


class SyntheticQuotaSession(SyntheticAuditSession):
    """Record only declared in-memory quota/resource calls and exact parameters."""

    def __init__(self, service: str, variant: str, *, region: str = "eu-west-2", calls: list[dict[str, Any]] | None = None) -> None:
        """Bind an explicit provider and share recorded operation observations."""
        super().__init__(service, variant, region=region)
        self.calls = calls if calls is not None else []

    def create_client(self, service: str, **kwargs: object) -> SyntheticQuotaSession:
        """Allow only the three existing read-only synthetic provider endpoints."""
        if service not in {"service-quotas", "ec2", "elbv2"} or kwargs.get("region_name") not in {"eu-west-1", "eu-west-2"}:
            message = "Unexpected synthetic quota endpoint"
            raise AssertionError(message)
        return SyntheticQuotaSession(service, self.variant, region=str(kwargs["region_name"]), calls=self.calls)

    def can_paginate(self, operation: str) -> bool:
        """Exercise the real paginator caller without network or sessions."""
        return operation in {"describe_nat_gateways", "describe_security_groups", "describe_vpcs", "describe_load_balancers", "list_service_quotas"}

    def get_paginator(self, operation: str) -> SimpleNamespace:
        """Serve one actual synthetic response page with recorded parameters."""

        def pages(**parameters: object) -> Iterator[dict[str, Any]]:
            yield getattr(self, operation)(**parameters)
            if self.variant == "paginated_failure":
                message = "Synthetic interrupted quota page stream"
                raise ValueError(message)

        return SimpleNamespace(paginate=pages)

    def __getattr__(self, operation: str) -> Callable[..., dict[str, Any]]:
        """Expose only the finite declared operation inventory and failure variants."""
        supported = {
            "service-quotas": {"get_service_quota", "list_service_quotas"},
            "ec2": {"describe_addresses", "describe_vpcs", "describe_security_groups", "describe_nat_gateways"},
            "elbv2": {"describe_load_balancers"},
        }
        if operation not in supported.get(self.service, set()):
            raise AttributeError(operation)

        def invoke(**parameters: object) -> dict[str, Any]:
            self.calls.append({"service": self.service, "region": self.region, "operation": operation, "parameters": dict(parameters)})
            code = {"denied": "AccessDenied", "unavailable": "ServiceUnavailable", "unsupported": "UnsupportedOperation", "failure": "InternalFailure"}.get(
                self.variant
            )
            if self.variant in {"partial", "region_failure"} and self.region == "eu-west-1":
                code = "AccessDenied"
            if operation == "get_service_quota" and self.variant in {"fallback", "ambiguous", "missing_quota"}:
                code = "NoSuchResourceException"
            if code:
                raise ClientError({"Error": {"Code": code, "Message": "synthetic-only quota failure"}}, operation)
            return self.response(operation, parameters)

        return invoke

    def response(self, operation: str, parameters: dict[str, object]) -> dict[str, Any]:
        """Use SDK wire keys, not serialized evidence or privacy registry paths."""
        if operation in {"get_service_quota", "list_service_quotas"}:
            quotas = [
                {
                    "ServiceCode": s.quota_service_code,
                    "QuotaCode": s.quota_code,
                    "QuotaName": ("high" if self.variant == "collision" else "synthetic-customer-quota"),
                    "Value": 10.0,
                }
                for s in SUPPORTED_SERVICE_QUOTA_CHECKS
                if s.quota_service_code == parameters["ServiceCode"]
            ]
            if operation == "get_service_quota":
                quota = next(q for q in quotas if q["QuotaCode"] == parameters["QuotaCode"])
                if self.variant == "nullable":
                    quota.pop("Value")
                    quota.pop("QuotaName")
                    quota.pop("QuotaCode")
                return {"Quota": quota}
            if self.variant == "missing_quota":
                quotas = []
            if self.variant == "ambiguous":
                quotas = [{"QuotaName": "Elastic IP addresses", "Value": 5.0}, {"QuotaName": "Elastic IP allocation", "Value": 10.0}]
            return {"Quotas": quotas}
        values = {
            "describe_addresses": {"Addresses": [{"AllocationId": "eipalloc-00000000000000000"}]},
            "describe_vpcs": {"Vpcs": [{"VpcId": "vpc-00000000000000000"}]},
            "describe_security_groups": {"SecurityGroups": [{"GroupId": "sg-00000000000000000"}]},
            "describe_nat_gateways": {
                "NatGateways": [
                    {"NatGatewayId": "nat-00000000000000000", "State": "available", "SubnetId": "subnet-00000000000000000", "VpcId": "vpc-00000000000000000"}
                ]
            },
            "describe_load_balancers": {"LoadBalancers": [{"Type": "application"}, {"Type": "network"}, {"Type": "gateway"}]},
        }
        response = deepcopy(values[operation])
        if self.variant == "empty":
            return {key: [] for key in response}
        if self.variant == "malformed":
            return dict.fromkeys(response)
        return response


def quota_producer_observation(variant: str = "success") -> dict[str, Any]:
    """Run real collection, callbacks, completeness and canonical serialization."""
    if variant not in VARIANTS:
        message = "Unknown synthetic quota variant"
        raise ValueError(message)
    session = SyntheticQuotaSession("ec2", variant)
    definition: Any = SimpleNamespace(scanner_id=SCANNER, display_name=SCANNER)
    regions = [] if variant == "no_regions" else ["eu-west-2", "eu-west-1"] if variant in {"partial", "region_failure"} else ["eu-west-2"]
    threshold: object = None if variant == "invalid_threshold" else -2 if variant == "negative_threshold" else True if variant == "bool_threshold" else 2
    state = SimpleNamespace(
        account_id="123456789012",
        session=session,
        get_selected_regions=lambda: regions,
        has_explicit_region_scope=lambda: True,
        get_scanner_option=lambda _s, _k, _d: threshold,
    )
    warnings: list[str] = []
    notes: list[dict[str, Any]] = []
    audit = AwsAuditContext(scanner_id=SCANNER, collector="synthetic-quota", allowed_api_calls=())

    def discovered_regions(*_args: object) -> list[str]:
        if variant == "region_failure":
            message = "Synthetic quota region discovery failure"
            raise ValueError(message)
        return regions

    runtime: Any = SimpleNamespace(
        runtime_state=state,
        current_period=CostPeriod(start_date=date(2026, 1, 1), end_date=date(2026, 1, 31), total_cost=Decimal(10), currency="USD"),
        create_audit_context=lambda *_a: audit,
        get_cached_ec2_regions=discovered_regions,
        get_scanner_option=lambda _s, _k, _d: threshold,
        add_scanner_warning=lambda _s, message: warnings.append(message),
        add_scanner_coverage_note=lambda _s, note: notes.append(note),
        scanner_data={},
    )
    evidence = ServiceQuotaProximityReviewCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return {
        "evidence": build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence),
        "warnings": warnings,
        "coverage_notes": notes,
        "operations": session.calls,
        "diagnostics": session.collection_diagnostics.convert_to_summary(),
    }


def add_quota_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Enrich the shared packaged/wheel input with actual populated quota variants."""
    observed = quota_producer_observation("region_failure")
    row = observed["evidence"]
    if unknown:
        row["payload"]["quota_records"][0]["unknown_quota_control"] = None
    add_scanner_producer_payload(files, row)
    results = json.loads(files["scan-result/scanner-results.json"])
    target = next(item for item in results["scanner_results"] if item["scanner_id"] == SCANNER)
    target["warnings"] = observed["warnings"]
    target["coverage_notes"] = observed["coverage_notes"]
    files["scan-result/scanner-results.json"] = json.dumps(results, sort_keys=True).encode()
