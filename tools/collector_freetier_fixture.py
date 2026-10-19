"""Actual Free Tier providers, callbacks and canonical DTO serialization."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator
import json

from botocore.exceptions import ClientError

from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.scanners.free_tier.collector import FreeTierUsageReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "free-tier-usage-review"
VARIANTS = (
    "success",
    "nullable",
    "empty",
    "denied",
    "unavailable",
    "unsupported",
    "failure",
    "partial",
    "expected_absence",
    "plan_denied",
    "usage_denied",
    "malformed_plan",
    "malformed_usage",
    "page_partial",
    "interrupted",
    "paid",
    "expired",
    "not_started",
    "collision",
    "requests",
)


class SyntheticFreeTierSession:
    """Return only the two explicit, offline account-level SDK operations."""

    def __init__(self, variant: str) -> None:
        """Bind one finite synthetic branch and record each attempted operation."""
        self.variant = variant
        self.calls: list[dict[str, Any]] = []

    def create_client(self, service: str, **kwargs: object) -> SyntheticFreeTierSession:
        """Refuse endpoint drift instead of ever constructing a provider client."""
        if service != "freetier" or kwargs.get("region_name") != "us-east-1":
            message = "Unexpected synthetic Free Tier endpoint"
            raise AssertionError(message)
        return self

    def can_paginate(self, operation: str) -> bool:
        """Use the actual paginator branch for the declared usage endpoint."""
        if operation != "get_free_tier_usage":
            message = "Unexpected synthetic Free Tier pagination operation"
            raise AssertionError(message)
        return True

    def get_paginator(self, operation: str) -> SyntheticFreeTierSession:
        """Return the finite synthetic SDK paginator for the expected operation."""
        if operation != "get_free_tier_usage":
            message = "Unexpected synthetic Free Tier pagination operation"
            raise AssertionError(message)
        return self

    def _fail(self, operation: str) -> None:
        codes = {
            "denied": "AccessDeniedException",
            "unavailable": "ServiceUnavailableException",
            "unsupported": "UnsupportedOperation",
            "failure": "InternalServerException",
            "plan_denied": "AccessDeniedException",
            "usage_denied": "AccessDeniedException",
            "expected_absence": "ResourceNotFoundException",
        }
        code = codes.get(self.variant)
        if self.variant in {"plan_denied", "expected_absence"} and operation != "get_account_plan_state":
            return
        if self.variant in {"usage_denied", "partial"} and operation == "get_account_plan_state":
            return
        if self.variant == "partial":
            code = "ThrottlingException"
        if code:
            raise ClientError({"Error": {"Code": code, "Message": "Synthetic customer detail; no provider calls"}}, operation)

    def get_account_plan_state(self) -> dict[str, Any]:
        """Return populated, optional, finite-state or failed plan responses."""
        self.calls.append({"operation": "get_account_plan_state", "parameters": {}})
        self._fail("get_account_plan_state")
        response = {
            "accountId": "123456789012",
            "accountPlanType": "FREE",
            "accountPlanStatus": "ACTIVE",
            "accountPlanRemainingCredits": {"amount": 25.0, "unit": "USD"},
            "accountPlanExpirationDate": datetime(2026, 12, 31, tzinfo=UTC),
        }
        if self.variant in {"nullable", "empty"}:
            return {"accountPlanType": "FREE", "accountPlanStatus": "ACTIVE"}
        if self.variant == "malformed_plan":
            return {"accountPlanType": None, "accountPlanStatus": "ACTIVE"}
        if self.variant == "paid":
            response["accountPlanType"] = "PAID"
        if self.variant in {"expired", "not_started"}:
            response["accountPlanStatus"] = "EXPIRED" if self.variant == "expired" else "NOT_STARTED"
        return deepcopy(response)

    def paginate(self, **kwargs: object) -> Iterator[dict[str, Any]]:
        """Exercise populated pages, nullable values and interruption honestly."""
        self.calls.append({"operation": "get_free_tier_usage", "parameters": dict(kwargs)})
        self._fail("get_free_tier_usage")
        row = {
            "service": "Amazon S3",
            "operation": "TimedStorage-ByteHrs",
            "usageType": "TimedStorage-ByteHrs",
            "region": "eu-west-2",
            "actualUsageAmount": 4.0,
            "forecastedUsageAmount": 6.0,
            "limit": 5.0,
            "unit": "GB-Mo",
            "description": "Synthetic customer usage description",
            "freeTierType": "AlwaysFree",
        }
        if self.variant == "nullable":
            row = {k: v for k, v in row.items() if k in {"service", "operation", "usageType"}}
        if self.variant == "collision":
            row.update(service="FREE", operation="ACTIVE", usageType="NOT_STARTED", description="EXPIRED", unit="PAID", freeTierType="FREE")
        if self.variant == "requests":
            row.update(service="Amazon Simple Storage Service", operation="Requests-Tier1", usageType="Requests-Tier1", unit="Requests")
        if self.variant == "malformed_usage":
            row["actualUsageAmount"] = "NaN"
        if self.variant == "empty":
            yield {"freeTierUsages": []}
            return
        if self.variant == "interrupted":
            yield {"freeTierUsages": [deepcopy(row)], "nextToken": "synthetic-next"}
            message = "Synthetic interrupted pagination"
            raise ValueError(message)
        if self.variant == "page_partial":
            yield {"freeTierUsages": [deepcopy(row)], "nextToken": "synthetic-next"}
            yield {"freeTierUsages": [{"service": None, "operation": "synthetic", "usageType": "synthetic"}]}
            return
        yield {"freeTierUsages": [deepcopy(row)]}
        if self.variant == "success":
            yield {"freeTierUsages": [dict(row, region="global", description="Second synthetic usage row")]}


def freetier_producer_observation(variant: str = "success") -> dict[str, Any]:
    """Run the real collector and canonical serialization with callback capture."""
    if variant not in VARIANTS:
        message = "Unknown synthetic Free Tier variant"
        raise ValueError(message)
    session = SyntheticFreeTierSession(variant)
    definition: Any = SimpleNamespace(scanner_id=SCANNER, display_name=SCANNER)
    warnings: list[str] = []
    notes: list[dict[str, Any]] = []
    runtime: Any = SimpleNamespace(
        runtime_state=SimpleNamespace(account_id="123456789012", session=session),
        create_audit_context=lambda *_a: AwsAuditContext(scanner_id=SCANNER, collector="synthetic-freetier", allowed_api_calls=()),
        add_scanner_warning=lambda _s, m: warnings.append(m),
        add_scanner_coverage_note=lambda _s, n: notes.append(n),
        scanner_data={},
    )
    evidence = FreeTierUsageReviewCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return {
        "evidence": build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence),
        "warnings": warnings,
        "coverage_notes": notes,
        "operations": session.calls,
        "status": evidence.get_status(),
        "account_plan_visibility": evidence.get_account_plan_visibility_status(),
    }


def add_freetier_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Use one real populated partial producer; do not merge variant DTOs."""
    observed = freetier_producer_observation("page_partial")
    row = observed["evidence"]
    if unknown:
        row["payload"]["usage_records"][0]["unknown_freetier_control"] = None
    add_scanner_producer_payload(files, row)
    results = json.loads(files["scan-result/scanner-results.json"])
    target = next(r for r in results["scanner_results"] if r["scanner_id"] == SCANNER)
    target["warnings"] = observed["warnings"]
    target["coverage_notes"] = observed["coverage_notes"]
    files["scan-result/scanner-results.json"] = json.dumps(results, sort_keys=True).encode()
