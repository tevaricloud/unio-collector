"""Actual KMS, encryption and Security Hub producers with offline providers."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_audit_fixture import SyntheticAuditSession
from tools.collector_key_responses import responses, shape_response
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.cost_explorer import DailyCostRecord
from unio_collector.scanners.kms.cost_governance.collector import KmsCostGovernanceReviewCollector
from unio_collector.scanners.kms.key_posture.collector import KmsKeyPostureReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.security_governance.encryption.collector import EncryptionBaselineReviewCollector
from unio_collector.scanners.security_governance.security_hub.summary.collector import SecurityHubControlSummaryReviewCollector

COLLECTORS = {
    "kms-cost-governance-review": (KmsCostGovernanceReviewCollector, "kms"),
    "kms-key-posture-review": (KmsKeyPostureReviewCollector, "kms"),
    "encryption-baseline-review": (EncryptionBaselineReviewCollector, "ec2"),
    "securityhub-control-summary-review": (SecurityHubControlSummaryReviewCollector, "securityhub"),
}
VARIANTS = (
    "success",
    "nullable",
    "empty",
    "partial",
    "denied",
    "unavailable",
    "unsupported",
    "failure",
    "collision",
    "identity_collision",
    "cost_unavailable",
    "malformed",
    "truncated",
    "not_enabled",
    "rotation_off",
)


class SyntheticKeySession(SyntheticAuditSession):
    """Finite offline endpoint inventory with recorded actual operation arguments."""

    def __init__(self, service: str, variant: str, *, scanner: str, region: str = "eu-west-2", calls: list[str] | None = None) -> None:
        """Bind one finite offline endpoint and shared operation observations."""
        super().__init__(service, variant, region=region)
        self.scanner = scanner
        self.calls = calls if calls is not None else []

    def create_client(self, service: str, **kwargs: Any) -> SyntheticKeySession:  # noqa: ANN401
        """Allow only the selected family's synthetic regional endpoints."""
        services = {"ec2", "s3"} if self.scanner == "encryption-baseline-review" else {self.service}
        if service not in services or kwargs.get("region_name") not in {"eu-west-1", "eu-west-2", "us-east-1"}:
            message = "Unexpected synthetic endpoint"
            raise AssertionError(message)
        return SyntheticKeySession(service, self.variant, scanner=self.scanner, region=str(kwargs["region_name"]), calls=self.calls)

    def get_paginator(self, operation: str) -> Any:  # noqa: ANN401
        """Serve one actual provider page through the normal paginator interface."""
        return SimpleNamespace(paginate=lambda **parameters: iter([getattr(self, operation)(**parameters)]))

    def __getattr__(self, operation: str) -> Any:  # noqa: ANN401
        """Expose finite in-memory SDK operations and explicit failure branches."""
        supported = responses(self.service, self.variant, {"scanner": self.scanner})
        if operation not in supported:
            raise AttributeError(operation)

        def invoke(**parameters: object) -> dict[str, Any]:
            self.calls.append(f"{self.service}:{self.region}:{operation}")
            code = {"denied": "AccessDenied", "unavailable": "ServiceUnavailable", "unsupported": "UnsupportedOperation", "failure": "InternalFailure"}.get(
                self.variant
            )
            if self.variant == "partial" and (
                self.region == "eu-west-1"
                or operation in {"get_key_rotation_status", "list_resource_tags", "get_bucket_encryption"}
                or parameters.get("KeyId") == "synthetic-customer-disabled"
            ):
                code = "AccessDenied"
            if self.variant == "not_enabled" and operation == "describe_hub":
                code = "InvalidAccessException"
            if operation == "get_bucket_encryption" and str(parameters.get("Bucket", "")).endswith("absent"):
                code = "ServerSideEncryptionConfigurationNotFoundError"
            if code:
                message = "synthetic Security Hub is not enabled" if self.variant == "not_enabled" else "synthetic-only provider failure"
                raise ClientError({"Error": {"Code": code, "Message": message}}, operation)
            value = responses(self.service, self.variant, dict(parameters, scanner=self.scanner))[operation]
            return shape_response(value, self.variant, operation, self.scanner)

        return invoke


def key_producer_observation(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Collect actual provider facts, callbacks, warnings and serialized envelope."""
    if scanner not in COLLECTORS or variant not in VARIANTS:
        message = "Unknown synthetic key producer case"
        raise ValueError(message)
    wrapper, service = COLLECTORS[scanner]
    session = SyntheticKeySession(service, variant, scanner=scanner)
    definition: Any = SimpleNamespace(scanner_id=scanner, display_name=scanner)
    state = SimpleNamespace(
        account_id="123456789012",
        session=session,
        get_selected_regions=lambda: ["eu-west-2", "eu-west-1"] if variant == "partial" else ["eu-west-2"],
        has_explicit_region_scope=lambda: True,
        get_scanner_option=lambda _scanner, _key, default: default,
    )
    audit = AwsAuditContext(scanner_id=scanner, collector="synthetic", allowed_api_calls=())
    costs = SimpleNamespace(
        service_costs=[
            {
                "service_name": {
                    "securityhub": "AWS Security Hub",
                    "kms": "AWS Key Management Service",
                    "ec2": "Synthetic Encryption",
                }[service],
                "current_cost": "123.45",
                "previous_cost": "67.89",
                "currency": "USD",
            }
        ],
        current_period=SimpleNamespace(currency="USD"),
    )
    warnings: list[str] = []
    notes: list[dict[str, Any]] = []

    def service_costs(*_args: object) -> Any:  # noqa: ANN401
        if variant == "cost_unavailable":
            message = "Synthetic billing context unavailable."
            raise RuntimeError(message)
        return costs

    runtime: Any = SimpleNamespace(
        runtime_state=state,
        create_audit_context=lambda *_a: audit,
        add_scanner_warning=lambda _scanner, message: warnings.append(message),
        add_scanner_coverage_note=lambda _scanner, note: notes.append(note),
        get_cached_ec2_regions=lambda *_a: ["eu-west-2"],
        collect_cached_service_costs=service_costs,
        collect_cached_daily_costs=lambda *_a, **_k: [
            DailyCostRecord(
                date=date(2026, 1, 2),
                service_name=costs.service_costs[0]["service_name"],
                region="eu-west-2",
                usage_type=None,
                cost=Decimal("23.45"),
                currency="USD",
            )
        ],
        analysis_reference_time=SimpleNamespace(instant=datetime(2026, 1, 2, tzinfo=UTC)),
    )
    evidence = wrapper(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return {
        "evidence": build_scanner_evidence_payload(scanner_id=scanner, evidence=evidence),
        "coverage_notes": notes,
        "warnings": warnings,
        "diagnostics": session.collection_diagnostics.convert_to_summary(),
        "operations": session.calls,
    }


def add_key_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Aggregate every real producer variant for clean-wheel and packaged smoke."""
    import json  # noqa: PLC0415

    from tools.collector_scanner_fixture import add_scanner_producer_payload  # noqa: PLC0415

    for scanner in COLLECTORS:
        observed = key_producer_observation(scanner)
        row = observed["evidence"]
        notes = observed["coverage_notes"]
        warnings = observed["warnings"]
        for variant in VARIANTS[1:]:
            extra = key_producer_observation(scanner, variant)
            notes.extend(extra["coverage_notes"])
            warnings.extend(extra["warnings"])
            for key, value in extra["evidence"]["payload"].items():
                if isinstance(value, list):
                    row["payload"][key].extend(value)
        if unknown:
            payload = row["payload"]
            target = payload.get("records", payload.get("keys", payload.get("ebs_volumes")))[0]
            if scanner == "kms-cost-governance-review":
                target = target["raw_keys"][0]
            target["unknown_key_control"] = {}
        add_scanner_producer_payload(files, row)
        results = json.loads(files["scan-result/scanner-results.json"])
        target = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
        target["coverage_notes"] = notes
        target["warnings"] = warnings
        files["scan-result/scanner-results.json"] = json.dumps(results, sort_keys=True).encode()
