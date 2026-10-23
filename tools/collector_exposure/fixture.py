"""Actual exposure and account-posture producers with offline providers."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_audit_fixture import SyntheticAuditSession
from tools.collector_exposure.responses import responses, shape_response
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.scanners.account_risk.root.recovery.collector import RootAccountRecoveryAdvisoryCollector
from unio_collector.scanners.ec2.security_group.collector import Ec2SecurityGroupExposureReviewCollector
from unio_collector.scanners.ecr.image_scan.collector import EcrImageScanPostureReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.security_governance.public_exposure.collector import PublicServiceExposureReviewCollector

COLLECTORS = {
    "ec2-security-group-exposure-review": (Ec2SecurityGroupExposureReviewCollector, "ec2"),
    "ecr-image-scan-posture-review": (EcrImageScanPostureReviewCollector, "ecr"),
    "public-service-exposure-review": (PublicServiceExposureReviewCollector, "ec2"),
    "root-account-recovery-advisory": (RootAccountRecoveryAdvisoryCollector, "iam"),
}
VARIANTS = ("success", "nullable", "empty", "partial", "denied", "unavailable", "unsupported", "failure", "collision")

CASE_VARIANTS = {
    scanner: ("success",)
    if scanner == "root-account-recovery-advisory"
    else VARIANTS
    + {
        "ecr-image-scan-posture-review": ("malformed", "basic"),
        "ec2-security-group-exposure-review": ("protocols", "port_collision"),
    }.get(scanner, ())
    for scanner in COLLECTORS
}


class SyntheticExposureSession(SyntheticAuditSession):
    """Finite offline endpoint inventory with recorded actual operation arguments."""

    def __init__(self, service: str, variant: str, *, scanner: str, region: str = "eu-west-2", calls: list[str] | None = None) -> None:
        """Bind one finite offline endpoint and shared operation observations."""
        super().__init__(service, variant, region=region)
        self.scanner = scanner
        self.calls = calls if calls is not None else []

    def create_client(self, service: str, **kwargs: Any) -> SyntheticExposureSession:  # noqa: ANN401
        """Allow only the selected family's synthetic regional endpoints."""
        services = (
            {"rds", "es", "redshift", "elbv2", "apigateway", "apigatewayv2", "cloudfront"}
            if self.scanner == "public-service-exposure-review"
            else {self.service}
        )
        if service not in services or (kwargs.get("region_name") or self.region) not in {"eu-west-1", "eu-west-2", "us-east-1"}:
            message = "Unexpected synthetic endpoint"
            raise AssertionError(message)
        return SyntheticExposureSession(service, self.variant, scanner=self.scanner, region=str(kwargs.get("region_name") or self.region), calls=self.calls)

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
            if self.variant == "partial" and (self.region == "eu-west-1" or operation in {"get_registry_scanning_configuration", "get_apis"}):
                code = "AccessDenied"
            if code:
                message = "synthetic-only provider failure"
                raise ClientError({"Error": {"Code": code, "Message": message}}, operation)
            value = responses(self.service, self.variant, dict(parameters, scanner=self.scanner))[operation]
            return shape_response(value, self.variant, operation, self.scanner)

        return invoke


def exposure_producer_observation(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Collect actual provider facts, callbacks, warnings and serialized envelope."""
    if scanner not in COLLECTORS or variant not in CASE_VARIANTS[scanner]:
        message = "Unknown synthetic key producer case"
        raise ValueError(message)
    wrapper, service = COLLECTORS[scanner]
    session = SyntheticExposureSession(service, variant, scanner=scanner)
    definition: Any = SimpleNamespace(scanner_id=scanner, display_name=scanner)
    state = SimpleNamespace(
        account_id="123456789012",
        session=session,
        get_selected_regions=lambda: ["eu-west-2", "eu-west-1"] if variant == "partial" else ["eu-west-2"],
        has_explicit_region_scope=lambda: True,
        get_scanner_option=lambda _scanner, _key, default: default,
    )
    audit = AwsAuditContext(scanner_id=scanner, collector="synthetic", allowed_api_calls=())
    warnings: list[str] = []
    notes: list[dict[str, Any]] = []

    runtime: Any = SimpleNamespace(
        runtime_state=state,
        create_audit_context=lambda *_a: audit,
        add_scanner_warning=lambda _scanner, message: warnings.append(message),
        add_scanner_coverage_note=lambda _scanner, note: notes.append(note),
        get_cached_ec2_regions=lambda *_a: ["eu-west-2"],
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


def add_exposure_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Aggregate every real producer variant for clean-wheel and packaged smoke."""
    import json  # noqa: PLC0415

    from tools.collector_scanner_fixture import add_scanner_producer_payload  # noqa: PLC0415

    for scanner in COLLECTORS:
        observed = exposure_producer_observation(scanner)
        row = observed["evidence"]
        notes = observed["coverage_notes"]
        warnings = observed["warnings"]
        for variant in CASE_VARIANTS[scanner][1:]:
            extra = exposure_producer_observation(scanner, variant)
            notes.extend(extra["coverage_notes"])
            warnings.extend(extra["warnings"])
            for key, value in extra["evidence"]["payload"].items():
                if isinstance(value, list):
                    row["payload"][key].extend(value)
        if unknown:
            payload = row["payload"]
            keys = {
                "ec2-security-group-exposure-review": "public_ingress_rules",
                "ecr-image-scan-posture-review": "repositories",
                "public-service-exposure-review": "records",
            }
            target = payload[keys[scanner]][0] if scanner in keys else payload
            target["unknown_exposure_control"] = {}
        add_scanner_producer_payload(files, row)
        results = json.loads(files["scan-result/scanner-results.json"])
        target = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
        target["coverage_notes"] = notes
        target["warnings"] = warnings
        files["scan-result/scanner-results.json"] = json.dumps(results, sort_keys=True).encode()
