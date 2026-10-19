"""Actual IAM and security-service producers with offline providers."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_audit_fixture import SyntheticAuditSession
from tools.collector_identity_responses import responses, shape_response
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.scanners.iam.access_analyzer.collector import IamAccessAnalyzerEvidenceReviewCollector
from unio_collector.scanners.iam.account_security.collector import IamAccountSecurityCollector
from unio_collector.scanners.iam.identity_center.collector import IamIdentityCenterVisibilityReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.security_governance.service.coverage.collector import AwsSecurityServiceCoverageReviewCollector

COLLECTORS = {
    "iam-account-security-review": (IamAccountSecurityCollector, "iam"),
    "iam-access-analyzer-evidence-review": (IamAccessAnalyzerEvidenceReviewCollector, "accessanalyzer"),
    "iam-identity-center-visibility-review": (IamIdentityCenterVisibilityReviewCollector, "sso-admin"),
    "aws-security-service-coverage-review": (AwsSecurityServiceCoverageReviewCollector, "ec2"),
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
    "full",
    "off",
    "malformed",
    "truncated",
    "not_enabled",
    "absent",
    "policy_collision",
    "statement_object",
)

ANALYZER_ALIAS_VARIANTS = ("name_complete", "name_region")


class SyntheticIdentitySession(SyntheticAuditSession):
    """Finite offline endpoint inventory with recorded actual operation arguments."""

    def __init__(self, service: str, variant: str, *, scanner: str, region: str = "eu-west-2", calls: list[str] | None = None) -> None:
        """Bind one finite offline endpoint and shared operation observations."""
        super().__init__(service, variant, region=region)
        self.scanner = scanner
        self.calls = calls if calls is not None else []

    def create_client(self, service: str, **kwargs: Any) -> SyntheticIdentitySession:  # noqa: ANN401
        """Allow only the selected family's synthetic regional endpoints."""
        services = {"cloudtrail", "config", "guardduty", "securityhub"} if self.scanner == "aws-security-service-coverage-review" else {self.service}
        if service not in services or (kwargs.get("region_name") or self.region) not in {"eu-west-1", "eu-west-2", "us-east-1"}:
            message = "Unexpected synthetic endpoint"
            raise AssertionError(message)
        return SyntheticIdentitySession(service, self.variant, scanner=self.scanner, region=str(kwargs.get("region_name") or self.region), calls=self.calls)

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
                or operation in {"get_access_key_last_used", "list_customer_managed_policy_references_in_permission_set", "describe_configuration_aggregators"}
            ):
                code = "AccessDenied"
            if self.variant == "not_enabled" and operation == "describe_hub":
                code = "InvalidAccessException"
            if self.variant == "absent" and operation in {"get_account_password_policy", "get_login_profile"}:
                code = "NoSuchEntity"
            if code:
                message = "synthetic Security Hub is not enabled" if self.variant == "not_enabled" else "synthetic-only provider failure"
                raise ClientError({"Error": {"Code": code, "Message": message}}, operation)
            value = responses(self.service, self.variant, dict(parameters, scanner=self.scanner))[operation]
            return shape_response(value, self.variant, operation, self.scanner)

        return invoke


def identity_producer_observation(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Collect actual provider facts, callbacks, warnings and serialized envelope."""
    if scanner not in COLLECTORS or variant not in (*VARIANTS, *(ANALYZER_ALIAS_VARIANTS if scanner == "iam-access-analyzer-evidence-review" else ())):
        message = "Unknown synthetic key producer case"
        raise ValueError(message)
    wrapper, service = COLLECTORS[scanner]
    session = SyntheticIdentitySession(service, variant, scanner=scanner)
    definition: Any = SimpleNamespace(scanner_id=scanner, display_name=scanner)
    state = SimpleNamespace(
        account_id="123456789012",
        session=session,
        get_selected_regions=lambda: ["eu-west-2", "eu-west-1"] if variant == "partial" else ["eu-west-2"],
        has_explicit_region_scope=lambda: True,
        get_scanner_option=lambda _scanner, key, default: (
            ("full" if variant in {"policy_collision", "statement_object"} else variant)
            if key == "policy_detail_mode" and variant in {"full", "off", "policy_collision", "statement_object"}
            else default
        ),
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


def add_identity_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Aggregate every real producer variant for clean-wheel and packaged smoke."""
    import json  # noqa: PLC0415

    from tools.collector_scanner_fixture import add_scanner_producer_payload  # noqa: PLC0415

    for scanner in COLLECTORS:
        observed = identity_producer_observation(scanner)
        row = observed["evidence"]
        notes = observed["coverage_notes"]
        warnings = observed["warnings"]
        for variant in (*VARIANTS[1:], *(ANALYZER_ALIAS_VARIANTS if scanner == "iam-access-analyzer-evidence-review" else ())):
            extra = identity_producer_observation(scanner, variant)
            notes.extend(extra["coverage_notes"])
            warnings.extend(extra["warnings"])
            for key, value in extra["evidence"]["payload"].items():
                if isinstance(value, list):
                    row["payload"][key].extend(value)
        if unknown:
            payload = row["payload"]
            target = payload.get("users", payload.get("analyzers", payload.get("instances", payload.get("records"))))[0]
            target["unknown_identity_control"] = {}
        add_scanner_producer_payload(files, row)
        results = json.loads(files["scan-result/scanner-results.json"])
        target = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
        target["coverage_notes"] = notes
        target["warnings"] = warnings
        files["scan-result/scanner-results.json"] = json.dumps(results, sort_keys=True).encode()
