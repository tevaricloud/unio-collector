"""Actual audit-service wrappers driven by synthetic provider metadata only."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_audit_fixture import SyntheticAuditSession
from tools.collector_governance.responses import responses
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.cost_explorer import DailyCostRecord
from unio_collector.scanners.config.cost_governance.collector import ConfigCostGovernanceReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.security_governance.guardduty.collector import GuardDutyCostGovernanceReviewCollector
from unio_collector.scanners.security_governance.securityhub_inspector_macie.collector import SecurityHubInspectorMacieCostReviewCollector
from unio_collector.scanners.security_governance.waf.collector import WafCostGovernanceReviewCollector

COLLECTORS = {
    "config-cost-governance-review": (ConfigCostGovernanceReviewCollector, "config"),
    "guardduty-cost-governance-review": (GuardDutyCostGovernanceReviewCollector, "guardduty"),
    "securityhub-inspector-macie-cost-review": (SecurityHubInspectorMacieCostReviewCollector, "securityhub"),
    "waf-cost-governance-review": (WafCostGovernanceReviewCollector, "wafv2"),
}
UNKNOWN_FIELDS = {
    "config-cost-governance-review": "unknown_config_governance",
    "guardduty-cost-governance-review": "unknown_guardduty_governance",
    "securityhub-inspector-macie-cost-review": "unknown_security_governance",
    "waf-cost-governance-review": "unknown_waf_governance",
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
    "summary",
    "collision",
    "legacy",
    "cost_unavailable",
    "identity_collision",
)


class SyntheticGovernanceSession(SyntheticAuditSession):
    """Bind a finite offline endpoint inventory, recording actual requested operations."""

    def __init__(self, service: str, variant: str, *, region: str = "eu-west-2", calls: list[str] | None = None) -> None:
        """Keep all child-client operation observations in one synthetic execution."""
        super().__init__(service, variant, region=region)
        self.calls = calls if calls is not None else []

    def create_client(self, service: str, **kwargs: Any) -> SyntheticGovernanceSession:  # noqa: ANN401
        """Allow portfolio endpoints and WAF global scope, never a live provider."""
        services = {"securityhub", "inspector2", "macie2"} if self.service == "securityhub" else {self.service}
        regions = {"eu-west-1", "eu-west-2", "us-east-1"} if self.service == "wafv2" else {"eu-west-1", "eu-west-2"}
        if service not in services or kwargs.get("region_name") not in regions:
            message = "Unexpected synthetic governance endpoint."
            raise AssertionError(message)
        return SyntheticGovernanceSession(service, self.variant, region=str(kwargs["region_name"]), calls=self.calls)

    def __getattr__(self, operation: str) -> Any:  # noqa: ANN401
        """Expose finite responses and meaningful optional-operation failure branches."""
        values = self._responses()
        if operation not in values:
            raise AttributeError(operation)

        def invoke(**kwargs: object) -> dict[str, Any]:
            self.calls.append(f"{self.service}:{self.region}:{operation}")
            code = {"denied": "AccessDenied", "unavailable": "ServiceUnavailable", "unsupported": "UnsupportedOperation", "failure": "InternalFailure"}.get(
                self.variant
            )
            if self.variant == "partial" and (
                self.region == "eu-west-1"
                or operation in {"describe_configuration_recorder_status", "get_detector", "get_enabled_standards", "list_resources_for_web_acl"}
            ):
                code = "AccessDenied"
            if code:
                raise ClientError({"Error": {"Code": code, "Message": "synthetic-only governance provider failure"}}, operation)
            value = values[operation]
            if (
                operation == "get_detector"
                and self.variant != "nullable"
                and kwargs.get("DetectorId") != "ENABLED"
                and str(kwargs.get("DetectorId", "")).endswith("detector")
            ):
                value = dict(value, Status="DISABLED", FindingPublishingFrequency="ONE_HOUR")
            if operation == "get_web_acl" and kwargs.get("Scope") == "CLOUDFRONT":
                value = {"WebACL": dict(value["WebACL"], DefaultAction={"Block": {}})}
            if self.variant == "empty":
                return {key: [] if isinstance(child, list) else child for key, child in value.items()}
            return value

        return invoke

    def _responses(self) -> dict[str, dict[str, Any]]:
        """Use provider-shaped data; every derived record remains producer-owned."""
        return responses(self.service, self.variant)


def governance_producer_case(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Return the actual evidence envelope from one fully retained observation."""
    return governance_producer_observation(scanner, variant)["evidence"]


def governance_producer_observation(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Execute the real wrapper and retain its notes, warnings and regional outcomes."""
    if scanner not in COLLECTORS or variant not in VARIANTS:
        message = "Unknown synthetic audit producer case."
        raise ValueError(message)
    wrapper, service = COLLECTORS[scanner]
    session = SyntheticGovernanceSession(service, variant)
    definition: Any = SimpleNamespace(scanner_id=scanner, display_name=scanner)
    state = SimpleNamespace(
        account_id="123456789012",
        session=session,
        get_selected_regions=lambda: ["eu-west-2", "eu-west-1"] if variant == "partial" else ["eu-west-2"],
        has_explicit_region_scope=lambda: True,
        get_scanner_option=lambda _scanner, _key, default: "summary" if variant == "summary" else default,
    )
    audit = AwsAuditContext(scanner_id=scanner, collector="synthetic", allowed_api_calls=())
    costs = SimpleNamespace(
        service_costs=[
            {
                "service_name": {"config": "AWS Config", "guardduty": "Amazon GuardDuty", "securityhub": "AWS Security Hub", "wafv2": "AWS WAF"}[service],
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


def add_governance_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Include actual populated and conditional audit-service records in packaged smoke."""
    import json  # noqa: PLC0415

    from tools.collector_scanner_fixture import add_scanner_producer_payload  # noqa: PLC0415

    for scanner in COLLECTORS:
        observed = governance_producer_observation(scanner)
        notes = observed["coverage_notes"]
        warnings = observed["warnings"]
        row = observed["evidence"]
        key = "records"
        for variant in VARIANTS:
            if variant == "success":
                continue
            observed = governance_producer_observation(scanner, variant)
            notes.extend(observed["coverage_notes"])
            warnings.extend(observed["warnings"])
            extra = observed["evidence"]["payload"]
            row["payload"][key].extend(extra[key])
            if "warnings" in extra:
                row["payload"]["warnings"].extend(extra["warnings"])
        if unknown:
            target = row["payload"][key][0]
            if scanner.startswith("guardduty"):
                target = target["feature_status_counts"]
            elif scanner.startswith("securityhub"):
                target = target["macie_job_status_counts"]
            target[UNKNOWN_FIELDS[scanner]] = {}
        add_scanner_producer_payload(files, row)
        results = json.loads(files["scan-result/scanner-results.json"])
        target = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
        target["coverage_notes"] = notes
        target["warnings"] = warnings
        files["scan-result/scanner-results.json"] = json.dumps(results, sort_keys=True).encode()
