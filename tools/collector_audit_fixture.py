"""Actual audit-service wrappers driven by synthetic provider metadata only."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics
from unio_collector.scanners.audit_cost.cloudtrail.cost.collector import CloudTrailCostGovernanceReviewCollector
from unio_collector.scanners.audit_cost.cloudtrail.security.collector import CloudTrailSecurityPostureReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.security_governance.secrets_manager.collector import SecretsManagerCostGovernanceReviewCollector
from unio_collector.scanners.xray.collector import XRayTracingCostGovernanceReviewCollector

COLLECTORS = {
    "secrets-manager-cost-governance-review": (SecretsManagerCostGovernanceReviewCollector, "secretsmanager"),
    "cloudtrail-cost-governance-review": (CloudTrailCostGovernanceReviewCollector, "cloudtrail"),
    "cloudtrail-security-posture-review": (CloudTrailSecurityPostureReviewCollector, "cloudtrail"),
    "xray-tracing-cost-governance-review": (XRayTracingCostGovernanceReviewCollector, "xray"),
}
UNKNOWN_FIELDS = {
    "secrets-manager-cost-governance-review": "unknown_secrets_audit",
    "cloudtrail-cost-governance-review": "unknown_cloudtrail_cost",
    "cloudtrail-security-posture-review": "unknown_cloudtrail_security",
    "xray-tracing-cost-governance-review": "unknown_xray_audit",
}
VARIANTS = ("success", "nullable", "empty", "partial", "denied", "unavailable", "unsupported", "failure", "advanced", "collision")


class SyntheticAuditSession:
    """Allow only an explicit finite in-memory provider operation inventory."""

    def __init__(self, service: str, variant: str, *, region: str = "eu-west-2") -> None:
        """Bind deterministic provider metadata and a real offline executor."""
        self.region = region
        self.service = service
        self.variant = variant
        self.runtime_config = AwsRuntimeConfig(max_workers=1)
        self.collection_diagnostics = AwsCollectionDiagnostics()

    def create_client(self, service: str, **kwargs: Any) -> SyntheticAuditSession:  # noqa: ANN401
        """Refuse every endpoint outside the selected synthetic region/service."""
        if service != self.service or kwargs.get("region_name") not in {"eu-west-2", "eu-west-1"}:
            message = "Unexpected synthetic provider endpoint."
            raise AssertionError(message)
        return SyntheticAuditSession(service, self.variant, region=str(kwargs["region_name"]))

    def __getattr__(self, operation: str) -> Any:  # noqa: ANN401
        """Expose only named in-memory operations, never an AWS session."""
        responses = self._responses()
        if operation not in responses:
            raise AttributeError(operation)

        def invoke(**_kwargs: object) -> dict[str, Any]:
            code = {"denied": "AccessDenied", "unavailable": "ServiceUnavailable", "unsupported": "UnsupportedOperation", "failure": "InternalFailure"}.get(
                self.variant
            )
            if self.variant == "partial" and (self.region == "eu-west-1" or operation in {"get_trail_status", "get_encryption_config"}):
                code = "AccessDenied"
            if code:
                raise ClientError({"Error": {"Code": code, "Message": "synthetic-only provider failure"}}, operation)
            value = responses[operation]
            if self.variant == "empty":
                return {key: [] if isinstance(child, list) else child for key, child in value.items()}
            return value

        return invoke

    def _responses(self) -> dict[str, dict[str, Any]]:
        nullable = self.variant == "nullable"
        name = "Enabled" if self.variant == "collision" else "synthetic-customer-resource"
        if self.service == "secretsmanager":
            secret: dict[str, Any] = {"Name": name, "ARN": "arn:aws:secretsmanager:eu-west-2:123456789012:secret:synthetic-resource"}
            if not nullable:
                secret.update(
                    RotationEnabled=True,
                    LastAccessedDate=datetime(2026, 1, 2, tzinfo=UTC),
                    KmsKeyId="synthetic-customer-key",
                    OwningService="synthetic-customer-service",
                    RotationLambdaARN="arn:aws:lambda:eu-west-2:123456789012:function:synthetic-resource",
                    ReplicationStatus=[{"Region": "us-east-1"}],
                    Tags=[{"Key": "Name", "Value": "synthetic-customer-tag"}],
                )
            return {"list_secrets": {"SecretList": [secret, {"Name": "synthetic-customer-deleted", "DeletedDate": datetime(2026, 1, 2, tzinfo=UTC)}]}}
        if self.service == "xray":
            return {
                "get_groups": {"Groups": [{"GroupName": name}]},
                "get_sampling_rules": {"SamplingRuleRecords": [{"SamplingRule": {"RuleName": name}}, {"SamplingRule": {"RuleName": "Default"}}]},
                "get_sampling_statistic_summaries": {"SamplingStatisticSummaries": [{"SampledCount": 7, "RequestCount": 19, "BorrowCount": 2}]},
                "get_encryption_config": {"EncryptionConfig": {} if nullable else {"Type": "KMS"}},
            }
        trail: dict[str, Any] = {"Name": name, "TrailARN": "arn:aws:cloudtrail:eu-west-2:123456789012:trail/synthetic-resource", "HomeRegion": "eu-west-2"}
        if not nullable:
            trail.update(
                IsMultiRegionTrail=True,
                IsOrganizationTrail=False,
                LogFileValidationEnabled=True,
                S3BucketName="synthetic-customer-bucket",
                KmsKeyId="synthetic-customer-key",
                CloudWatchLogsLogGroupArn="arn:aws:logs:eu-west-2:123456789012:log-group:synthetic-group",
                SnsTopicName="synthetic-customer-topic",
            )
        advanced = {
            "Name": "synthetic-customer-selector",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {
                    "Field": "resources.ARN",
                    "StartsWith": ["arn:aws:s3:::synthetic-customer-bucket/"],
                    "EndsWith": ["synthetic-customer-suffix"],
                    "NotEquals": ["synthetic-customer-excluded"],
                    "NotStartsWith": ["synthetic-customer-prefix"],
                    "NotEndsWith": ["synthetic-customer-tail"],
                },
            ],
        }
        selectors = {"AdvancedEventSelectors": [advanced]}
        if self.variant != "advanced":
            selectors["EventSelectors"] = [
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "ExcludeManagementEventSources": ["kms.amazonaws.com"],
                    "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::synthetic-customer-bucket/"]}],
                }
            ]
        store = {
            "EventDataStoreArn": "arn:aws:cloudtrail:eu-west-2:123456789012:eventdatastore/synthetic-store",
            "Name": "synthetic-customer-store",
            "Status": "ENABLED",
            "RetentionPeriod": 90,
            "AdvancedEventSelectors": [advanced],
        }
        return {
            "describe_trails": {"trailList": [trail]},
            "get_trail_status": {} if nullable else {"IsLogging": True, "LatestDeliveryError": "synthetic-customer-error"},
            "get_event_selectors": selectors,
            "get_insight_selectors": {"InsightSelectors": [{"InsightType": "ApiCallRateInsight"}]},
            "list_event_data_stores": {"EventDataStores": [store]},
            "get_event_data_store": store,
        }


def audit_producer_case(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Return the actual evidence envelope from one fully retained observation."""
    return audit_producer_observation(scanner, variant)["evidence"]


def audit_producer_observation(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Execute the real wrapper and retain its notes, warnings and regional outcomes."""
    if scanner not in COLLECTORS or variant not in VARIANTS:
        message = "Unknown synthetic audit producer case."
        raise ValueError(message)
    wrapper, service = COLLECTORS[scanner]
    session = SyntheticAuditSession(service, variant)
    definition: Any = SimpleNamespace(scanner_id=scanner, display_name=scanner)
    state = SimpleNamespace(
        account_id="123456789012",
        session=session,
        get_selected_regions=lambda: ["eu-west-2", "eu-west-1"] if variant == "partial" else ["eu-west-2"],
        has_explicit_region_scope=lambda: True,
    )
    audit = AwsAuditContext(scanner_id=scanner, collector="synthetic", allowed_api_calls=())
    costs = SimpleNamespace(
        service_costs=[
            {
                "service_name": {"secretsmanager": "AWS Secrets Manager", "cloudtrail": "AWS CloudTrail", "xray": "AWS X-Ray"}[service],
                "current_cost": "123.45",
                "previous_cost": "67.89",
                "currency": "USD",
            }
        ],
        current_period=SimpleNamespace(currency="USD"),
    )
    warnings: list[str] = []
    notes: list[dict[str, Any]] = []
    runtime: Any = SimpleNamespace(
        runtime_state=state,
        create_audit_context=lambda *_a: audit,
        add_scanner_warning=lambda _scanner, message: warnings.append(message),
        add_scanner_coverage_note=lambda _scanner, note: notes.append(note),
        get_cached_ec2_regions=lambda *_a: ["eu-west-2"],
        collect_cached_service_costs=lambda *_a: costs,
        collect_cached_daily_costs=lambda *_a, **_k: [],
        analysis_reference_time=SimpleNamespace(instant=datetime(2026, 1, 2, tzinfo=UTC)),
    )
    evidence = wrapper(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return {
        "evidence": build_scanner_evidence_payload(scanner_id=scanner, evidence=evidence),
        "coverage_notes": notes,
        "warnings": warnings,
        "diagnostics": session.collection_diagnostics.convert_to_summary(),
    }


def add_audit_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Include actual populated and conditional audit-service records in packaged smoke."""
    import json  # noqa: PLC0415

    from tools.collector_scanner_fixture import add_scanner_producer_payload  # noqa: PLC0415

    for scanner in COLLECTORS:
        observed = audit_producer_observation(scanner)
        notes = observed["coverage_notes"]
        warnings = observed["warnings"]
        row = observed["evidence"]
        key = "trails" if scanner == "cloudtrail-security-posture-review" else "records"
        for variant in VARIANTS:
            if variant == "success":
                continue
            observed = audit_producer_observation(scanner, variant)
            notes.extend(observed["coverage_notes"])
            warnings.extend(observed["warnings"])
            extra = observed["evidence"]["payload"]
            row["payload"][key].extend(extra[key])
            if "warnings" in extra:
                row["payload"]["warnings"].extend(extra["warnings"])
        if unknown:
            row["payload"][key][0][UNKNOWN_FIELDS[scanner]] = {}
        add_scanner_producer_payload(files, row)
        results = json.loads(files["scan-result/scanner-results.json"])
        target = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
        target["coverage_notes"] = notes
        target["warnings"] = warnings
        files["scan-result/scanner-results.json"] = json.dumps(results, sort_keys=True).encode()
