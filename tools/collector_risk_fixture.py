"""Offline actual-producer account-risk fixtures; no SDK session or client calls."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.account.risk.collector import AccountCostRiskCollector
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.cost_explorer.response_parser import CostExplorerResponseParser
from unio_collector.scanners.account_risk.cost.evidence import AccountCostRiskEvidence
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SYNTHETIC_IAM_SUMMARY = {
    "Users": 2,
    "UsersQuota": 5000,
    "Groups": 1,
    "GroupsQuota": 300,
    "ServerCertificates": 1,
    "ServerCertificatesQuota": 20,
    "UserPolicySizeQuota": 2048,
    "GroupPolicySizeQuota": 5120,
    "GroupsPerUserQuota": 10,
    "SigningCertificatesPerUserQuota": 2,
    "AccessKeysPerUserQuota": 2,
    "MFADevices": 2,
    "MFADevicesInUse": 1,
    "AccountMFAEnabled": 1,
    "AccountAccessKeysPresent": 0,
    "AccountPasswordPresent": 1,
    "AccountSigningCertificatesPresent": 0,
    "AttachedPoliciesPerGroupQuota": 10,
    "AttachedPoliciesPerRoleQuota": 10,
    "AttachedPoliciesPerUserQuota": 10,
    "Policies": 2,
    "PoliciesQuota": 1500,
    "PolicySizeQuota": 6144,
    "PolicyVersionsInUse": 3,
    "PolicyVersionsInUseQuota": 10000,
    "VersionsPerPolicyQuota": 5,
    "GlobalEndpointTokenVersion": 2,
    "AssumeRolePolicySizeQuota": 2048,
    "InstanceProfiles": 2,
    "InstanceProfilesQuota": 1000,
    "Providers": 1,
    "RolePolicySizeQuota": 10240,
    "Roles": 3,
    "RolesQuota": 1000,
}


def synthetic_trail(index: int = 0) -> dict[str, Any]:
    """Populate the complete current DescribeTrails record using fixed synthetic names."""

    def arn(service: str, resource: str) -> str:
        return ":".join(("arn", "aws", service, "eu-west-2", "123456789012", resource))  # noqa: FLY002

    return {
        "Name": f"synthetic-customer-trail-{index}",
        "S3BucketName": "synthetic-customer-bucket",
        "S3KeyPrefix": "synthetic-customer-prefix/",
        "SnsTopicName": "synthetic-customer-topic",
        "SnsTopicARN": arn("sns", "synthetic-customer-topic"),
        "IncludeGlobalServiceEvents": True,
        "IsMultiRegionTrail": True,
        "HomeRegion": "eu-west-2",
        "TrailARN": arn("cloudtrail", f"trail/synthetic-customer-trail-{index}"),
        "LogFileValidationEnabled": True,
        "CloudWatchLogsLogGroupArn": arn("logs", "log-group:synthetic-customer-log"),
        "CloudWatchLogsRoleArn": arn("iam", "role/synthetic-customer-role"),
        "KmsKeyId": "synthetic-customer-key",
        "HasCustomEventSelectors": False,
        "HasInsightSelectors": False,
        "IsOrganizationTrail": True,
        "RecursiveLogging": False,
    }


class SyntheticAccountRiskSession:
    """Supply deterministic in-memory responses, including unavailable and capped evidence."""

    def __init__(self, variant: str) -> None:
        """Select one explicit synthetic response variant."""
        self.variant = variant
        self.status_calls = 0

    def create_client(self, service_name: str, *, region_name: str, audit_context: AwsAuditContext) -> SyntheticAccountRiskSession:
        """Never create a real SDK client."""
        del audit_context
        if service_name not in {"cloudtrail", "iam"} or region_name != "us-east-1":
            message = "Synthetic account-risk fixture received an unexpected endpoint."
            raise ValueError(message)
        return self

    def describe_trails(self, **kwargs: object) -> dict[str, Any] | None:
        """Exercise successful, empty, unavailable, denied and capped collection."""
        del kwargs
        if self.variant == "denied":
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "synthetic diagnostic"}}, "DescribeTrails")
        if self.variant == "unavailable":
            return None
        count = 0 if self.variant == "empty" else 26 if self.variant == "capped" else 1
        trails = [synthetic_trail(index) for index in range(count)]
        if self.variant == "name_only":
            trails[0].pop("TrailARN")
        return {"trailList": trails}

    def get_account_summary(self) -> dict[str, Any] | None:
        """Return every known finite IAM counter, or explicit unavailable input."""
        if self.variant in {"unavailable", "denied"}:
            return None
        return {"SummaryMap": {} if self.variant == "empty" else dict(SYNTHETIC_IAM_SUMMARY)}

    def get_trail_status(self, **kwargs: object) -> dict[str, Any]:
        """Retain partial/absent logging state and optional raw diagnostics."""
        del kwargs
        self.status_calls += 1
        if self.variant == "status_unavailable":
            return {}
        return {
            "IsLogging": None if self.variant == "partial" or (self.variant == "capped" and self.status_calls == 1) else True,
            "LatestDeliveryError": "synthetic-customer diagnostic" if self.variant in {"partial", "capped"} else None,
        }


def account_risk_producer_payload(variant: str = "success") -> dict[str, Any]:
    """Call actual provider-response parsing, risk collection and envelope serialization."""
    session = SyntheticAccountRiskSession(variant)
    record = AccountCostRiskCollector(
        session,
        account_id="123456789012",
        audit_context=AwsAuditContext(
            scanner_id="account-cost-risk-signal-review",
            collector="synthetic",
            allowed_api_calls=(),
        ),
    ).collect()
    if variant == "capped" and session.status_calls != 25:  # noqa: PLR2004
        message = "Synthetic account-risk producer did not preserve its status-call bound."
        raise AssertionError(message)
    response = {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": "2026-09-01", "End": "2026-09-02"},
                "Groups": [
                    {
                        "Keys": ["Amazon EC2", "eu-west-2", "synthetic-usage"],
                        "Metrics": {"UnblendedCost": {"Amount": "12.75", "Unit": "USD"}},
                    }
                ],
            }
        ]
    }
    parser = CostExplorerResponseParser()
    daily = parser.parse_daily_cost_response(response, ("SERVICE", "REGION", "USAGE_TYPE"))
    daily.extend(parser.parse_daily_cost_response(response, ("SERVICE", "REGION")))
    return build_scanner_evidence_payload(
        scanner_id="account-cost-risk-signal-review", evidence=AccountCostRiskEvidence(daily_costs=daily, account_risk=record)
    )


def add_account_risk_producer_payload(files: dict[str, bytes], *, unknown_field: bool = False) -> None:
    """Enrich the shared fixture with complete, partial and capped actual observations."""
    primary = account_risk_producer_payload("capped")
    if unknown_field:
        primary["payload"]["account_risk"]["iam_summary"]["unknown_synthetic_field"] = 1
        primary["payload"]["daily_costs"][0]["unknown_synthetic_field"] = {}
    add_scanner_producer_payload(files, primary)
