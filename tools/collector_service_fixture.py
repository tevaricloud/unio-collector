"""Actual service coverage collectors driven by synthetic offline provider responses."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.scanners.lightsail.collector import LightsailCostGovernanceReviewCollector
from unio_collector.scanners.route53.collector import Route53CostGovernanceReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.sns.collector import SnsCostGovernanceReviewCollector
from unio_collector.scanners.step_functions.collector import StepFunctionsCostGovernanceReviewCollector

COLLECTORS = {
    "route53-cost-governance-review": (Route53CostGovernanceReviewCollector, "route53"),
    "sns-cost-governance-review": (SnsCostGovernanceReviewCollector, "sns"),
    "step-functions-cost-governance-review": (StepFunctionsCostGovernanceReviewCollector, "stepfunctions"),
    "lightsail-cost-governance-review": (LightsailCostGovernanceReviewCollector, "lightsail"),
}
VARIANTS = (
    "success",
    "nullable",
    "denied",
    "unavailable",
    "unsupported",
    "failure",
    "detail-denied",
    "partial",
    "malformed-detail",
    "finding",
    "empty",
    "collision",
)
LIGHTSAIL_OPERATIONS = {
    "get_instances": "instances",
    "get_static_ips": "staticIps",
    "get_disks": "disks",
    "get_load_balancers": "loadBalancers",
    "get_relational_databases": "relationalDatabases",
    "get_buckets": "buckets",
    "get_container_services": "containerServices",
}


class SyntheticServiceSession:
    """Expose only explicit, in-memory fixture operations; never construct an AWS client."""

    def __init__(self, service: str, variant: str) -> None:
        """Bind a service and one deterministic collection outcome."""
        self.service = service
        self.variant = variant

    def create_client(self, service: str, **kwargs: Any) -> SyntheticServiceSession:  # noqa: ANN401
        """Reject attempts to leave the selected synthetic service and region."""
        if service != self.service or kwargs.get("region_name") != ("us-east-1" if service == "route53" else "eu-west-2"):
            message = "Unexpected synthetic service or region."
            raise AssertionError(message)
        return self

    def can_paginate(self, _operation: str) -> bool:
        """Exercise the current non-paginator response admission path."""
        return False

    def __getattr__(self, operation: str) -> Any:  # noqa: ANN401
        """Resolve only named fixture operations, without any provider connection."""
        responses = self._responses()
        if operation not in responses:
            raise AttributeError(operation)

        def invoke(**_kwargs: Any) -> dict[str, Any]:  # noqa: ANN401
            codes = {"denied": "AccessDenied", "unavailable": "ServiceUnavailable", "unsupported": "UnsupportedOperation"}
            code = codes.get(self.variant)
            if self.variant == "detail-denied" and operation in {"get_topic_attributes", "list_tags_for_resource"}:
                code = "AccessDenied"
            if self.variant == "partial" and operation in {"list_health_checks", "list_activities", "get_buckets"}:
                code = "AccessDenied"
            if code:
                raise ClientError({"Error": {"Code": code, "Message": "synthetic-only failure"}}, operation)
            if self.variant == "failure":
                message = "synthetic-only local failure"
                raise RuntimeError(message)
            if self.variant == "empty":
                return {key: [] if isinstance(value, list) else value for key, value in responses[operation].items()}
            return responses[operation]

        return invoke

    def _responses(self) -> dict[str, dict[str, Any]]:
        nullable = self.variant == "nullable"
        malformed = self.variant == "malformed-detail"
        topic = "arn:aws:sns:eu-west-2:123456789012:" + ("true" if self.variant == "collision" else "synthetic-customer-topic")
        machine = "arn:aws:states:eu-west-2:123456789012:stateMachine:synthetic-customer-machine"
        activity = "arn:aws:states:eu-west-2:123456789012:activity:synthetic-customer-activity"
        if self.service == "route53":
            return {
                "list_hosted_zones": {
                    "HostedZones": [
                        {
                            "Id": "/hostedzone/synthetic-zone",
                            "Name": "synthetic-customer.example.invalid",
                            "ResourceRecordSetCount": None if nullable else 7,
                            "Config": {} if nullable else {"PrivateZone": True},
                        }
                    ]
                },
                "list_health_checks": {
                    "HealthChecks": [
                        {
                            "Id": "synthetic-health",
                            "CallerReference": "HTTPS" if self.variant == "collision" else "synthetic-customer-reference",
                            "HealthCheckConfig": {} if nullable else {"Type": "HTTPS"},
                        }
                    ]
                },
                "list_traffic_policies": {
                    "TrafficPolicySummaries": [{"Id": "synthetic-policy", "Name": "synthetic-customer-policy", "Type": None if nullable else "A"}]
                },
            }
        if self.service == "sns":
            return {
                "list_topics": {"Topics": [{"TopicArn": topic}]},
                "get_topic_attributes": {
                    "Attributes": {}
                    if nullable
                    else {
                        "SubscriptionsConfirmed": "synthetic-customer-count" if malformed else "0" if self.variant == "finding" else "17",
                        "KmsMasterKeyId": "arn:aws:kms:eu-west-2:123456789012:key/synthetic-key",
                        "FifoTopic": "true",
                    }
                },
                "list_tags_for_resource": {"Tags": None if malformed else [{"Key": "Name", "Value": "synthetic-customer"}]},
            }
        if self.service == "stepfunctions":
            return {
                "list_state_machines": {
                    "stateMachines": [
                        {
                            "stateMachineArn": machine,
                            "name": "STANDARD" if self.variant == "collision" else "synthetic-customer-machine",
                            **({} if nullable else {"type": "STANDARD", "creationDate": "2026-01-02T03:04:05Z"}),
                        }
                    ]
                },
                "list_activities": {"activities": [{"activityArn": activity, "name": "synthetic-customer-activity", "creationDate": "2026-01-02T03:04:05Z"}]},
                "list_tags_for_resource": {
                    "tags": None if malformed else [] if self.variant == "finding" else [{"key": "Name", "value": "synthetic-customer"}]
                },
            }
        responses = {}
        for operation, key in LIGHTSAIL_OPERATIONS.items():
            item = {
                "arn": f"arn:aws:lightsail:eu-west-2:123456789012:{key}/synthetic-resource",
                "name": "stopped" if self.variant == "collision" else "synthetic-customer-resource",
                "tags": [{"key": "Name", "value": "synthetic-customer"}],
            }
            if not nullable:
                item.update(
                    state={"name": "stopped"},
                    isAttached=self.variant != "finding",
                    attachedTo=None if self.variant == "finding" else "synthetic-customer-host",
                    blueprintId="amazon_linux_2023",
                    bundleId="nano_3_0",
                )
            responses[operation] = {key: [item]}
        return responses


def service_producer_case(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Run the actual wrapper, gateways and serializer using populated synthetic responses."""
    if scanner not in COLLECTORS or variant not in VARIANTS:
        message = "Unknown synthetic service coverage case."
        raise ValueError(message)
    collector_type, service = COLLECTORS[scanner]
    definition: Any = SimpleNamespace(scanner_id=scanner, display_name=scanner)
    session = SyntheticServiceSession(service, variant)
    state = SimpleNamespace(account_id="123456789012", session=session, get_selected_regions=lambda: ["eu-west-2"], has_explicit_region_scope=lambda: True)
    warnings: list[str] = []
    runtime: Any = SimpleNamespace(
        runtime_state=state,
        get_cached_ec2_regions=lambda _definition: ["eu-west-2"],
        create_audit_context=lambda *_args: None,
        add_scanner_warning=lambda _scanner, message: warnings.append(message),
    )
    evidence = collector_type(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return build_scanner_evidence_payload(scanner_id=scanner, evidence=evidence)


def add_service_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Include real populated and conditional producer branches in packaged smoke."""
    for scanner in COLLECTORS:
        row = service_producer_case(scanner)
        for variant in VARIANTS:
            if variant == "success":
                continue
            extra = service_producer_case(scanner, variant)["payload"]
            row["payload"]["records"].extend(extra["records"])
            row["payload"]["warnings"].extend(extra["warnings"])
            for key, value in extra["metadata"].items():
                if key.endswith("_count"):
                    row["payload"]["metadata"][key] += value
        if unknown:
            row["payload"]["records"][0]["attributes"]["unknown_service_container"] = {}
        add_scanner_producer_payload(files, row)
