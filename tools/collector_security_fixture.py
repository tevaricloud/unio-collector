"""Actual security/config producer fixtures using fixed offline endpoints only."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

from botocore.exceptions import ClientError

from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.scanners.config.compliance.collector import AwsConfigComplianceReviewCollector
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.security_finding.active.collector import ActiveSecurityFindingReviewCollector

if TYPE_CHECKING:
    from collections.abc import Iterator


SCANNERS = {"active-security-finding-review": ActiveSecurityFindingReviewCollector, "aws-config-compliance-review": AwsConfigComplianceReviewCollector}
VARIANTS = ("success", "empty", "denied", "unavailable", "unsupported", "optional", "inactive", "fallback", "partial")


def _security_context(variant: str) -> Mock:
    c = Mock()
    c.options.get_selected_regions.return_value = ["eu-west-2"]
    gd = Mock()
    hub = Mock()
    config = Mock()
    finding = {
        "Id": "synthetic-customer-finding",
        "Region": "eu-west-2",
        "Title": "synthetic-customer-title",
        "Description": "synthetic-customer-diagnostic",
        "Severity": 5.0,
        "Type": "Synthetic/Observation",
        "UpdatedAt": datetime(2026, 9, 1, tzinfo=UTC),
        "Resource": {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "synthetic-customer-instance"}},
    }
    gd.list_detectors.return_value = {"DetectorIds": ["synthetic-detector"]}
    gd.get_paginator.return_value.paginate.return_value = [{"FindingIds": ["synthetic-customer-finding"]}]
    gd.get_findings.return_value = {"Findings": [finding]}
    hub.get_paginator.return_value.paginate.return_value = [
        {
            "Findings": [
                {
                    "Id": "synthetic-customer-hub-finding",
                    "Region": "eu-west-2",
                    "Title": "synthetic-customer-title",
                    "Severity": {"Label": "HIGH"},
                    "Resources": [{"Type": "AwsEc2Instance", "Id": "synthetic-customer-instance"}],
                    "Types": ["Synthetic/Observation"],
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                    "UpdatedAt": "2026-09-01T00:00:00Z",
                }
            ]
        }
    ]
    responses = {
        "describe_compliance_by_config_rule": {
            "ComplianceByConfigRules": [
                {"ConfigRuleName": "synthetic-customer-rule", "Compliance": {"ComplianceType": "NON_COMPLIANT", "Annotation": "synthetic-customer-annotation"}}
            ]
        },
        "describe_conformance_packs": {"ConformancePackDetails": [{"ConformancePackName": "synthetic-customer-pack"}]},
        "describe_conformance_pack_compliance": {
            "ConformancePackRuleComplianceList": [
                {"ConfigRuleName": "synthetic-customer-rule", "ComplianceType": "NON_COMPLIANT", "Controls": ["synthetic-customer-control"]}
            ]
        },
    }

    def paginator(name: str) -> Mock:
        p = Mock()
        p.paginate.return_value = [responses[name]]
        return p

    config.get_paginator.side_effect = paginator
    if variant == "empty":
        gd.list_detectors.return_value = {"DetectorIds": []}
        hub.get_paginator.return_value.paginate.return_value = [{"Findings": []}]
        responses["describe_compliance_by_config_rule"] = {"ComplianceByConfigRules": []}
        responses["describe_conformance_packs"] = {"ConformancePackDetails": []}
    if variant == "optional":
        gd.get_findings.return_value = {"Findings": [{"Id": "synthetic-customer-finding"}]}
        hub.get_paginator.return_value.paginate.return_value = [{"Findings": [{"Id": "synthetic-customer-hub-finding"}]}]
        responses["describe_compliance_by_config_rule"]["ComplianceByConfigRules"][0]["Compliance"].pop("Annotation")
        responses["describe_conformance_pack_compliance"]["ConformancePackRuleComplianceList"][0]["Controls"] = []
    if variant == "inactive":
        hub.get_paginator.return_value.paginate.return_value = [
            {
                "Findings": [
                    {"Id": "synthetic-archived", "RecordState": "ARCHIVED"},
                    {"Id": "synthetic-resolved", "Workflow": {"Status": "RESOLVED"}},
                    {"Id": "synthetic-suppressed", "Workflow": {"Status": "SUPPRESSED"}},
                ]
            }
        ]
    if variant == "fallback":
        hub.get_findings.return_value = hub.get_paginator.return_value.paginate.return_value[0]
        hub.get_paginator.side_effect = NotImplementedError("Synthetic paginator unavailable")
        gd.get_paginator.side_effect = NotImplementedError("Synthetic paginator unavailable")
        gd.list_findings.return_value = {"FindingIds": ["synthetic-customer-finding"]}
        config.get_paginator.side_effect = NotImplementedError("Synthetic paginator unavailable")
        for operation, response in responses.items():
            getattr(config, operation).return_value = response
    if variant == "partial":

        def partial_page(response: dict[str, Any]) -> Iterator[dict[str, Any]]:
            yield response
            raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "Synthetic page interruption"}}, "GetFindings")

        hub_response = hub.get_paginator.return_value.paginate.return_value[0]
        hub.get_paginator.return_value.paginate.side_effect = lambda: partial_page(hub_response)

        def partial_paginator(name: str) -> Mock:
            p = Mock()
            p.paginate.side_effect = lambda **_kwargs: partial_page(responses[name])
            return p

        config.get_paginator.side_effect = partial_paginator
    _apply_unavailable(gd, hub, config, variant)
    c.security.create_client.side_effect = lambda service, **_kwargs: {"guardduty": gd, "securityhub": hub, "config": config}[service]
    return c


def security_producer_payload(scanner_id: str, variant: str = "success") -> dict[str, Any]:
    """Serialize complete actual collector output, including limited observations."""
    if variant not in VARIANTS:
        message = "Unknown synthetic security producer variant."
        raise ValueError(message)
    evidence = SCANNERS[scanner_id](Mock(scanner_id=scanner_id)).collect(_security_context(variant))
    return build_scanner_evidence_payload(scanner_id=scanner_id, evidence=evidence)


def add_security_producer_payloads(files: dict[str, bytes], *, unknown_field: bool = False) -> None:
    """Enrich shared smoke with populated partial security/config observations."""
    for scanner_id in SCANNERS:
        row = security_producer_payload(scanner_id, "partial")
        if unknown_field:
            payload = row["payload"]
            target = payload["findings"][0] if scanner_id == "active-security-finding-review" else payload["conformance_pack_records"][0]
            target["unknown_synthetic_field"] = {}
        add_scanner_producer_payload(files, row)


def _apply_unavailable(gd: Mock, hub: Mock, config: Mock, variant: str) -> None:
    """Apply explicit synthetic failure responses to all relevant endpoints."""
    if variant in ("denied", "unavailable", "unsupported"):
        error = ClientError(
            {
                "Error": {
                    "Code": {"denied": "AccessDeniedException", "unavailable": "InvalidAccessException", "unsupported": "UnknownOperationException"}[variant],
                    "Message": "Synthetic unavailable or denied",
                }
            },
            "GetFindings",
        )
        gd.list_detectors.side_effect = error
        hub.get_paginator.side_effect = error
        hub.get_findings.side_effect = error
        config.get_paginator.side_effect = error
        config.describe_compliance_by_config_rule.side_effect = error
        config.describe_conformance_packs.side_effect = error
