"""Factual provider security finding fields and collection availability."""

from __future__ import annotations

from math import isfinite
from typing import Any

from unio_collector.aws import errors as aws_errors


def securityhub_finding_is_inactive(finding: dict[str, Any]) -> bool:  # noqa: D103
    record_state = str(finding.get("RecordState") or "").upper()
    workflow = finding.get("Workflow", {})
    workflow_status = str(workflow.get("Status") or "").upper() if isinstance(workflow, dict) else ""
    return record_state == "ARCHIVED" or workflow_status in {
        "RESOLVED",
        "SUPPRESSED",
    }


def securityhub_findings_unavailable(error: Exception) -> bool:  # noqa: D103
    return aws_errors.is_service_unavailable_error(
        error,
        service_name="securityhub",
        operation_name="GetFindings",
    )


def append_securityhub_unavailable_warning(  # noqa: D103
    warnings: list[str],
    region: str,
) -> None:
    warnings.append(
        f"Security Hub findings were not collected in {region} because Security Hub is not enabled or the account is not subscribed in that region.",
    )


def extract_securityhub_resource(  # noqa: D103
    finding: dict[str, Any],
) -> tuple[str | None, str | None]:
    resources = finding.get("Resources", [])
    if not isinstance(resources, list) or not resources:
        return None, None
    resource = resources[0]
    if not isinstance(resource, dict):
        return None, None
    return (
        str(resource.get("Type")) if resource.get("Type") else None,
        str(resource.get("Id")) if resource.get("Id") else None,
    )


def extract_guardduty_resource(  # noqa: D103
    finding: dict[str, Any],
) -> tuple[str | None, str | None]:
    resource = finding.get("Resource", {})
    if not isinstance(resource, dict):
        return None, None
    resource_type = resource.get("ResourceType")
    detail_keys = (
        ("InstanceDetails", "InstanceId"),
        ("AccessKeyDetails", "AccessKeyId"),
        ("S3BucketDetails", "Name"),
        ("KubernetesDetails", "KubernetesWorkloadDetails"),
        ("RdsDbInstanceDetails", "DbInstanceIdentifier"),
        ("EbsVolumeDetails", "VolumeArn"),
    )
    for detail_key, id_key in detail_keys:
        detail = resource.get(detail_key)
        if isinstance(detail, dict) and detail.get(id_key):
            return str(resource_type or detail_key), str(detail[id_key])
        if isinstance(detail, list) and detail:
            first = detail[0]
            if isinstance(first, dict) and first.get(id_key):
                return str(resource_type or detail_key), str(first[id_key])
    return str(resource_type) if resource_type else None, None


def retain_provider_severity(value: object) -> str | int | float | None:
    """Retain a provider scalar or explicit unknown, without assigning severity."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        try:
            return value if isfinite(value) else None
        except OverflowError:
            return None
    if isinstance(value, str):
        label = value.strip()
        if label.casefold() in {"critical", "high", "medium", "low", "info", "informational", "notice"}:
            return label
    return None
