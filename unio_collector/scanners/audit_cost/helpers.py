from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import import_module
from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.audit_cost.cloudtrail.record import (
    CloudTrailCostGovernanceRecord,
)
from unio_collector.aws.audit_cost.config.record import (
    ConfigCostGovernanceRecord,
)
from unio_collector.aws.audit_cost.guardduty.record import (
    GuardDutyCostGovernanceRecord,
)
from unio_collector.aws.audit_cost.kms.record import (
    KmsCostGovernanceRecord,
)
from unio_collector.aws.audit_cost.secrets_manager.record import (
    SecretsManagerCostGovernanceRecord,
)
from unio_collector.aws.audit_cost.security_services.record import (
    SecurityHubInspectorMacieCostGovernanceRecord,
)
from unio_collector.aws.audit_cost.waf.record import (
    WafCostGovernanceRecord,
)
from unio_collector.evidence.models import EvidenceRecord
from unio_collector.scanners.audit_cost.evidence_signals import (
    build_audit_cost_context_missing_signals,
    build_audit_cost_context_source_signal,
    build_audit_cost_evidence_signal,
    build_permission_missing_signals,
    build_waf_collection_missing_signals,
    has_audit_cost_context,
)
from unio_collector.scanners.cost_context import enrich_records_with_cost_context

if TYPE_CHECKING:
    from unio_collector.aws.audit_cost.config.options import (
        ConfigCostGovernanceCollectionOptions,
    )
    from unio_collector.aws.audit_cost.inventory.collector import (
        AuditCostInventoryCollector,
    )
    from unio_collector.aws.audit_cost.waf.options import (
        WafCostGovernanceCollectionOptions,
    )
    from unio_collector.scanners.base import ScannerContext

AUDIT_COST_EXPLORER_SERVICE_NAMES: dict[str, tuple[str, ...]] = {
    "cloudtrail-cost-governance-review": ("AWS CloudTrail",),
    "config-cost-governance-review": ("AWS Config",),
    "guardduty-cost-governance-review": ("Amazon GuardDuty",),
    "kms-cost-governance-review": ("AWS Key Management Service",),
    "secrets-manager-cost-governance-review": ("AWS Secrets Manager",),
    "securityhub-inspector-macie-cost-review": (
        "AWS Security Hub",
        "Amazon Inspector",
        "Amazon Macie",
    ),
    "waf-cost-governance-review": ("AWS WAF", "AWS WAFV2"),
}

AUDIT_EVIDENCE_SERVICE_NAMES: dict[str, str] = {
    "cloudtrail-cost-governance-review": "AWS CloudTrail",
    "config-cost-governance-review": "AWS Config",
    "guardduty-cost-governance-review": "Amazon GuardDuty",
    "kms-cost-governance-review": "AWS Key Management Service",
    "secrets-manager-cost-governance-review": "AWS Secrets Manager",
    "securityhub-inspector-macie-cost-review": ("AWS Security Hub, Inspector, and Macie"),
    "waf-cost-governance-review": "AWS WAF",
}

AUDIT_EVIDENCE_RESOURCE_TYPES: dict[str, str] = {
    "cloudtrail-cost-governance-review": "CloudTrail audit summary",
    "config-cost-governance-review": "AWS Config audit summary",
    "guardduty-cost-governance-review": "GuardDuty audit summary",
    "kms-cost-governance-review": "KMS governance summary",
    "secrets-manager-cost-governance-review": "Secrets Manager governance summary",
    "securityhub-inspector-macie-cost-review": ("Security service governance summary"),
    "waf-cost-governance-review": "WAF governance summary",
}

type AuditCostRecord = (
    CloudTrailCostGovernanceRecord
    | ConfigCostGovernanceRecord
    | GuardDutyCostGovernanceRecord
    | KmsCostGovernanceRecord
    | SecurityHubInspectorMacieCostGovernanceRecord
    | SecretsManagerCostGovernanceRecord
    | WafCostGovernanceRecord
)


@dataclass(frozen=True)
class AuditCostExecutionDetailSpec:  # noqa: D101
    service_label: str
    resource_label: str
    resource_count_fields: tuple[str, ...]
    detail_count_fields: tuple[str, ...]


AUDIT_COST_EXECUTION_DETAIL_SPECS: dict[str, AuditCostExecutionDetailSpec] = {
    "cloudtrail-cost-governance-review": AuditCostExecutionDetailSpec(
        service_label="CloudTrail",
        resource_label="trail or event data store",
        resource_count_fields=("trail_count", "event_data_store_count"),
        detail_count_fields=(
            "trail_count",
            "data_event_selector_count",
            "insight_selector_count",
            "event_data_store_count",
        ),
    ),
    "config-cost-governance-review": AuditCostExecutionDetailSpec(
        service_label="AWS Config",
        resource_label="recorder, rule, or conformance pack",
        resource_count_fields=(
            "recorder_count",
            "config_rule_count",
            "conformance_pack_count",
        ),
        detail_count_fields=(
            "recorder_count",
            "all_supported_recording_count",
            "config_rule_count",
            "conformance_pack_count",
        ),
    ),
    "guardduty-cost-governance-review": AuditCostExecutionDetailSpec(
        service_label="GuardDuty",
        resource_label="detector or protection feature",
        resource_count_fields=("detector_count", "enabled_feature_count"),
        detail_count_fields=(
            "detector_count",
            "enabled_feature_count",
            "disabled_feature_count",
        ),
    ),
    "kms-cost-governance-review": AuditCostExecutionDetailSpec(
        service_label="KMS",
        resource_label="key or alias",
        resource_count_fields=("key_count", "alias_count"),
        detail_count_fields=(
            "listed_key_count",
            "key_count",
            "customer_managed_key_count",
            "multi_region_key_count",
            "disabled_customer_key_count",
            "alias_count",
        ),
    ),
    "secrets-manager-cost-governance-review": AuditCostExecutionDetailSpec(
        service_label="Secrets Manager",
        resource_label="secret",
        resource_count_fields=("secret_count",),
        detail_count_fields=(
            "secret_count",
            "active_secret_count",
            "rotation_disabled_secret_count",
            "missing_last_access_secret_count",
            "replica_secret_count",
        ),
    ),
    "securityhub-inspector-macie-cost-review": AuditCostExecutionDetailSpec(
        service_label="Security Hub, Inspector, and Macie",
        resource_label="security-service control",
        resource_count_fields=(
            "securityhub_standard_count",
            "macie_classification_job_count",
        ),
        detail_count_fields=(
            "securityhub_standard_count",
            "inspector_enabled",
            "macie_enabled",
            "macie_classification_job_count",
        ),
    ),
    "waf-cost-governance-review": AuditCostExecutionDetailSpec(
        service_label="WAF",
        resource_label="web ACL or managed rule group",
        resource_count_fields=("web_acl_count", "managed_rule_group_count"),
        detail_count_fields=(
            "web_acl_count",
            "managed_rule_group_count",
            "rate_based_rule_count",
            "associated_resource_count",
        ),
    ),
}


def build_audit_cost_collector(  # noqa: D103
    context: ScannerContext,
    *,
    config_collection_options: ConfigCostGovernanceCollectionOptions | None = None,
    waf_collection_options: WafCostGovernanceCollectionOptions | None = None,
) -> AuditCostInventoryCollector:
    collector_class = import_module(
        "unio_collector.aws.audit_cost.inventory.collector",
    ).AuditCostInventoryCollector
    return context.security.create_regional_inventory_collector(
        collector_class,
        collector_name="AuditCostInventoryCollector",
        config_collection_options=config_collection_options,
        waf_collection_options=waf_collection_options,
    )


def add_audit_cost_context[TAuditCostRecord: AuditCostRecord](  # noqa: D103
    records: list[TAuditCostRecord],
    context: ScannerContext,
) -> list[TAuditCostRecord]:
    service_names = AUDIT_COST_EXPLORER_SERVICE_NAMES.get(
        context.definition.scanner_id,
        (),
    )
    if not records or not service_names:
        return records
    try:
        service_costs = context.costs.collect_service_costs()
        regional_costs = context.costs.collect_daily_costs(
            group_keys=("SERVICE", "REGION"),
        )
    except Exception as exc:  # noqa: BLE001
        code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
        context.warnings.add(
            (f"Cost Explorer context was unavailable for this audit-service scanner; metadata findings continued ({code})."),
        )
        return records
    return enrich_records_with_cost_context(
        records,
        service_names=service_names,
        service_costs=service_costs,
        daily_costs=regional_costs,
    )


def record_audit_cost_execution_detail[TAuditCostRecord: AuditCostRecord](  # noqa: D103
    context: ScannerContext,
    records: list[TAuditCostRecord],
    *,
    regions: list[str],
) -> None:
    context.warnings.add_coverage_note(
        build_audit_cost_execution_detail_note(
            context.definition.scanner_id,
            records,
            regions=regions,
        ),
    )


def build_audit_cost_execution_detail_note[TAuditCostRecord: AuditCostRecord](  # noqa: D103
    scanner_id: str,
    records: list[TAuditCostRecord],
    *,
    regions: list[str],
) -> dict[str, Any]:
    spec = AUDIT_COST_EXECUTION_DETAIL_SPECS.get(
        scanner_id,
        AuditCostExecutionDetailSpec(
            service_label="audit-service",
            resource_label="metadata record",
            resource_count_fields=(),
            detail_count_fields=(),
        ),
    )
    resource_count = sum_record_fields(records, spec.resource_count_fields)
    detail_counts = {field: sum_record_fields(records, (field,)) for field in spec.detail_count_fields}
    billing_context_count = sum(1 for record in records if has_audit_cost_context(record))
    permission_error_count = sum(len(getattr(record, "permission_errors", [])) for record in records)
    if billing_context_count:
        billing_phrase = f"service or regional billing context was available on {billing_context_count} record(s)"
    else:
        billing_phrase = "no matching service or regional billing context was attached to the collected metadata"
    note = {
        "note_type": "execution_detail",
        "scanner_id": scanner_id,
        "scope_area": "audit_service_metadata",
        "summary": (
            f"{spec.service_label} cost governance review collected "
            f"{resource_count} {spec.resource_label}(s) across "
            f"{len(records)} region/scope record(s); {billing_phrase}. "
            "This is not resource-level or control-level cost attribution."
        ),
        "regions_attempted": list(regions),
        "region_record_count": len(records),
        "resource_label": spec.resource_label,
        "resource_count": resource_count,
        "detail_counts": detail_counts,
        "billing_context_record_count": billing_context_count,
        "permission_error_count": permission_error_count,
        "result_scope": "metadata_with_optional_billing_context",
        "impact": ("This read-only note explains audit-service metadata and billing context coverage; it does not change AWS resources or security controls."),
    }
    if scanner_id == "waf-cost-governance-review":
        note.update(build_waf_association_execution_fields(records))
    return note


def build_waf_association_execution_fields[TAuditCostRecord: AuditCostRecord](  # noqa: D103
    records: list[TAuditCostRecord],
) -> dict[str, Any]:
    waf_records = [record for record in records if isinstance(record, WafCostGovernanceRecord)]
    if not waf_records:
        return {}
    collected_count = sum(1 for record in waf_records if record.association_metadata_collected)
    return {
        "association_detail_modes": sorted(
            {record.association_detail_mode for record in waf_records},
        ),
        "association_metadata_collected_record_count": collected_count,
        "association_metadata_skipped_record_count": (len(waf_records) - collected_count),
    }


def sum_record_fields[TAuditCostRecord: AuditCostRecord](  # noqa: D103
    records: list[TAuditCostRecord],
    fields: tuple[str, ...],
) -> int:
    total = 0
    for record in records:
        for field_name in fields:
            value = getattr(record, field_name, 0)
            if isinstance(value, bool):
                total += int(value)
            elif isinstance(value, int):
                total += value
    return total


def build_audit_cost_evidence_records[TAuditCostRecord: AuditCostRecord](  # noqa: D103
    scanner_id: str,
    records: list[TAuditCostRecord],
    *,
    collection_time: datetime | None = None,
) -> list[EvidenceRecord]:
    resolved_collection_time = collection_time or datetime.now(UTC)
    return [
        build_audit_cost_evidence_record(
            scanner_id,
            record,
            index=index,
            collection_time=resolved_collection_time,
        )
        for index, record in enumerate(records, start=1)
    ]


def build_audit_cost_evidence_record(  # noqa: D103
    scanner_id: str,
    record: AuditCostRecord,
    *,
    index: int,
    collection_time: datetime,
) -> EvidenceRecord:
    signal = build_audit_cost_evidence_signal(scanner_id, record)
    permission_errors = list(getattr(record, "permission_errors", []))
    costs = [build_audit_cost_context_source_signal(record)] if has_audit_cost_context(record) else []
    return EvidenceRecord(
        evidence_id=build_audit_cost_evidence_id(scanner_id, record, index),
        source_scanner_id=scanner_id,
        collector_id="AuditCostInventoryCollector",
        account_id=getattr(record, "account_id", None),
        region=getattr(record, "region", "global"),
        service=AUDIT_EVIDENCE_SERVICE_NAMES.get(scanner_id, "AWS audit service"),
        resource_type=AUDIT_EVIDENCE_RESOURCE_TYPES.get(
            scanner_id,
            "Audit service governance summary",
        ),
        resource_id=build_audit_cost_evidence_resource_id(scanner_id, record),
        metrics=[signal],
        costs=costs,
        collection_time=collection_time,
        confidence="medium" if permission_errors else "high",
        limitations=(
            build_permission_missing_signals(permission_errors)
            + build_audit_cost_context_missing_signals(record)
            + build_waf_collection_missing_signals(record)
        ),
    )


def build_audit_cost_evidence_id(  # noqa: D103
    scanner_id: str,
    record: AuditCostRecord,
    index: int,
) -> str:
    return f"{scanner_id}:{getattr(record, 'region', 'global')}:{getattr(record, 'scope', 'regional')}:{index}"


def build_audit_cost_evidence_resource_id(  # noqa: D103
    scanner_id: str,
    record: AuditCostRecord,
) -> str:
    scope = getattr(record, "scope", None)
    suffix = f":{scope}" if scope else ""
    return f"{scanner_id}:{getattr(record, 'region', 'global')}{suffix}"
