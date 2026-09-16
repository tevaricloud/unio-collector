from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.audit_cost.cloudtrail.cost.evidence import CloudTrailCostGovernanceEvidence
    from unio_collector.scanners.audit_cost.cloudtrail.cost.scanner import CloudTrailCostGovernanceReviewScanner
    from unio_collector.scanners.audit_cost.helpers import (
        AUDIT_COST_EXECUTION_DETAIL_SPECS,
        AUDIT_COST_EXPLORER_SERVICE_NAMES,
        AUDIT_EVIDENCE_RESOURCE_TYPES,
        AUDIT_EVIDENCE_SERVICE_NAMES,
        AuditCostExecutionDetailSpec,
        add_audit_cost_context,
        build_audit_cost_collector,
        build_audit_cost_evidence_id,
        build_audit_cost_evidence_record,
        build_audit_cost_evidence_records,
        build_audit_cost_evidence_resource_id,
        build_audit_cost_evidence_signal,
        build_audit_cost_execution_detail_note,
        build_waf_association_execution_fields,
        record_audit_cost_execution_detail,
        sum_record_fields,
    )
    from unio_collector.scanners.audit_cost.packs import AUDIT_COST_SCANNER_PACKS, AUDIT_COST_SCANNER_TYPES
    from unio_collector.scanners.config.cost_governance.evidence import ConfigCostGovernanceEvidence
    from unio_collector.scanners.config.cost_governance.scanner import ConfigCostGovernanceReviewScanner
    from unio_collector.scanners.kms.cost_governance.evidence import KmsCostGovernanceEvidence
    from unio_collector.scanners.kms.cost_governance.scanner import KmsCostGovernanceReviewScanner
    from unio_collector.scanners.security_governance.guardduty.evidence import GuardDutyCostGovernanceEvidence
    from unio_collector.scanners.security_governance.guardduty.scanner import GuardDutyCostGovernanceReviewScanner
    from unio_collector.scanners.security_governance.secrets_manager.evidence import SecretsManagerCostGovernanceEvidence
    from unio_collector.scanners.security_governance.secrets_manager.scanner import SecretsManagerCostGovernanceReviewScanner
    from unio_collector.scanners.security_governance.securityhub_inspector_macie.evidence import SecurityHubInspectorMacieCostGovernanceEvidence
    from unio_collector.scanners.security_governance.securityhub_inspector_macie.scanner import SecurityHubInspectorMacieCostReviewScanner
    from unio_collector.scanners.security_governance.waf.evidence import WafCostGovernanceEvidence
    from unio_collector.scanners.security_governance.waf.scanner import WafCostGovernanceReviewScanner

_EXPORTS = {
    "CloudTrailCostGovernanceEvidence": ("unio_collector.scanners.audit_cost.cloudtrail.cost.evidence", "CloudTrailCostGovernanceEvidence"),
    "CloudTrailCostGovernanceReviewScanner": ("unio_collector.scanners.audit_cost.cloudtrail.cost.scanner", "CloudTrailCostGovernanceReviewScanner"),
    "AUDIT_COST_EXECUTION_DETAIL_SPECS": ("unio_collector.scanners.audit_cost.helpers", "AUDIT_COST_EXECUTION_DETAIL_SPECS"),
    "AUDIT_COST_EXPLORER_SERVICE_NAMES": ("unio_collector.scanners.audit_cost.helpers", "AUDIT_COST_EXPLORER_SERVICE_NAMES"),
    "AUDIT_EVIDENCE_RESOURCE_TYPES": ("unio_collector.scanners.audit_cost.helpers", "AUDIT_EVIDENCE_RESOURCE_TYPES"),
    "AUDIT_EVIDENCE_SERVICE_NAMES": ("unio_collector.scanners.audit_cost.helpers", "AUDIT_EVIDENCE_SERVICE_NAMES"),
    "AuditCostExecutionDetailSpec": ("unio_collector.scanners.audit_cost.helpers", "AuditCostExecutionDetailSpec"),
    "add_audit_cost_context": ("unio_collector.scanners.audit_cost.helpers", "add_audit_cost_context"),
    "build_audit_cost_collector": ("unio_collector.scanners.audit_cost.helpers", "build_audit_cost_collector"),
    "build_audit_cost_evidence_id": ("unio_collector.scanners.audit_cost.helpers", "build_audit_cost_evidence_id"),
    "build_audit_cost_evidence_record": ("unio_collector.scanners.audit_cost.helpers", "build_audit_cost_evidence_record"),
    "build_audit_cost_evidence_records": ("unio_collector.scanners.audit_cost.helpers", "build_audit_cost_evidence_records"),
    "build_audit_cost_evidence_resource_id": ("unio_collector.scanners.audit_cost.helpers", "build_audit_cost_evidence_resource_id"),
    "build_audit_cost_evidence_signal": ("unio_collector.scanners.audit_cost.helpers", "build_audit_cost_evidence_signal"),
    "build_audit_cost_execution_detail_note": ("unio_collector.scanners.audit_cost.helpers", "build_audit_cost_execution_detail_note"),
    "build_waf_association_execution_fields": ("unio_collector.scanners.audit_cost.helpers", "build_waf_association_execution_fields"),
    "record_audit_cost_execution_detail": ("unio_collector.scanners.audit_cost.helpers", "record_audit_cost_execution_detail"),
    "sum_record_fields": ("unio_collector.scanners.audit_cost.helpers", "sum_record_fields"),
    "AUDIT_COST_SCANNER_PACKS": ("unio_collector.scanners.audit_cost.packs", "AUDIT_COST_SCANNER_PACKS"),
    "AUDIT_COST_SCANNER_TYPES": ("unio_collector.scanners.audit_cost.packs", "AUDIT_COST_SCANNER_TYPES"),
    "ConfigCostGovernanceEvidence": ("unio_collector.scanners.config.cost_governance.evidence", "ConfigCostGovernanceEvidence"),
    "ConfigCostGovernanceReviewScanner": ("unio_collector.scanners.config.cost_governance.scanner", "ConfigCostGovernanceReviewScanner"),
    "KmsCostGovernanceEvidence": ("unio_collector.scanners.kms.cost_governance.evidence", "KmsCostGovernanceEvidence"),
    "KmsCostGovernanceReviewScanner": ("unio_collector.scanners.kms.cost_governance.scanner", "KmsCostGovernanceReviewScanner"),
    "GuardDutyCostGovernanceEvidence": ("unio_collector.scanners.security_governance.guardduty.evidence", "GuardDutyCostGovernanceEvidence"),
    "GuardDutyCostGovernanceReviewScanner": ("unio_collector.scanners.security_governance.guardduty.scanner", "GuardDutyCostGovernanceReviewScanner"),
    "SecretsManagerCostGovernanceEvidence": ("unio_collector.scanners.security_governance.secrets_manager.evidence", "SecretsManagerCostGovernanceEvidence"),
    "SecretsManagerCostGovernanceReviewScanner": (
        "unio_collector.scanners.security_governance.secrets_manager.scanner",
        "SecretsManagerCostGovernanceReviewScanner",
    ),
    "SecurityHubInspectorMacieCostGovernanceEvidence": (
        "unio_collector.scanners.security_governance.securityhub_inspector_macie.evidence",
        "SecurityHubInspectorMacieCostGovernanceEvidence",
    ),
    "SecurityHubInspectorMacieCostReviewScanner": (
        "unio_collector.scanners.security_governance.securityhub_inspector_macie.scanner",
        "SecurityHubInspectorMacieCostReviewScanner",
    ),
    "WafCostGovernanceEvidence": ("unio_collector.scanners.security_governance.waf.evidence", "WafCostGovernanceEvidence"),
    "WafCostGovernanceReviewScanner": ("unio_collector.scanners.security_governance.waf.scanner", "WafCostGovernanceReviewScanner"),
}

__all__ = [
    "AUDIT_COST_EXECUTION_DETAIL_SPECS",
    "AUDIT_COST_EXPLORER_SERVICE_NAMES",
    "AUDIT_COST_SCANNER_PACKS",
    "AUDIT_COST_SCANNER_TYPES",
    "AUDIT_EVIDENCE_RESOURCE_TYPES",
    "AUDIT_EVIDENCE_SERVICE_NAMES",
    "AuditCostExecutionDetailSpec",
    "CloudTrailCostGovernanceEvidence",
    "CloudTrailCostGovernanceReviewScanner",
    "ConfigCostGovernanceEvidence",
    "ConfigCostGovernanceReviewScanner",
    "GuardDutyCostGovernanceEvidence",
    "GuardDutyCostGovernanceReviewScanner",
    "KmsCostGovernanceEvidence",
    "KmsCostGovernanceReviewScanner",
    "SecretsManagerCostGovernanceEvidence",
    "SecretsManagerCostGovernanceReviewScanner",
    "SecurityHubInspectorMacieCostGovernanceEvidence",
    "SecurityHubInspectorMacieCostReviewScanner",
    "WafCostGovernanceEvidence",
    "WafCostGovernanceReviewScanner",
    "add_audit_cost_context",
    "build_audit_cost_collector",
    "build_audit_cost_evidence_id",
    "build_audit_cost_evidence_record",
    "build_audit_cost_evidence_records",
    "build_audit_cost_evidence_resource_id",
    "build_audit_cost_evidence_signal",
    "build_audit_cost_execution_detail_note",
    "build_waf_association_execution_fields",
    "record_audit_cost_execution_detail",
    "sum_record_fields",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value
