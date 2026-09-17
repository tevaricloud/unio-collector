from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.audit_cost.cloudtrail.record import (
        CloudTrailCostGovernanceRecord,
    )
    from unio_collector.aws.audit_cost.config.options import (
        ConfigCostGovernanceCollectionOptions,
    )
    from unio_collector.aws.audit_cost.config.record import ConfigCostGovernanceRecord
    from unio_collector.aws.audit_cost.guardduty.record import (
        GuardDutyCostGovernanceRecord,
    )
    from unio_collector.aws.audit_cost.inventory.collector import (
        AuditCostInventoryCollector,
    )
    from unio_collector.aws.audit_cost.kms.record import KmsCostGovernanceRecord
    from unio_collector.aws.audit_cost.secrets_manager.record import (
        SecretsManagerCostGovernanceRecord,
    )
    from unio_collector.aws.audit_cost.security_services.record import (
        SecurityHubInspectorMacieCostGovernanceRecord,
    )
    from unio_collector.aws.audit_cost.waf.options import (
        WafCostGovernanceCollectionOptions,
    )
    from unio_collector.aws.audit_cost.waf.record import WafCostGovernanceRecord

__all__ = [
    "AuditCostInventoryCollector",
    "CloudTrailCostGovernanceRecord",
    "ConfigCostGovernanceCollectionOptions",
    "ConfigCostGovernanceRecord",
    "GuardDutyCostGovernanceRecord",
    "KmsCostGovernanceRecord",
    "SecretsManagerCostGovernanceRecord",
    "SecurityHubInspectorMacieCostGovernanceRecord",
    "WafCostGovernanceCollectionOptions",
    "WafCostGovernanceRecord",
]


def _load_symbol(module_name: str, symbol_name: str) -> Any:  # noqa: ANN401
    return getattr(import_module(module_name), symbol_name)


def __getattr__(name: str) -> Any:  # noqa: ANN401, C901
    if name == "AuditCostInventoryCollector":
        return _load_symbol(
            "unio_collector.aws.audit_cost.inventory.collector",
            "AuditCostInventoryCollector",
        )
    if name == "CloudTrailCostGovernanceRecord":
        return _load_symbol(
            "unio_collector.aws.audit_cost.cloudtrail.record",
            "CloudTrailCostGovernanceRecord",
        )
    if name == "ConfigCostGovernanceCollectionOptions":
        return _load_symbol(
            "unio_collector.aws.audit_cost.config.options",
            "ConfigCostGovernanceCollectionOptions",
        )
    if name == "ConfigCostGovernanceRecord":
        return _load_symbol(
            "unio_collector.aws.audit_cost.config.record",
            "ConfigCostGovernanceRecord",
        )
    if name == "GuardDutyCostGovernanceRecord":
        return _load_symbol(
            "unio_collector.aws.audit_cost.guardduty.record",
            "GuardDutyCostGovernanceRecord",
        )
    if name == "KmsCostGovernanceRecord":
        return _load_symbol(
            "unio_collector.aws.audit_cost.kms.record",
            "KmsCostGovernanceRecord",
        )
    if name == "SecretsManagerCostGovernanceRecord":
        return _load_symbol(
            "unio_collector.aws.audit_cost.secrets_manager.record",
            "SecretsManagerCostGovernanceRecord",
        )
    if name == "SecurityHubInspectorMacieCostGovernanceRecord":
        return _load_symbol(
            "unio_collector.aws.audit_cost.security_services.record",
            "SecurityHubInspectorMacieCostGovernanceRecord",
        )
    if name == "WafCostGovernanceCollectionOptions":
        return _load_symbol(
            "unio_collector.aws.audit_cost.waf.options",
            "WafCostGovernanceCollectionOptions",
        )
    if name == "WafCostGovernanceRecord":
        return _load_symbol(
            "unio_collector.aws.audit_cost.waf.record",
            "WafCostGovernanceRecord",
        )
    raise AttributeError(name)
