from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any, TypeVar

from unio_collector.aws.audit_cost.config.options import (
    ConfigCostGovernanceCollectionOptions,
)
from unio_collector.aws.audit_cost.inventory.cloudtrail import (
    PrimaryAuditCollectionMixin,
)
from unio_collector.aws.audit_cost.inventory.collect import AuditServiceHelperMixin
from unio_collector.aws.audit_cost.inventory.keys import KeySecretAuditCollectionMixin
from unio_collector.aws.audit_cost.inventory.metrics import AuditMetricHelperMixin
from unio_collector.aws.audit_cost.inventory.resources import AuditResourceHelperMixin
from unio_collector.aws.audit_cost.inventory.security import SecurityAuditCollectionMixin
from unio_collector.aws.audit_cost.waf.options import (
    WafCostGovernanceCollectionOptions,
)
from unio_collector.aws.inventory_helpers import RegionalInventoryCollectionHelper
from unio_collector.aws.pagination import AwsPaginationHelper

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.audit_cost.cloudtrail.record import (
        CloudTrailCostGovernanceRecord,
    )
    from unio_collector.aws.audit_cost.config.record import ConfigCostGovernanceRecord
    from unio_collector.aws.audit_cost.guardduty.record import (
        GuardDutyCostGovernanceRecord,
    )
    from unio_collector.aws.audit_cost.kms.record import KmsCostGovernanceRecord
    from unio_collector.aws.audit_cost.secrets_manager.record import (
        SecretsManagerCostGovernanceRecord,
    )
    from unio_collector.aws.audit_cost.security_services.record import (
        SecurityHubInspectorMacieCostGovernanceRecord,
    )
    from unio_collector.aws.audit_cost.waf.record import WafCostGovernanceRecord

AuditRecordT = TypeVar("AuditRecordT")


class AuditCostInventoryCollector(
    PrimaryAuditCollectionMixin,
    SecurityAuditCollectionMixin,
    KeySecretAuditCollectionMixin,
    AuditServiceHelperMixin,
    AuditMetricHelperMixin,
    AuditResourceHelperMixin,
):
    """Collect read-only audit-service metadata for cost governance scanners."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
        config_collection_options: (ConfigCostGovernanceCollectionOptions | None) = None,
        waf_collection_options: WafCostGovernanceCollectionOptions | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self.config_collection_options = config_collection_options or ConfigCostGovernanceCollectionOptions()
        self.waf_collection_options = waf_collection_options or WafCostGovernanceCollectionOptions()
        self._pagination = AwsPaginationHelper()
        self._regional_collection = RegionalInventoryCollectionHelper(
            self.session,
            account_id=self.account_id,
            audit_context=self.audit_context,
            collector_id="AuditCostInventoryCollector",
        )
        self._available_regions_cache: list[str] | None = None

    def collect_cloudtrail_records(  # noqa: D102
        self,
    ) -> list[CloudTrailCostGovernanceRecord]:
        return self._collect_regional_records(
            regions=self.get_available_regions(),
            service="cloudtrail",
            operation=("DescribeTrails+GetTrailStatus+GetEventSelectors+GetInsightSelectors"),
            collect_region=self._collect_cloudtrail_record,
        )

    def collect_config_records(self) -> list[ConfigCostGovernanceRecord]:  # noqa: D102
        return self._collect_regional_records(
            regions=self.get_available_regions(),
            service="config",
            operation=self._get_config_operation_summary(),
            collect_region=self._collect_config_record,
        )

    def _get_config_operation_summary(self) -> str:
        operations = [
            "DescribeConfigurationRecorders",
            "DescribeDeliveryChannels",
            "DescribeConfigurationRecorderStatus",
        ]
        if self.config_collection_options.should_collect_rule_metadata():
            operations.extend(
                [
                    "DescribeConfigRules",
                    "DescribeConformancePacks",
                ],
            )
        return "+".join(operations)

    def collect_waf_records(self) -> list[WafCostGovernanceRecord]:  # noqa: D102
        records = self._collect_regional_records(
            regions=self.get_available_regions(),
            service="wafv2",
            operation=self._get_waf_operation_summary(),
            collect_region=self._collect_regional_waf_records,
        )
        cloudfront_results = self._collect_cloudfront_waf_task()
        for result in cloudfront_results:
            if result.status == "completed" and result.value:
                records.extend(result.value)
        return records

    def collect_guardduty_records(  # noqa: D102
        self,
    ) -> list[GuardDutyCostGovernanceRecord]:
        return self._collect_regional_records(
            regions=self.get_available_regions(),
            service="guardduty",
            operation="ListDetectors+GetDetector",
            collect_region=self._collect_guardduty_record,
        )

    def collect_securityhub_inspector_macie_records(  # noqa: D102
        self,
    ) -> list[SecurityHubInspectorMacieCostGovernanceRecord]:
        return self._collect_regional_records(
            regions=self.get_available_regions(),
            service="securityhub-inspector-macie",
            operation=("DescribeHub+GetEnabledStandards+BatchGetAccountStatus+GetMacieSession+ListClassificationJobs"),
            collect_region=self._collect_securityhub_inspector_macie_record,
        )

    def collect_kms_records(self) -> list[KmsCostGovernanceRecord]:  # noqa: D102
        return self._collect_regional_records(
            regions=self.get_available_regions(),
            service="kms",
            operation=("ListKeys+DescribeKey+GetKeyRotationStatus+ListAliases+ListResourceTags"),
            collect_region=self._collect_kms_record,
        )

    def collect_secrets_manager_records(  # noqa: D102
        self,
    ) -> list[SecretsManagerCostGovernanceRecord]:
        return self._collect_regional_records(
            regions=self.get_available_regions(),
            service="secretsmanager",
            operation="ListSecrets",
            collect_region=self._collect_secrets_manager_record,
        )

    def _collect_regional_records(
        self,
        *,
        regions: list[str],
        service: str,
        operation: str,
        collect_region: Callable[[str], list[AuditRecordT]],
    ) -> list[AuditRecordT]:
        return self._regional_collection.collect_region_records(
            regions=regions,
            service=service,
            operation=operation,
            collect_region=collect_region,
        )
