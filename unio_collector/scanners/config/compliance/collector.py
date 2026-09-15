from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.response_admission import iter_response_rows, require_response_mapping, require_response_string
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.config.compliance.evidence import ConfigComplianceEvidence
from unio_collector.scanners.config.compliance.rule_record import ConfigComplianceRuleRecord
from unio_collector.scanners.security_governance.collection.regions import get_selected_or_available_regions
from unio_collector.scanners.security_governance.collection.values import normalize_reportable_metadata
from unio_collector.scanners.security_governance.collection.warnings import append_warning

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class AwsConfigComplianceReviewCollector(BaseUnioScanner):
    """Collect provider evidence for aws-config-compliance-review."""

    def collect(self, context: ScannerContext) -> ConfigComplianceEvidence:  # noqa: D102
        regions = get_selected_or_available_regions(context, "config")
        warnings: list[str] = []
        records: list[ConfigComplianceRuleRecord] = []
        conformance_pack_records: list[dict[str, Any]] = []
        for region in regions:
            client = context.security.create_client(
                "config",
                region_name=region,
                collector_name="AwsConfigComplianceReviewScanner",
            )
            records.extend(self._list_rule_compliance(client, region, warnings))
            conformance_pack_records.extend(
                self._list_conformance_pack_compliance(client, region, warnings),
            )
        for warning in warnings:
            context.warnings.add(warning)
        return ConfigComplianceEvidence(
            records=tuple(records),
            conformance_pack_records=tuple(conformance_pack_records),
            regions=tuple(regions),
            warnings=tuple(warnings),
        )

    def _list_rule_compliance(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
    ) -> list[ConfigComplianceRuleRecord]:
        records: list[ConfigComplianceRuleRecord] = []
        try:
            pages = client.get_paginator(
                "describe_compliance_by_config_rule",
            ).paginate()
        except Exception:  # noqa: BLE001
            try:
                pages = [client.describe_compliance_by_config_rule()]
            except Exception as exc:  # noqa: BLE001
                append_warning(warnings, f"AWS Config rule compliance in {region}", exc)
                return records
        try:
            for item in iter_response_rows(pages, "ComplianceByConfigRules"):
                compliance = require_response_mapping(item.get("Compliance"))
                records.append(
                    ConfigComplianceRuleRecord(
                        region=region,
                        rule_name=require_response_string(item.get("ConfigRuleName")),
                        compliance_type=require_response_string(compliance.get("ComplianceType")),
                        annotation=(str(compliance.get("Annotation")) if compliance.get("Annotation") else None),
                    ),
                )
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"AWS Config rule compliance in {region}", exc)
        return records

    def _list_conformance_pack_compliance(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        pack_names = self._list_conformance_pack_names(client, region, warnings)
        if not pack_names:
            return []
        records: list[dict[str, Any]] = []
        for pack_name in pack_names:
            records.extend(
                self._list_single_conformance_pack_compliance(
                    client,
                    region,
                    pack_name,
                    warnings,
                ),
            )
        return records

    def _list_conformance_pack_names(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
    ) -> list[str]:
        try:
            pages = client.get_paginator("describe_conformance_packs").paginate()
        except Exception:  # noqa: BLE001
            try:
                pages = [client.describe_conformance_packs()]
            except Exception as exc:  # noqa: BLE001
                append_warning(
                    warnings,
                    f"AWS Config conformance packs in {region}",
                    exc,
                )
                return []
        names: list[str] = []
        try:
            names.extend(require_response_string(pack.get("ConformancePackName")) for pack in iter_response_rows(pages, "ConformancePackDetails"))
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"AWS Config conformance packs in {region}", exc)
        return list(dict.fromkeys(names))

    def _list_single_conformance_pack_compliance(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        pack_name: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        try:
            pages = client.get_paginator(
                "describe_conformance_pack_compliance",
            ).paginate(ConformancePackName=pack_name)
        except Exception:  # noqa: BLE001
            try:
                pages = [
                    client.describe_conformance_pack_compliance(
                        ConformancePackName=pack_name,
                    ),
                ]
            except Exception as exc:  # noqa: BLE001
                append_warning(
                    warnings,
                    (f"AWS Config conformance pack compliance for {pack_name} in {region}"),
                    exc,
                )
                return []
        records: list[dict[str, Any]] = []
        try:
            for pack in iter_response_rows(pages, "ConformancePackRuleComplianceList"):
                record = dict(pack)
                record["region"] = region
                record.setdefault("ConformancePackName", pack_name)
                records.append(normalize_reportable_metadata(record))
        except Exception as exc:  # noqa: BLE001
            append_warning(
                warnings,
                (f"AWS Config conformance pack compliance for {pack_name} in {region}"),
                exc,
            )
        return records

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="AwsConfigComplianceReviewScanner",
            implementation_module="unio_collector.scanners.config.compliance.scanner",
        )
