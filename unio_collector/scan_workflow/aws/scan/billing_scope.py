from __future__ import annotations  # noqa: D100

from dataclasses import replace
from typing import TYPE_CHECKING

from unio_collector.aws.audit import AwsAuditContext
from unio_collector.scan_workflow.scope.billing.region_coverage import (
    BillingRegionCoverageBuilder,
)

if TYPE_CHECKING:
    from unio_collector.collector.config.protocol import CollectionConfigProtocol
    from unio_collector.scan_workflow.aws.scan.contracts import AwsScanRunnerContract


class BillingRegionScopeService:
    """Resolve billing-derived region scope and coverage payloads for scans."""

    def apply_scope_derivation[TConfig: CollectionConfigProtocol](
        self,
        config: TConfig,
        runner: AwsScanRunnerContract,
    ) -> tuple[TConfig, dict[str, object]]:
        """Return effective scan config and derivation metadata."""
        if not config.regions_from_billing_enabled:
            return config, {
                "enabled": False,
                "status": "not_requested",
                "requested_regions": list(config.regions),
                "billing_active_regions": [],
                "normalized_candidate_regions": [],
                "derived_material_regions": [],
                "residual_regions": [],
                "unrecognized_billing_region_values": [],
                "final_regions": list(config.regions),
            }
        if config.global_only:
            return (
                config,
                {
                    "enabled": True,
                    "status": "ignored_global_only",
                    "reason": "--global-only limits the run to global checks.",
                    "requested_regions": list(config.regions),
                    "billing_active_regions": [],
                    "normalized_candidate_regions": [],
                    "derived_material_regions": [],
                    "residual_regions": [],
                    "unrecognized_billing_region_values": [],
                    "final_regions": list(config.regions),
                },
            )
        builder = BillingRegionCoverageBuilder()
        requested_regions = list(config.regions)
        audit_context = AwsAuditContext(
            scanner_id="billing-region-scope-derivation",
            collector="BillingRegionScopeDerivationCollector",
            allowed_api_calls=("ce:GetCostAndUsage",),
            recipient_account_id=runner.runtime_state.account_id,
        )
        try:
            records = runner.evidence_gateway.collect_cached_daily_costs_with_context(
                audit_context,
                group_keys=("REGION",),
            )
        except Exception as exc:  # noqa: BLE001
            return (
                self.keep_safe_scope_fallback(config),
                {
                    "enabled": True,
                    "status": "unavailable",
                    "reason": (f"Cost Explorer billing-region scope derivation could not be performed: {exc.__class__.__name__}: {exc}"),
                    "requested_regions": requested_regions,
                    "derived_material_regions": [],
                    "billing_active_regions": [],
                    "normalized_candidate_regions": [],
                    "residual_regions": [],
                    "unrecognized_billing_region_values": [],
                    "final_regions": list(config.regions),
                    "fallback_behavior": ("Original explicit regions were kept; if none were configured, the scan falls back to all available regions."),
                },
            )
        coverage = builder.build_from_daily_costs(
            records,
            selected_regions=requested_regions,
            explicit_region_scope=bool(requested_regions),
            current_period=runner.current_period,
        ).convert_to_dict()
        derived_regions = [str(region) for region in coverage.get("material_billing_active_regions", []) if str(region).strip()]
        final_regions = sorted(dict.fromkeys([*requested_regions, *derived_regions]))
        if not final_regions:
            return (
                self.keep_safe_scope_fallback(config),
                {
                    "enabled": True,
                    "status": "no_material_billing_regions",
                    "requested_regions": requested_regions,
                    "derived_material_regions": [],
                    "billing_active_regions": list(
                        coverage.get("billing_active_regions", []),
                    ),
                    "normalized_candidate_regions": list(
                        coverage.get("billing_active_regions", []),
                    ),
                    "residual_regions": list(
                        coverage.get("residual_billing_active_regions", []),
                    ),
                    "unrecognized_billing_region_values": list(
                        coverage.get("unrecognized_billing_region_values", []),
                    ),
                    "final_regions": list(config.regions),
                    "materiality_threshold": str(
                        coverage.get("materiality_threshold") or "0.01",
                    ),
                    "fallback_behavior": (
                        "No material billed regions were found; if no explicit regions were configured, the scan falls back to all available regions."
                    ),
                },
            )
        effective_config = replace(
            config,
            regions=tuple(final_regions),
            explicit_region_scope=True,
            global_checks_enabled=True,
        )
        return (
            effective_config,
            {
                "enabled": True,
                "status": "applied",
                "source": "cost_explorer_region_costs",
                "requested_regions": requested_regions,
                "derived_material_regions": derived_regions,
                "billing_active_regions": list(
                    coverage.get("billing_active_regions", []),
                ),
                "normalized_candidate_regions": list(
                    coverage.get("billing_active_regions", []),
                ),
                "residual_regions": list(
                    coverage.get("residual_billing_active_regions", []),
                ),
                "unrecognized_billing_region_values": list(
                    coverage.get("unrecognized_billing_region_values", []),
                ),
                "final_regions": final_regions,
                "materiality_threshold": str(
                    coverage.get("materiality_threshold") or "0.01",
                ),
                "global_checks_enabled": True,
                "fallback_behavior": "not_used",
            },
        )

    def build_region_scope_provenance(
        self,
        config: CollectionConfigProtocol,
        derivation: dict[str, object],
        account_scope: dict[str, object],
    ) -> dict[str, object]:
        """Combine account discovery and billing selection into one contract."""
        summary = dict(account_scope)
        requested = _string_list(derivation.get("requested_regions"))
        final_regions = _regional_values(
            derivation.get("final_regions") or summary.get("selected_regions"),
        )
        excluded = _exclusion_records(summary.get("excluded_regions"))
        excluded.extend(
            {
                "region_name": region,
                "status": "excluded",
                "stage": "billing_materiality",
                "reason": "below_materiality_threshold",
            }
            for region in _string_list(derivation.get("residual_regions"))
        )
        excluded.extend(
            {
                "region_name": value,
                "status": "excluded",
                "stage": "billing_normalization",
                "reason": "unrecognized_billing_region_value",
            }
            for value in _string_list(
                derivation.get("unrecognized_billing_region_values"),
            )
        )
        ordered_exclusions = sorted(
            {
                (
                    str(item.get("region_name") or ""),
                    str(item.get("stage") or "account_region_discovery"),
                    str(item.get("reason") or "region_not_selected"),
                ): item
                for item in excluded
                if item.get("region_name")
            }.values(),
            key=lambda item: (
                str(item.get("region_name")),
                str(item.get("stage")),
                str(item.get("reason")),
            ),
        )
        summary.update(
            {
                "scope_version": "2026-08",
                "selection_mode": _selection_mode(config),
                "regions_from_billing_requested": bool(
                    derivation.get("enabled"),
                ),
                "regions_from_billing_effective": bool(
                    getattr(config, "regions_from_billing_enabled", False),
                ),
                "billing_region_source": ("cost_explorer_region_costs" if derivation.get("enabled") else "not_requested"),
                "billing_region_status": str(
                    derivation.get("status") or "unknown",
                ),
                "materiality_threshold": str(
                    derivation.get("materiality_threshold") or "0.01",
                ),
                "billing_active_regions": _string_list(
                    derivation.get("billing_active_regions"),
                ),
                "normalized_candidate_regions": _string_list(
                    derivation.get("normalized_candidate_regions"),
                ),
                "material_billing_candidate_regions": _string_list(
                    derivation.get("derived_material_regions"),
                ),
                "residual_billing_candidate_regions": _string_list(
                    derivation.get("residual_regions"),
                ),
                "unrecognized_billing_region_values": _string_list(
                    derivation.get("unrecognized_billing_region_values"),
                ),
                "explicit_requested_regions": requested,
                "selected_regional_targets": final_regions,
                "selected_regions": final_regions,
                "excluded_regions": ordered_exclusions,
                "excluded_region_count": len(ordered_exclusions),
                "global_scope": {
                    "enabled": bool(getattr(config, "global_checks_enabled", True)),
                    "pseudo_scope": "global",
                    "regional_target": False,
                },
                "control_sources": dict(
                    getattr(config, "region_scope_control_sources", {}),
                ),
                "service_specific_exclusions": _object_list(
                    summary.get("service_specific_exclusions"),
                ),
            },
        )
        return summary

    def keep_safe_scope_fallback[TConfig: CollectionConfigProtocol](self, config: TConfig) -> TConfig:
        """Return safe fallback config when billing-derived scope is unavailable."""
        if config.regions:
            return replace(config, regions_from_billing_enabled=False)
        return replace(
            config,
            explicit_region_scope=False,
            regions_from_billing_enabled=False,
        )

    def build_region_coverage(
        self,
        config: CollectionConfigProtocol,
        runner: AwsScanRunnerContract,
    ) -> dict[str, object]:
        """Build billed-region coverage metadata for report manifest summaries."""
        builder = BillingRegionCoverageBuilder()
        audit_context = AwsAuditContext(
            scanner_id="billing-region-coverage",
            collector="BillingRegionCoverageCollector",
            allowed_api_calls=("ce:GetCostAndUsage",),
            recipient_account_id=runner.runtime_state.account_id,
        )
        try:
            records = runner.evidence_gateway.collect_cached_daily_costs_with_context(
                audit_context,
                group_keys=("REGION",),
            )
        except Exception as exc:  # noqa: BLE001
            return builder.build_unavailable(
                selected_regions=list(config.regions),
                explicit_region_scope=config.explicit_region_scope,
                current_period=runner.current_period,
                currency=runner.current_period.currency,
                reason=(f"Cost Explorer billing-region cross-check could not be performed: {exc.__class__.__name__}: {exc}"),
            ).convert_to_dict()
        return builder.build_from_daily_costs(
            records,
            selected_regions=list(config.regions),
            explicit_region_scope=config.explicit_region_scope,
            current_period=runner.current_period,
        ).convert_to_dict()


def _string_list(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return sorted(dict.fromkeys(str(item) for item in value if str(item).strip()))


def _object_list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def _regional_values(value: object) -> list[str]:
    return [region for region in _string_list(value) if region not in {"global", "aws-global"}]


def _exclusion_records(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    records: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        record = dict(item)
        record.setdefault("stage", "account_region_discovery")
        record.setdefault("reason", "region_not_selected")
        records.append(record)
    return records


def _selection_mode(config: object) -> str:
    get_mode = getattr(config, "get_region_selection_mode", None)
    if callable(get_mode):
        return str(get_mode())
    return "account_enabled"
