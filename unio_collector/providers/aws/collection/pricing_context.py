"""Collect the typed pricing context required by standalone replay."""

from __future__ import annotations

import time
from datetime import date
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.aws.pricing.rate.provider import AwsPricingRateProvider
from unio_collector.pricing.lookup.plan import PricingLookupPlan
from unio_collector.pricing.progress import PricingRateProgress
from unio_collector.pricing.replay.context import PricingReplayContext
from unio_collector.pricing.stops import PricingLookupStoppedError

if TYPE_CHECKING:
    from unio_collector.pricing.rates import PricingRates


class AwsCollectorPricingContextService:
    """Collect typed pricing inputs without running report analysis."""

    _USAGE_SCANNERS = (
        "data-transfer-cost-review",
        "cost-spike-analysis",
        "nat-gateway-cost-review",
    )

    def collect(
        self,
        *,
        session: Any,  # noqa: ANN401
        account_id: str,
        config: Any,  # noqa: ANN401
        scanner_evidence_payloads: list[dict[str, Any]],
        no_cost_data: bool,
    ) -> PricingReplayContext:
        """Return the complete replay context for collected evidence."""
        if no_cost_data or not config.pricing_enrichment_enabled:
            reason = "Cost data was excluded by collector policy." if no_cost_data else "Pricing enrichment was disabled for collection."
            return PricingReplayContext(
                status="disabled",
                provider="not_available",
                limitations=[reason],
            )
        plan = self._build_lookup_plan(scanner_evidence_payloads)
        usage_records = self._collect_usage_records(scanner_evidence_payloads)
        rates = self._collect_rates(
            session=session,
            account_id=account_id,
            config=config,
            plan=plan,
        )
        limitations = (
            []
            if usage_records
            else [
                "Cost Explorer usage records were unavailable for pricing usage-pool reconstruction.",
            ]
        )
        return PricingReplayContext.from_runtime(
            rates,
            usage_records,
            limitations=limitations,
        )

    def _collect_rates(
        self,
        *,
        session: Any,  # noqa: ANN401
        account_id: str,
        config: Any,  # noqa: ANN401
        plan: PricingLookupPlan,
    ) -> PricingRates:
        progress = PricingRateProgress(
            max_api_calls=config.pricing_max_api_calls,
            timeout_seconds=config.pricing_enrichment_timeout_seconds,
            api_call_timeout_seconds=config.pricing_api_call_timeout_seconds,
            worker_count=config.pricing_worker_count,
        )
        if not plan.get_regions():
            return progress.build_rates(
                status="skipped",
                warnings=["No pricing-supported collected resources required rate lookup."],
            )
        try:
            return AwsPricingRateProvider(session, account_id=account_id).collect_rates(
                regions=plan.get_regions(),
                ebs_volume_types=set(),
                include_snapshots=False,
                include_logs_storage=False,
                include_public_ipv4=False,
                lookup_plan=plan,
                deadline_monotonic=(time.monotonic() + config.pricing_enrichment_timeout_seconds),
                max_api_calls=config.pricing_max_api_calls,
                timeout_seconds=config.pricing_enrichment_timeout_seconds,
                api_call_timeout_seconds=config.pricing_api_call_timeout_seconds,
                worker_count=config.pricing_worker_count,
                progress=progress,
            )
        except PricingLookupStoppedError as exc:
            progress.record_stop(exc.status, str(exc))
            return progress.build_rates(status=exc.status, stop_reason=exc.status)
        except Exception as exc:  # noqa: BLE001
            progress.record_error(str(exc))
            return progress.build_rates(status="failed", errors=[str(exc)])

    def _build_lookup_plan(self, payloads: list[dict[str, Any]]) -> PricingLookupPlan:
        volumes: dict[str, set[str]] = {}
        snapshots: set[str] = set()
        logs: set[str] = set()
        ipv4: set[str] = set()
        for item in payloads:
            scanner_id = str(item.get("scanner_id") or "")
            payload = item.get("payload")
            records = payload.get("records") if isinstance(payload, dict) else None
            if not isinstance(records, list):
                continue
            for record in records:
                if not isinstance(record, dict):
                    continue
                self._add_lookup_target(
                    scanner_id,
                    record,
                    volumes=volumes,
                    snapshots=snapshots,
                    logs=logs,
                    ipv4=ipv4,
                )
        return PricingLookupPlan(
            ebs_volume_types_by_region={key: tuple(sorted(value)) for key, value in sorted(volumes.items())},
            snapshot_regions=tuple(sorted(snapshots)),
            logs_storage_regions=tuple(sorted(logs)),
            public_ipv4_regions=tuple(sorted(ipv4)),
        )

    @staticmethod
    def _add_lookup_target(
        scanner_id: str,
        record: dict[str, Any],
        *,
        volumes: dict[str, set[str]],
        snapshots: set[str],
        logs: set[str],
        ipv4: set[str],
    ) -> None:
        region = str(record.get("region") or "")
        if not region or region == "global":
            return
        if scanner_id == "ec2-unattached-ebs-volumes":
            variant = str(record.get("volume_type") or "")
            if variant and Decimal(str(record.get("size_gib") or 0)) > 0:
                volumes.setdefault(region, set()).add(variant)
        elif (
            scanner_id == "snapshot-age-review"
            and Decimal(
                str(record.get("volume_size_gib") or 0),
            )
            > 0
        ):
            snapshots.add(region)
        elif (
            scanner_id == "cloudwatch-idle-log-review"
            and Decimal(
                str(record.get("stored_bytes") or 0),
            )
            > 0
        ):
            logs.add(region)
        elif scanner_id in {
            "ec2-unassociated-elastic-ips",
            "network-public-ipv4-review",
        } and (
            scanner_id == "ec2-unassociated-elastic-ips"
            or max(
                int(record.get("elastic_ip_count") or 0),
                int(record.get("eni_public_ip_count") or 0),
            )
            > 0
        ):
            ipv4.add(region)

    def _collect_usage_records(self, payloads: list[dict[str, Any]]) -> list[DailyCostRecord]:
        by_key: dict[tuple[object, ...], DailyCostRecord] = {}
        for scanner_id in self._USAGE_SCANNERS:
            for item in payloads:
                if item.get("scanner_id") != scanner_id:
                    continue
                payload = item.get("payload")
                if not isinstance(payload, dict):
                    continue
                raw_records = payload.get("records", payload.get("daily_costs", []))
                if not isinstance(raw_records, list):
                    continue
                for raw in raw_records:
                    if not isinstance(raw, dict):
                        continue
                    record = DailyCostRecord(
                        date=date.fromisoformat(str(raw["date"])),
                        service_name=str(raw["service_name"]),
                        region=str(raw.get("region") or "global"),
                        usage_type=(str(raw["usage_type"]) if raw.get("usage_type") is not None else None),
                        cost=Decimal(str(raw["cost"])),
                        currency=str(raw["currency"]),
                    )
                    key = (record.date, record.service_name, record.region, record.usage_type, record.currency)
                    previous = by_key.get(key)
                    if previous is not None and previous.cost != record.cost:
                        msg = "Conflicting Cost Explorer usage records were collected for pricing replay."
                        raise ValueError(msg)
                    by_key[key] = record
            if by_key:
                break
        return [by_key[key] for key in sorted(by_key, key=lambda value: tuple(str(item) for item in value))]
