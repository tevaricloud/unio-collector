from __future__ import annotations  # noqa: D100

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any

from unio_collector.aws.audit import AwsAuditContext
from unio_collector.aws.pricing.client_config import build_pricing_client_config
from unio_collector.aws.pricing.rate.budget import AwsPricingRateBudgetMixin
from unio_collector.core.count_formatting import format_count
from unio_collector.pricing.enrich.constants import REGION_LOCATION_NAMES
from unio_collector.pricing.enrich.utils import (
    term_match_filter,
)
from unio_collector.pricing.lookup.plan import PricingLookupPlan
from unio_collector.pricing.lookup.request import PricingLookupRequest
from unio_collector.pricing.product_finder import PricingApiProductFinder
from unio_collector.pricing.progress import PricingRateProgress
from unio_collector.pricing.stops import PricingLookupStoppedError

if TYPE_CHECKING:
    from botocore.config import Config

    from unio_collector.pricing.rates import PricingRates
    from unio_collector.pricing.unit_rate import UnitRate


class AwsPricingRateProvider(AwsPricingRateBudgetMixin):  # noqa: D101
    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
    ) -> None:
        self.session = session
        self.account_id = account_id

    def collect_rates(  # noqa: D102
        self,
        *,
        regions: set[str],
        ebs_volume_types: set[str],
        include_snapshots: bool = True,
        include_logs_storage: bool = True,
        include_public_ipv4: bool = True,
        lookup_plan: PricingLookupPlan | None = None,
        deadline_monotonic: float | None = None,
        max_api_calls: int | None = None,
        timeout_seconds: int | None = None,
        api_call_timeout_seconds: int | None = None,
        worker_count: int = 4,
        progress: PricingRateProgress | None = None,
    ) -> PricingRates:
        context = AwsAuditContext(
            scanner_id="unio-collector-pricing-estimates",
            collector="AwsPricingRateProvider",
            allowed_api_calls=("pricing:GetProducts",),
            recipient_account_id=self.account_id,
        )
        client = self.session.create_client(
            "pricing",
            region_name="us-east-1",
            audit_context=context,
            client_config=self._build_client_config(api_call_timeout_seconds),
        )
        progress = progress or PricingRateProgress(
            max_api_calls=max_api_calls,
            timeout_seconds=timeout_seconds,
            api_call_timeout_seconds=api_call_timeout_seconds,
            worker_count=worker_count,
        )
        collector = PricingApiProductFinder(
            client,
            deadline_monotonic=deadline_monotonic,
            max_api_calls=max_api_calls,
            api_call_timeout_seconds=api_call_timeout_seconds,
            progress=progress,
        )
        lookup_plan = lookup_plan or PricingLookupPlan.build_from_legacy_inputs(
            regions=regions,
            ebs_volume_types=ebs_volume_types,
            include_snapshots=include_snapshots,
            include_logs_storage=include_logs_storage,
            include_public_ipv4=include_public_ipv4,
        )
        requests = self._build_lookup_requests(
            lookup_plan=lookup_plan,
            progress=progress,
        )
        requests = self._prioritize_lookup_requests(requests)
        budget_estimate = self._build_budget_estimate(
            requests,
            timeout_seconds=timeout_seconds,
            api_call_timeout_seconds=api_call_timeout_seconds,
            max_api_calls=max_api_calls,
        )
        scheduled_requests = self._select_lookup_requests_for_budget(
            requests,
            max_api_calls,
        )
        progress.record_budget_estimate(budget_estimate)
        progress.record_lookup_plan_summary(lookup_plan.convert_to_summary())
        progress.record_lookup_schedule(
            lookup_request_count=len(requests),
            scheduled_lookup_request_count=len(scheduled_requests),
            omitted_lookup_request_count=budget_estimate.omitted_lookup_request_count,
        )
        if budget_estimate.omitted_lookup_request_count:
            progress.record_stop(
                "lookup_budget_limited",
                (
                    "Pricing scheduled "
                    f"{budget_estimate.scheduled_lookup_request_count} of "
                    f"{format_count(budget_estimate.lookup_request_count, 'lookup request')} "
                    "based on the configured Price List API call limit."
                ),
            )
        elif not budget_estimate.likely_to_complete_within_budget:
            progress.record_warning(budget_estimate.note)
        errors: list[str] = []
        stop_reason = self._collect_lookup_requests(
            collector,
            scheduled_requests,
            progress=progress,
            errors=errors,
            worker_count=worker_count,
        )
        stop_reason = stop_reason or ("lookup_budget_limited" if budget_estimate.omitted_lookup_request_count else None)
        loaded_any = progress.has_rates()
        if stop_reason and loaded_any:
            status = "partial"
        elif stop_reason:
            status = stop_reason
        elif loaded_any:
            status = "loaded"
        else:
            status = "empty"
        return progress.build_rates(
            status=status,
            errors=errors,
            stop_reason=stop_reason,
        )

    def _build_client_config(
        self,
        api_call_timeout_seconds: int | None,
    ) -> Config | None:
        runtime_config = getattr(self.session, "runtime_config", None)
        if runtime_config is not None and api_call_timeout_seconds is not None:
            return runtime_config.build_botocore_config(
                read_timeout_seconds=api_call_timeout_seconds,
            )
        return build_pricing_client_config(api_call_timeout_seconds)

    def _build_lookup_requests(
        self,
        *,
        lookup_plan: PricingLookupPlan,
        progress: PricingRateProgress,
    ) -> list[PricingLookupRequest]:
        requests: list[PricingLookupRequest] = []
        for region in sorted(lookup_plan.get_regions()):
            location = REGION_LOCATION_NAMES.get(region)
            if not location:
                progress.record_warning(
                    f"No pricing location mapping is available for {region}.",
                )
                continue
            requests.extend(
                PricingLookupRequest(
                    request_type="ebs_volume",
                    region=region,
                    location=location,
                    volume_type=volume_type,
                )
                for volume_type in lookup_plan.get_ebs_volume_types(region)
            )
            if region in lookup_plan.snapshot_regions:
                requests.append(
                    PricingLookupRequest(
                        request_type="snapshot",
                        region=region,
                        location=location,
                    ),
                )
            if region in lookup_plan.logs_storage_regions:
                requests.append(
                    PricingLookupRequest(
                        request_type="logs_storage",
                        region=region,
                        location=location,
                    ),
                )
            if region in lookup_plan.public_ipv4_regions:
                requests.append(
                    PricingLookupRequest(
                        request_type="public_ipv4",
                        region=region,
                        location=location,
                    ),
                )
        return requests

    def _prioritize_lookup_requests(
        self,
        requests: list[PricingLookupRequest],
    ) -> list[PricingLookupRequest]:
        priority = {
            "public_ipv4": 0,
            "logs_storage": 1,
            "snapshot": 2,
            "ebs_volume": 3,
        }
        return sorted(
            requests,
            key=lambda request: (
                priority.get(request.request_type, 99),
                request.region,
                request.volume_type or "",
            ),
        )

    def _collect_lookup_requests(
        self,
        collector: PricingApiProductFinder,
        requests: list[PricingLookupRequest],
        *,
        progress: PricingRateProgress,
        errors: list[str],
        worker_count: int,
    ) -> str | None:
        if not requests:
            return None
        stop_reason: str | None = None
        workers = max(1, min(worker_count, len(requests)))
        with ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="unio-collector-pricing",
        ) as executor:
            futures = {
                executor.submit(
                    self._execute_lookup_request,
                    collector,
                    request,
                ): request
                for request in requests
            }
            for future in as_completed(futures):
                request = futures[future]
                try:
                    rate = future.result()
                except PricingLookupStoppedError as exc:
                    stop_reason = exc.status
                    progress.record_stop(exc.status, str(exc))
                    for pending in futures:
                        pending.cancel()
                    break
                except Exception as exc:  # noqa: BLE001
                    message = str(exc)
                    errors.append(message)
                    progress.record_error(message)
                    continue
                if rate:
                    self._record_lookup_rate(progress, request, rate)
        return stop_reason

    def _execute_lookup_request(
        self,
        collector: PricingApiProductFinder,
        request: PricingLookupRequest,
    ) -> UnitRate | None:
        if request.request_type == "ebs_volume":
            volume_type = request.volume_type or ""
            return collector.find_ec2_rate(
                lookup_request=request,
                location=request.location,
                lookup_key=f"ebs-volume:{request.region}:{volume_type}",
                filters=(
                    term_match_filter("regionCode", request.region),
                    term_match_filter("productFamily", "Storage"),
                    term_match_filter("volumeApiName", volume_type),
                ),
                predicate=lambda attributes, usage_type, product_family: (
                    product_family == "Storage" and attributes.get("volumeApiName") == volume_type and "volumeusage" in usage_type.lower()
                ),
            )
        if request.request_type == "snapshot":
            return collector.find_ec2_rate(
                lookup_request=request,
                location=request.location,
                lookup_key=f"ebs-snapshot:{request.region}",
                filters=(
                    term_match_filter("regionCode", request.region),
                    term_match_filter("productFamily", "Storage Snapshot"),
                    term_match_filter("storageMedia", "Amazon S3"),
                ),
                predicate=lambda _attributes, usage_type, product_family: (
                    product_family == "Storage Snapshot" and usage_type.lower().endswith("ebs:snapshotusage")
                ),
            )
        if request.request_type == "logs_storage":
            return collector.find_cloudwatch_rate(
                lookup_request=request,
                location=request.location,
                lookup_key=f"cloudwatch-logs-storage:{request.region}",
                filters=(
                    term_match_filter("regionCode", request.region),
                    term_match_filter("productFamily", "Storage Snapshot"),
                    term_match_filter("storageMedia", "Amazon S3"),
                ),
                predicate=lambda _attributes, usage_type, product_family: (
                    product_family == "Storage Snapshot" and usage_type.lower().endswith("timedstorage-bytehrs")
                ),
            )
        if request.request_type == "public_ipv4":
            return collector.find_vpc_rate(
                lookup_request=request,
                location=request.location,
                lookup_key=f"public-ipv4:{request.region}",
                filters=(
                    term_match_filter("regionCode", request.region),
                    term_match_filter("group", "VPCPublicIPv4Address"),
                ),
                predicate=lambda _attributes, usage_type, product_family: (
                    "publicipv4:idleaddress" in usage_type.lower() or "public ipv4" in product_family.lower()
                ),
            )
        return None

    def _record_lookup_rate(
        self,
        progress: PricingRateProgress,
        request: PricingLookupRequest,
        rate: UnitRate,
    ) -> None:
        if request.request_type == "ebs_volume" and request.volume_type:
            progress.record_ebs_volume_rate(request.region, request.volume_type, rate)
        elif request.request_type == "snapshot":
            progress.record_snapshot_rate(request.region, rate)
        elif request.request_type == "logs_storage":
            progress.record_logs_storage_rate(request.region, rate)
        elif request.request_type == "public_ipv4":
            progress.record_public_ipv4_rate(request.region, rate)
