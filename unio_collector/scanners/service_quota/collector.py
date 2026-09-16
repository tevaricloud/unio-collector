from __future__ import annotations  # noqa: D100

import logging
from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.options import parse_scanner_option_int
from unio_collector.scanners.service_quota.collection_payload import build_quota_collection_payload
from unio_collector.scanners.service_quota.matcher import ServiceQuotaMatcher
from unio_collector.scanners.service_quota.observation import ServiceQuotaObservation
from unio_collector.scanners.service_quota.parsing import parse_finite_quota_value, quota_response_records
from unio_collector.scanners.service_quota.supported_checks import SUPPORTED_SERVICE_QUOTA_CHECKS
from unio_collector.scanners.service_quota.usage import ServiceQuotaUsage
from unio_collector.scanners.service_quota.usage_counts import ServiceQuotaUsageCountMixin

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext
    from unio_collector.scanners.service_quota.check_spec import ServiceQuotaCheckSpec

LOGGER = logging.getLogger("unio_collector.scanners.service_quotas")


from unio_collector.scanners.scanner.implementation import ScannerImplementation
from unio_collector.scanners.service_quota.values import deduplicate_strings


class ServiceQuotaProximityReviewCollector(ServiceQuotaUsageCountMixin, BaseUnioScanner):
    """Collect provider evidence for service-quota-proximity-review."""

    def collect(self, context: ScannerContext) -> dict[str, Any]:  # noqa: D102
        threshold = self._get_configured_threshold(context)
        selected_regions = self._get_regions(context)
        records: list[ServiceQuotaObservation] = []
        warnings: list[str] = []
        if not selected_regions:
            warnings.append("No AWS region was available for quota and usage collection.")

        quota_cache: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for region in selected_regions:
            for spec in SUPPORTED_SERVICE_QUOTA_CHECKS:
                quota = self._get_quota(
                    context,
                    spec=spec,
                    region=region,
                    warnings=warnings,
                    quota_cache=quota_cache,
                )
                usage = self._collect_usage(context, spec=spec, region=region)
                if usage.limitation:
                    warnings.append(usage.limitation)
                record = self._build_record(
                    spec=spec,
                    region=region,
                    quota=quota,
                    usage=usage,
                )
                records.append(record)

        payload = build_quota_collection_payload(
            account_id=context.security.account_id,
            period=context.costs.get_current_period().model_dump(mode="json"),
            selected_regions=selected_regions,
            threshold=threshold,
            records=records,
            warnings=deduplicate_strings(warnings),
            limitations=self._build_limitations(),
        )
        context.data.set("service_quota_proximity", payload)
        return payload

    def _get_configured_threshold(self, context: ScannerContext) -> int | None:
        value = context.options.get("remaining_threshold", None)
        try:
            return parse_scanner_option_int(value)
        except (TypeError, ValueError):
            return None

    def _get_regions(self, context: ScannerContext) -> list[str]:
        try:
            return context.ec2.get_regions()
        except Exception as exc:  # noqa: BLE001
            context.warnings.add(
                (f"Service Quotas proximity region discovery was unavailable ({exc.__class__.__name__})."),
            )
        selected = context.options.get_selected_regions()
        return sorted(selected or [])

    def _get_quota(
        self,
        context: ScannerContext,
        *,
        spec: ServiceQuotaCheckSpec,
        region: str,
        warnings: list[str],
        quota_cache: dict[tuple[str, str], list[dict[str, Any]]],
    ) -> dict[str, Any] | None:
        client = self._create_service_quotas_client(context, region=region)
        try:
            response = client.get_service_quota(
                ServiceCode=spec.quota_service_code,
                QuotaCode=spec.quota_code,
            )
            quota = response.get("Quota")
            if isinstance(quota, dict):
                return quota
        except Exception as exc:
            LOGGER.debug(
                "Falling back to service quota listing after get_service_quota failure.",
                exc_info=exc,
            )
        cache_key = (region, spec.quota_service_code)
        quotas = quota_cache.get(cache_key)
        if quotas is None:
            quotas = self._list_service_quotas(
                client,
                region=region,
                service_code=spec.quota_service_code,
                warnings=warnings,
            )
            quota_cache[cache_key] = quotas
        return ServiceQuotaMatcher().select_quota(quotas, spec)

    def _create_service_quotas_client(
        self,
        context: ScannerContext,
        *,
        region: str,
    ) -> Any:  # noqa: ANN401
        return context.security.create_client(
            "service-quotas",
            region_name=region,
            collector_name="ServiceQuotaProximityCollector",
        )

    def _list_service_quotas(
        self,
        client: Any,  # noqa: ANN401
        *,
        region: str,
        service_code: str,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        try:
            if client.can_paginate("list_service_quotas"):
                pages = client.get_paginator("list_service_quotas").paginate(
                    ServiceCode=service_code,
                )
                return [quota for page in pages for quota in quota_response_records(page, "Quotas")]
            response = client.list_service_quotas(ServiceCode=service_code)
            return quota_response_records(response, "Quotas")
        except Exception as exc:  # noqa: BLE001
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            warnings.append(
                f"Service Quotas data was unavailable for {service_code} in {region} ({code}).",
            )
            return []

    def _collect_usage(
        self,
        context: ScannerContext,
        *,
        spec: ServiceQuotaCheckSpec,
        region: str,
    ) -> ServiceQuotaUsage:
        counters = {
            "ec2_describe_addresses_count": self._count_elastic_ips,
            "ec2_describe_vpcs_count": self._count_vpcs,
            "ec2_describe_security_groups_count": (self._count_security_groups),
            "ec2_describe_nat_gateways_max_per_az": self._count_nat_gateways_per_az,
            "elbv2_describe_load_balancers_application_count": (self._count_application_load_balancers),
            "elbv2_describe_load_balancers_network_count": (self._count_network_load_balancers),
        }
        counter = counters[spec.usage_method]
        try:
            return counter(context, region)
        except Exception as exc:  # noqa: BLE001
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            return ServiceQuotaUsage(
                value=None,
                confidence="low",
                method=spec.usage_method,
                limitation=(f"{spec.resource_type} usage count was unavailable in {region} ({code})."),
            )

    def _build_record(
        self,
        *,
        spec: ServiceQuotaCheckSpec,
        region: str,
        quota: dict[str, Any] | None,
        usage: ServiceQuotaUsage,
    ) -> ServiceQuotaObservation:
        quota_value = parse_finite_quota_value(quota.get("Value") if quota else None)
        limitation = usage.limitation
        if quota is None:
            limitation = f"Service Quotas record for {spec.resource_type} was not found in {region}."
        elif quota_value is None:
            limitation = f"Service Quotas value for {spec.resource_type} was unavailable or malformed in {region}."
        return ServiceQuotaObservation(
            check_id=spec.check_id,
            region=region,
            service=spec.service,
            resource_type=spec.resource_type,
            quota_name=str(quota.get("QuotaName") if quota else spec.check_id),
            quota_code=(str(quota.get("QuotaCode")) if quota and quota.get("QuotaCode") else None),
            quota_value=quota_value,
            quota_found=quota is not None,
            current_usage=usage.value,
            confidence=usage.confidence,
            resource_count_method=usage.method,
            limitation=limitation,
        )

    def _build_limitations(self) -> list[str]:
        return [
            "This scanner checks a conservative first set of countable regional quotas only.",
            "Service Quotas records can vary by region and account; missing quota records are reported as limitations.",
        ]

    def _count_elastic_ips(
        self,
        context: ScannerContext,
        region: str,
    ) -> ServiceQuotaUsage:
        client = self._create_ec2_client(context, region)
        addresses = self._collect_operation_items(
            client,
            "describe_addresses",
            "Addresses",
        )
        return ServiceQuotaUsage(
            value=len(addresses),
            confidence="high",
            method="ec2:DescribeAddresses count",
        )

    def _count_vpcs(
        self,
        context: ScannerContext,
        region: str,
    ) -> ServiceQuotaUsage:
        client = self._create_ec2_client(context, region)
        vpcs = self._collect_operation_items(client, "describe_vpcs", "Vpcs")
        return ServiceQuotaUsage(
            value=len(vpcs),
            confidence="high",
            method="ec2:DescribeVpcs count",
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="ServiceQuotaProximityReviewScanner",
            implementation_module="unio_collector.scanners.service_quotas",
        )
