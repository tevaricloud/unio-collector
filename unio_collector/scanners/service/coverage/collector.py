from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.response_admission import iter_response_rows, require_complete_response, require_response_rows
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class ServiceCoverageCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    collector_name = "ServiceCoverageCollector"

    def get_regions(self, context: ScannerContext) -> list[str]:  # noqa: D102
        try:
            return context.ec2.get_regions()
        except Exception as exc:  # noqa: BLE001
            context.warnings.add(
                (f"{self.metadata.display_name} region discovery was unavailable ({exc.__class__.__name__})."),
            )
        return sorted(context.options.get_selected_regions() or [])

    def create_client(  # noqa: D102
        self,
        context: ScannerContext,
        service_name: str,
        region: str,
    ) -> Any:  # noqa: ANN401
        return context.security.create_client(
            service_name,
            region_name=region,
            collector_name=self.collector_name,
        )

    def collect_items(  # noqa: D102
        self,
        client: Any,  # noqa: ANN401
        operation_name: str,
        result_key: str,
        *,
        pagination_kwargs: dict[str, Any] | None = None,
        call_kwargs: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        pagination_kwargs = dict(pagination_kwargs or {})
        call_kwargs = dict(call_kwargs or {})
        if client.can_paginate(operation_name):
            pages = client.get_paginator(operation_name).paginate(**pagination_kwargs)
            return list(iter_response_rows(pages, result_key))
        response = getattr(client, operation_name)(**call_kwargs)
        require_complete_response(response)
        return require_response_rows(response, result_key)

    def add_warning(  # noqa: D102
        self,
        context: ScannerContext,
        warnings: list[str],
        service_label: str,
        region: str,
        exc: Exception,
    ) -> None:
        code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
        warning = f"{service_label} inventory was unavailable in {region} ({code})."
        warnings.append(warning)
        context.warnings.add(warning)
