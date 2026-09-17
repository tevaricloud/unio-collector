"""Read-only network operations with explicit enumeration outcomes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.aws.network.batch import NetworkInventoryBatch
from unio_collector.aws.network.coverage import NetworkCollectionCoverage

if TYPE_CHECKING:
    from collections.abc import Iterator

    from unio_collector.aws.audit import AwsAuditContext

NETWORK_OPERATIONS: dict[str, tuple[str, str, int | None]] = {
    "addresses": ("describe_addresses", "Addresses", None),
    "vpcs": ("describe_vpcs", "Vpcs", 100),
    "route_tables": ("describe_route_tables", "RouteTables", 100),
    "vpc_endpoints": ("describe_vpc_endpoints", "VpcEndpoints", 1000),
    "nat_gateways": ("describe_nat_gateways", "NatGateways", 1000),
    "network_interfaces": ("describe_network_interfaces", "NetworkInterfaces", 1000),
    "subnets": ("describe_subnets", "Subnets", 1000),
    "transit_gateways": ("describe_transit_gateways", "TransitGateways", 100),
    "transit_gateway_attachments": ("describe_transit_gateway_attachments", "TransitGatewayAttachments", 100),
    "transit_gateway_route_tables": ("describe_transit_gateway_route_tables", "TransitGatewayRouteTables", 100),
    "vpc_endpoint_service_configurations": ("describe_vpc_endpoint_service_configurations", "ServiceConfigurations", 100),
}


class NetworkOperationCollector:
    """Retain all normal pages and sanitize failures without extra AWS calls."""

    def __init__(self, session: Any, *, account_id: str, audit_context: AwsAuditContext) -> None:  # noqa: ANN401
        """Bind audited read-only session access."""
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context

    def collect(self, collection_name: str, region: str, *, client: Any = None) -> NetworkInventoryBatch:  # noqa: ANN401
        """Enumerate one existing operation and record its termination state."""
        method, result_key, page_size = NETWORK_OPERATIONS[collection_name]
        operation = "".join(part.title() for part in method.split("_"))
        items: list[dict[str, Any]] = []
        page_count = 0
        reason: str | None = None
        seen: set[str] = set()
        try:
            if client is None:
                client = self.session.create_client("ec2", region_name=region, audit_context=self.audit_context)
            for page in self._pages(client, method, page_size):
                if not isinstance(page, dict) or not isinstance(page.get(result_key, []), list):
                    reason = "api_failure"
                    break
                page_count += 1
                values = page.get(result_key, [])
                if any(not isinstance(item, dict) for item in values):
                    reason = "api_failure"
                    break
                items.extend(values)
                token = str(page.get("NextToken") or "")
                if token and token in seen:
                    reason = "pagination_cycle"
                    break
                if token:
                    seen.add(token)
        except Exception as error:  # noqa: BLE001
            response = getattr(error, "response", {})
            code = response.get("Error", {}).get("Code", "") if isinstance(response, dict) else ""
            reason = "api_denied" if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"} else "api_failure"
            if code in {"UnsupportedOperation", "UnsupportedOperationException", "OptInRequired"}:
                reason = "unsupported_region_service"
        if page_count == 0 and reason is None:
            reason = "api_failure"
        state = "complete" if reason is None else ("partial" if page_count else "unavailable")
        coverage = NetworkCollectionCoverage(
            account_id=self.account_id,
            collection_name=collection_name,
            region=region,
            operation=operation,
            state=state,
            pages_observed=page_count,
            resources_observed=len(items),
            resources_retained=len(items),
            enumeration_normal_termination=reason is None,
            reason_codes=(reason,) if reason else (),
            failure_category=reason,
            failure_reference=f"{operation}:{region}" if reason else None,
        )
        return NetworkInventoryBatch(self.account_id, collection_name, {region: items}, (coverage,))

    def _pages(self, client: Any, method: str, page_size: int | None) -> Iterator[Any]:  # noqa: ANN401
        parameters: dict[str, Any] = {} if page_size is None else {"MaxResults": page_size}
        can_paginate = getattr(client, "can_paginate", None)
        try:
            paginated = page_size is not None and callable(can_paginate) and can_paginate(method)
        except Exception:  # noqa: BLE001
            paginated = False
        if paginated:
            yield from client.get_paginator(method).paginate(**parameters)
            return
        operation = getattr(client, method)
        while True:
            response = operation(**parameters)
            yield response
            token = response.get("NextToken") if isinstance(response, dict) else None
            if page_size is None or not token:
                return
            parameters["NextToken"] = str(token)
