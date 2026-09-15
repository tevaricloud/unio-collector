from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.inventory_helpers import AwsInventoryValueHelper


@dataclass(frozen=True)
class CloudFrontMarkerPaginator:
    """Collect CloudFront list responses that use Marker/NextMarker pagination."""

    values: AwsInventoryValueHelper

    def collect_items(  # noqa: D102
        self,
        client: Any,  # noqa: ANN401
        method_name: str,
        *,
        list_key: str,
        request_parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        marker: str | None = None
        seen_markers: set[str] = set()
        while True:
            request = dict(request_parameters or {})
            if marker:
                request["Marker"] = marker
            response = getattr(client, method_name)(**request)
            item_list = response.get(list_key) if isinstance(response, dict) else None
            records.extend(self.validate_items(item_list, paginated=True))
            if not isinstance(item_list, dict) or type(item_list.get("IsTruncated")) is not bool:
                msg = "CloudFront list response lacks explicit pagination completeness."
                raise ValueError(msg)
            if not item_list["IsTruncated"]:
                break
            marker = item_list.get("NextMarker")
            if not isinstance(marker, str) or not marker or marker in seen_markers:
                msg = "CloudFront pagination cursor is missing or repeated."
                raise ValueError(msg)
            seen_markers.add(marker)
        return records

    @staticmethod
    def validate_items(container: object, *, paginated: bool = False) -> list[dict[str, Any]]:
        """Require explicit rows, allowing account-wide quantities on pages."""
        if not isinstance(container, dict):
            msg = "CloudFront item container is unavailable."
            raise ValueError(msg)
        items = container.get("Items", [] if container.get("Quantity") == 0 else None)
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            msg = "CloudFront item rows are missing or malformed."
            raise ValueError(msg)
        if "Quantity" in container:
            quantity = container["Quantity"]
            if type(quantity) is not int or quantity < len(items) or (not paginated and quantity != len(items)):
                msg = "CloudFront item quantity contradicts the returned rows."
                raise ValueError(msg)
        return items
