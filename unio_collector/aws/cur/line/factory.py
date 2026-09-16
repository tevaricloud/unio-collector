from __future__ import annotations  # noqa: D100

from datetime import date
from decimal import Decimal, InvalidOperation

from unio_collector.aws.cur.line.item import CurLineItem

CUR_TAG_PREFIXES = (
    "resourcetags/user:",
    "resourceTags/user:",
    "resource_tags_user_",
    "resourcetags_user_",
)


class CurLineItemFactory:  # noqa: D101
    def __init__(self, row: dict[str, str]) -> None:  # noqa: D107
        self.row = row
        self.normalized = {normalize_column_name(key): value for key, value in row.items()}

    def create_line_item(self) -> CurLineItem | None:  # noqa: D102
        usage_start = parse_usage_date(
            self.get_value(
                "lineItem/UsageStartDate",
                "line_item_usage_start_date",
                "usage_start_date",
            ),
        )
        cost = parse_decimal(
            self.get_value(
                "lineItem/NetUnblendedCost",
                "line_item_net_unblended_cost",
                "lineItem/NetAmortizedCost",
                "line_item_net_amortized_cost",
                "lineItem/AmortizedCost",
                "line_item_amortized_cost",
                "lineItem/UnblendedCost",
                "line_item_unblended_cost",
                "unblended_cost",
                "cost",
            ),
        )
        if usage_start is None or cost is None:
            return None
        service_name = self.get_value(
            "product/ProductName",
            "product_product_name",
            "service",
            "lineItem/ProductCode",
            "line_item_product_code",
        )
        region = self.get_value(
            "product/region",
            "product_region",
            "region",
            "lineItem/AvailabilityZone",
            "line_item_availability_zone",
        )
        return CurLineItem(
            usage_start_date=usage_start,
            service_name=service_name or "Unknown",
            region=region or "global",
            usage_type=self.get_value(
                "lineItem/UsageType",
                "line_item_usage_type",
                "usage_type",
            ),
            resource_id=self.get_value(
                "lineItem/ResourceId",
                "line_item_resource_id",
                "resource_id",
            ),
            account_id=self.get_value(
                "lineItem/UsageAccountId",
                "line_item_usage_account_id",
                "account_id",
            ),
            cost=cost,
            currency=(self.get_value("pricing/currency", "pricing_currency", "currency") or "USD").upper(),
            tags=self.extract_tags(),
        )

    def get_value(self, *column_names: str) -> str | None:  # noqa: D102
        for column_name in column_names:
            raw_value = self.row.get(column_name)
            if raw_value not in (None, ""):
                return raw_value.strip()
            normalized_value = self.normalized.get(normalize_column_name(column_name))
            if normalized_value not in (None, ""):
                return normalized_value.strip()
        return None

    def extract_tags(self) -> dict[str, str]:  # noqa: D102
        tags: dict[str, str] = {}
        for key, value in self.row.items():
            if not value:
                continue
            tag_key = extract_tag_key(key)
            if tag_key:
                tags[tag_key] = value.strip()
        return tags


def normalize_column_name(value: str) -> str:  # noqa: D103
    return value.replace("/", "_").replace(":", "_").replace("-", "_").replace(" ", "_").casefold()


def extract_tag_key(column_name: str) -> str | None:  # noqa: D103
    for prefix in CUR_TAG_PREFIXES:
        if column_name.startswith(prefix):
            return column_name[len(prefix) :]
    normalized = normalize_column_name(column_name)
    for prefix in ("resourcetags_user_", "resource_tags_user_"):
        if normalized.startswith(prefix):
            return normalized[len(prefix) :]
    return None


def parse_usage_date(value: str | None) -> date | None:  # noqa: D103
    if not value:
        return None
    normalized = value.strip().replace("Z", "+00:00")
    try:
        return date.fromisoformat(normalized[:10])
    except ValueError:
        return None


def parse_decimal(value: str | None) -> Decimal | None:  # noqa: D103
    if value in (None, ""):
        return None
    try:
        result = Decimal(value)
        return result if result.is_finite() else None
    except (InvalidOperation, ValueError):
        return None
