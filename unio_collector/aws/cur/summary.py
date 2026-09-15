from __future__ import annotations  # noqa: D100

from decimal import Decimal
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable


def build_top_resource_records(  # noqa: D103
    resource_costs: dict[str, Decimal],
    resource_context: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    sorted_resource_costs = sorted(
        resource_costs.items(),
        key=lambda item: item[1],
        reverse=True,
    )
    for resource_id, cost in sorted_resource_costs[:25]:
        context = resource_context.get(resource_id, {})
        records.append(
            {
                **context,
                "resource_id": resource_id,
                "cost": str(cost.quantize(Decimal("0.01"))),
            },
        )
    return records


def build_cur_limitations(path_limitations: Iterable[str]) -> list[str]:  # noqa: D103
    return [
        *path_limitations,
        ("CSV and CSV.GZ CUR/Data Export data files are supported from local paths and S3 object URIs."),
        ("Local directories and local or S3 manifest JSON files can be expanded to CSV/CSV.GZ files."),
        "Parquet and Athena query inputs are not supported in this phase.",
        "Cost allocation depends on columns present in the supplied export.",
    ]


def get_tag_value(tags: dict[str, str], requested_key: str) -> str | None:  # noqa: D103
    value = tags.get(requested_key)
    if value:
        return value
    requested = requested_key.casefold()
    for key, child in tags.items():
        if key.casefold() == requested:
            return child
    return None


def decimal_mapping_to_records(  # noqa: D103
    mapping: dict[str, Decimal],
    name_key: str,
) -> list[dict[str, str]]:
    return [
        {name_key: name, "cost": str(cost.quantize(Decimal("0.01")))}
        for name, cost in sorted(
            mapping.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:25]
    ]


def calculate_percentage(part: Decimal, whole: Decimal) -> str:  # noqa: D103
    if whole == 0:
        return "0.0"
    return str(((part / whole) * Decimal(100)).quantize(Decimal("0.1")))
