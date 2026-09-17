from __future__ import annotations  # noqa: D100

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from unio_collector.aws.ec2.helpers import build_ec2_arn
from unio_collector.aws.taggable_resource_record import TaggableResourceRecord

if TYPE_CHECKING:
    from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
    from unio_collector.aws.resource_groups.tagging import (
        ResourceGroupsTaggingCollectionResult,
    )


def merge_taggable_resource_records(  # noqa: D103
    direct_records: list[TaggableResourceRecord],
    fast_path_records: list[TaggableResourceRecord],
) -> list[TaggableResourceRecord]:
    merged: dict[tuple[str, str, str, str], TaggableResourceRecord] = {}
    for record in direct_records:
        merged[get_taggable_resource_key(record)] = record
    for record in fast_path_records:
        key = get_taggable_resource_key(record)
        if key in merged:
            merged[key] = merge_taggable_resource_record(merged[key], record)
            continue
        merged[key] = record
    return list(merged.values())


def build_nat_gateway_taggable_records(  # noqa: D103
    records: list[NatGatewayRecord],
) -> list[TaggableResourceRecord]:
    taggable_records: list[TaggableResourceRecord] = [
        TaggableResourceRecord(
            resource_id=record.nat_gateway_id,
            resource_type="NAT Gateway",
            service="Amazon VPC",
            account_id=record.account_id,
            region=record.region,
            resource_name=record.tags.get("Name"),
            arn=build_ec2_arn(
                record.region,
                record.account_id,
                "natgateway",
                record.nat_gateway_id,
            ),
            tags=record.tags,
        )
        for record in records
    ]
    return taggable_records


def get_taggable_resource_key(  # noqa: D103
    record: TaggableResourceRecord,
) -> tuple[str, str, str, str]:
    return (
        record.account_id,
        record.region,
        record.resource_type,
        record.resource_id or record.arn or "unknown",
    )


def merge_taggable_resource_record(
    primary: TaggableResourceRecord,
    secondary: TaggableResourceRecord,
) -> TaggableResourceRecord:
    """Merge duplicate tag records while preserving direct relationship context."""
    association_source = select_preferred_association(primary, secondary)
    return replace(
        primary,
        resource_name=primary.resource_name or secondary.resource_name,
        arn=primary.arn or secondary.arn,
        tags=primary.tags if primary.tags is not None else secondary.tags,
        associated_resource_id=association_source.associated_resource_id,
        associated_resource_type=association_source.associated_resource_type,
        associated_resource_tags=association_source.associated_resource_tags,
        association_reason=association_source.association_reason,
    )


def select_preferred_association(  # noqa: D103
    primary: TaggableResourceRecord,
    secondary: TaggableResourceRecord,
) -> TaggableResourceRecord:
    if not primary.associated_resource_id:
        return secondary if secondary.associated_resource_id else primary
    if not secondary.associated_resource_id:
        return primary
    primary_score = score_association_strength(primary)
    secondary_score = score_association_strength(secondary)
    return secondary if secondary_score > primary_score else primary


def score_association_strength(record: TaggableResourceRecord) -> int:  # noqa: D103
    score = {
        "Load balancer": 5,
        "Target group": 5,
        "Auto Scaling group": 4,
        "EC2 instance": 3,
        "Subnet": 2,
        "VPC": 1,
    }.get(record.associated_resource_type or "", 0)
    if record.associated_resource_tags:
        score += 1
    return score


def build_tagging_fast_path_note(  # noqa: D103
    result: ResourceGroupsTaggingCollectionResult,
) -> dict[str, Any]:
    status_text = result.status.replace("_", " ")
    if result.status == "completed":
        summary = (
            "Resource Groups Tagging API fast-path enrichment completed and "
            f"returned {len(result.records)} supported tagged resource "
            f"{pluralize('record', len(result.records))}."
        )
    elif result.status == "partial":
        summary = "Resource Groups Tagging API fast-path enrichment completed only partially; direct EC2 inventory remained the primary evidence source."
    elif result.status == "permission_denied":
        summary = "Resource Groups Tagging API fast-path enrichment was not available because tag:GetResources was denied; direct EC2 inventory was used."
    else:
        summary = "Resource Groups Tagging API fast-path enrichment was unavailable; direct EC2 inventory was used."
    return {
        "note_type": "fast_path_source",
        "summary": summary,
        "source": result.source,
        "status": result.status,
        "status_label": status_text,
        "records_returned": len(result.records),
        "regions_scanned": list(result.regions_scanned),
        "errors": list(result.errors),
        "limitations": list(result.limitations),
        "fallback_source": "direct_ec2_inventory",
        "impact": (
            "This source can enrich tagged-resource discovery, but it does not replace direct EC2 inventory for untagged resources or attachment relationships."
        ),
    }


def build_tagging_fast_path_disabled_note() -> dict[str, Any]:  # noqa: D103
    return {
        "note_type": "fast_path_source",
        "summary": ("Resource Groups Tagging API fast-path enrichment was disabled by scanner configuration; direct EC2 inventory was used."),
        "source": "resource_groups_tagging_api",
        "status": "disabled",
        "records_returned": 0,
        "regions_scanned": [],
        "errors": [],
        "limitations": [
            ("Direct EC2 inventory still checks supported EC2-family resources, including resources with no tags."),
        ],
        "fallback_source": "direct_ec2_inventory",
        "config_key": "tagging-missing-cost-tags.use_resource_groups_tagging_api",
    }


def pluralize(singular: str, count: int) -> str:  # noqa: D103
    return singular if count == 1 else f"{singular}s"
