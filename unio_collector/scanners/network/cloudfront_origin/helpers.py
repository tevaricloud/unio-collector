from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cloudfront.distribution import CloudFrontDistributionRecord


def build_cloudfront_execution_detail_note(  # noqa: D103
    record: CloudFrontDistributionRecord,
) -> dict[str, object]:
    metric_status = format_cloudfront_metric_collection_status(
        record.metric_collection_status,
    )
    return {
        "note_type": "execution_detail",
        "scanner_id": "cloudfront-origin-cost-review",
        "scope_area": "cloudfront_distribution_metadata",
        "summary": (
            "CloudFront origin cost review collected "
            f"{record.distribution_count} distribution(s), "
            f"{record.origin_count} origin(s), and "
            f"{record.cache_behavior_count} cache behavior(s); metric "
            f"enrichment: {metric_status}."
        ),
        "regions_attempted": ["global"],
        "distribution_count": record.distribution_count,
        "enabled_distribution_count": record.enabled_distribution_count,
        "origin_count": record.origin_count,
        "cache_behavior_count": record.cache_behavior_count,
        "metric_collection_status": record.metric_collection_status,
        "metric_distribution_count": record.metric_distribution_count,
        "metric_datapoint_count": record.metric_datapoint_count,
        "metric_collection_reason": record.metric_collection_reason,
        "result_scope": "current_scan",
        "impact": ("CloudFront inventory collection is read-only. Metric enrichment runs only when optional enrichment is allowed for the scan."),
    }


def format_cloudfront_metric_collection_status(status: str) -> str:  # noqa: D103
    status_map = {
        "skipped_by_chargeable_policy": ("not run because optional metric enrichment was not enabled"),
        "not_configured": "not configured for this scan",
        "not_applicable": "not applicable for the visible distribution inventory",
        "no_datapoints": "ran, but returned no standard metric datapoints",
        "failed": "attempted but failed",
        "collected": "collected",
    }
    return status_map.get(status, status.replace("_", " ") or "not recorded")
