from __future__ import annotations  # noqa: D100


def calculate_average(values: list[float]) -> float | None:  # noqa: D103
    if not values:
        return None
    return round(sum(values) / len(values), 2)


def resolve_metric_collection_status(  # noqa: D103
    *,
    datapoint_count: int,
    errors: list[str],
) -> str:
    if errors and datapoint_count > 0:
        return "partial"
    if errors:
        return "failed"
    if datapoint_count > 0:
        return "collected"
    return "no_datapoints"


def normalize_cloudfront_invalidation_detail_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in {"full", "summary"}:
        return normalized
    msg = "CloudFront invalidation_detail_mode must be one of 'full' or 'summary'."
    raise ValueError(
        msg,
    )


def build_metric_collection_reason(  # noqa: D103
    *,
    datapoint_count: int,
    errors: list[str],
) -> str:
    if errors and datapoint_count > 0:
        return "CloudWatch GetMetricData returned some CloudFront metric datapoints, but one or more metric batches failed."
    if errors:
        return "CloudWatch GetMetricData did not return CloudFront metric datapoints because metric collection failed."
    if datapoint_count > 0:
        return "CloudWatch GetMetricData returned CloudFront standard metric datapoints for the selected scan period."
    return "CloudWatch GetMetricData completed but did not return CloudFront standard metric datapoints for the selected scan period."
