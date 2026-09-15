"""Factual completeness and sample validation for CloudWatch responses."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from unio_collector.aws.metric.datapoint import MetricDatapoint
from unio_collector.aws.metric.read.reason import MetricReadReason
from unio_collector.aws.metric.read.values import MetricReadValues


class MetricResponseParser:
    """Retain complete paginated reads and label unresolved provider failures."""

    def parse_pages(self, pages: list[dict[str, Any]], query_ids: list[str]) -> dict[str, MetricReadValues]:
        """Consume existing response pages without requesting extra provider calls."""
        values = {query_id: MetricReadValues([], status="unavailable", reason=MetricReadReason.MISSING_RESULT) for query_id in query_ids}
        invalid: set[str] = set()
        for page in pages:
            results = page.get("MetricDataResults") if isinstance(page, dict) else None
            if not isinstance(results, list) or page.get("Messages"):
                self._invalidate_all(values, invalid, MetricReadReason.INCOMPLETE_RESPONSE)
                continue
            seen: set[str] = set()
            for result in results:
                if not isinstance(result, dict):
                    self._invalidate_all(values, invalid, MetricReadReason.MALFORMED_RESULT)
                    continue
                query_id = result.get("Id")
                if not isinstance(query_id, str) or query_id not in values or query_id in invalid:
                    continue
                read = values[query_id]
                if query_id in seen:
                    invalid.add(query_id)
                    read.status, read.reason = "unavailable", MetricReadReason.DUPLICATE_RESULT
                    continue
                seen.add(query_id)
                if not self._update_read(result, read, has_next=bool(page.get("NextToken"))):
                    invalid.add(query_id)
        return values

    def _update_read(self, result: dict[str, Any], read: MetricReadValues, *, has_next: bool) -> bool:
        status = result.get("StatusCode")
        if status not in {"Complete", "PartialData"} or result.get("Messages"):
            read.status, read.reason = "unavailable", MetricReadReason.PROVIDER_RESULT_UNAVAILABLE
            return False
        try:
            samples = self._samples(result)
        except ValueError:
            read.status, read.reason = "unavailable", MetricReadReason.MALFORMED_SAMPLES
            return False
        read.extend(samples)
        if status == "Complete":
            read.status, read.reason = "complete", None
            return True
        read.status, read.reason = "partial", MetricReadReason.PARTIAL_PROVIDER_DATA
        return has_next

    @staticmethod
    def _invalidate_all(values: dict[str, MetricReadValues], invalid: set[str], reason: MetricReadReason) -> None:
        invalid.update(values)
        for read in values.values():
            read.status, read.reason = "unavailable", reason

    def parse_statistics(self, response: object, statistic: str) -> MetricReadValues:
        """Reject missing or malformed lists instead of establishing empty reads."""
        points = response.get("Datapoints") if isinstance(response, dict) else None
        if not isinstance(points, list):
            return MetricReadValues([], status="unavailable", reason=MetricReadReason.MISSING_DATAPOINTS)
        values: list[Decimal | MetricDatapoint] = []
        for point in points:
            if not isinstance(point, dict) or not isinstance(point.get("Timestamp"), datetime):
                return MetricReadValues(values, status="unavailable", reason=MetricReadReason.MALFORMED_DATAPOINT)
            try:
                value = self._number(point.get(statistic))
            except ValueError:
                return MetricReadValues(values, status="unavailable", reason=MetricReadReason.MALFORMED_DATAPOINT)
            values.append(MetricDatapoint(timestamp=point["Timestamp"], value=value))
        return MetricReadValues(values)

    def _samples(self, result: dict[str, Any]) -> list[Decimal | MetricDatapoint]:
        values, timestamps = result.get("Values"), result.get("Timestamps")
        if not isinstance(values, list) or not isinstance(timestamps, list) or len(values) != len(timestamps):
            message = "CloudWatch sample arrays are missing or inconsistent."
            raise ValueError(message)
        samples: list[Decimal | MetricDatapoint] = []
        for timestamp, value in zip(timestamps, values, strict=True):
            if not isinstance(timestamp, datetime):
                message = "CloudWatch sample timestamp is missing or malformed."
                raise ValueError(message)
            samples.append(MetricDatapoint(timestamp=timestamp, value=self._number(value)))
        return samples

    @staticmethod
    def _number(value: object) -> Decimal:
        try:
            parsed = Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            message = "CloudWatch sample value is malformed."
            raise ValueError(message) from exc
        if not parsed.is_finite():
            message = "CloudWatch sample value is non-finite."
            raise ValueError(message)
        return parsed
