"""Synthetic actual CloudWatch query-ID and completeness responses."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from tools.collector_serverless.base import SyntheticServerlessClient


class SyntheticMetricClient(SyntheticServerlessClient):
    """Preserve the real batched query correlation and aggregate construction."""

    def get_metric_data(self, **kwargs: object) -> dict[str, Any]:
        """Provide finite observed datapoints; failures use the real SDK classifier."""
        self._fail("get_metric_data")
        queries = kwargs["MetricDataQueries"]
        if not isinstance(queries, list):
            message = "Synthetic metric queries must be a list."
            raise TypeError(message)
        return {
            "MetricDataResults": [
                {
                    "Id": query["Id"],
                    "Values": [] if self.session.variant == "no_data" else [1.25, 3.5],
                    "Timestamps": [] if self.session.variant == "no_data" else [datetime(2026, 9, 2, tzinfo=UTC), datetime(2026, 9, 3, tzinfo=UTC)],
                    "StatusCode": "Complete",
                }
                for query in queries
            ]
        }
