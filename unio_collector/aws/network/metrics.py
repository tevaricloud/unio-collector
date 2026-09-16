"""Factual NAT CloudWatch requests with private post-replay interpretation."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudwatch.metric_collector import CloudWatchMetricCollector
from unio_collector.aws.metric.context import MetricCollectionContext
from unio_collector.aws.metric.request import MetricRequest

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
    from unio_collector.core.scan.period import ScanPeriod


class NetworkMetricCollector:
    """Preserve seven hourly provider requests and collection context."""

    def __init__(self, session: Any, *, audit_context: AwsAuditContext, regions: list[str]) -> None:  # noqa: ANN401
        """Bind the existing session and metric collection scope."""
        self.session = session
        self.audit_context = audit_context
        self.regions = regions

    def get_available_regions(self) -> list[str]:
        """Return the supplied collection scope."""
        return self.regions

    def add_nat_gateway_metrics(
        self,
        records: list[NatGatewayRecord],
        scan_period: ScanPeriod,
    ) -> list[NatGatewayRecord]:
        """Attach read-only hourly CloudWatch capacity and health evidence."""
        result: list[NatGatewayRecord] = []
        for region in sorted({record.region for record in records}):
            regional = [record for record in records if record.region == region]
            collector = CloudWatchMetricCollector(
                self.session,
                region=region,
                audit_context=self.audit_context,
            )
            requests: list[MetricRequest] = []
            record_indexes: list[int] = []
            for index, record in enumerate(regional):
                dimensions = [
                    {"Name": "NatGatewayId", "Value": record.nat_gateway_id},
                ]
                for name, statistic in (
                    ("BytesInFromSource", "Sum"),
                    ("BytesOutToDestination", "Sum"),
                    ("PeakBytesPerSecond", "Maximum"),
                    ("PeakPacketsPerSecond", "Maximum"),
                    ("ActiveConnectionCount", "Maximum"),
                    ("ErrorPortAllocation", "Sum"),
                    ("PacketsDropCount", "Sum"),
                ):
                    requests.append(
                        MetricRequest(
                            namespace="AWS/NATGateway",
                            metric_name=name,
                            dimensions=dimensions,
                            statistic=statistic,
                            period=3600,
                            start_time=scan_period.current_start_datetime,
                            end_time=scan_period.current_end_exclusive_datetime,
                            collection_context=MetricCollectionContext.NAT_GATEWAY,
                        ),
                    )
                    record_indexes.append(index)
            summaries_by_index = {index: [] for index in range(len(regional))}
            for index, summary in zip(
                record_indexes,
                collector.collect_metric_summaries(requests),
                strict=True,
            ):
                summaries_by_index[index].append(summary)
            result.extend(replace(record, metric_summaries=summaries_by_index[index]) for index, record in enumerate(regional))
        return result
