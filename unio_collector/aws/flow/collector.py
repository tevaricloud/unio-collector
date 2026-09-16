from __future__ import annotations  # noqa: D100

import time
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from unio_collector.aws.flow.collection.helpers import (
    build_flow_log_insights_query,
)
from unio_collector.aws.flow.collection.metadata import VpcFlowLogCollectionMetadata
from unio_collector.aws.flow.definition import VpcFlowLogDefinition
from unio_collector.aws.flow.observation import FlowObservation
from unio_collector.aws.flow.query_summary import FlowQuerySummary
from unio_collector.aws.flow.topology_context import FlowTopologyContext
from unio_collector.aws.inventory_helpers import (
    AwsEc2RegionDiscoveryHelper,
    AwsInventoryValueHelper,
)
from unio_collector.aws.log.insights_polling import LogsInsightsPollingConfig
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.core.count_formatting import format_count

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.core.scan.period import ScanPeriod


class VpcFlowLogCollector:
    """Collects read-only VPC Flow Log attribution from CloudWatch Logs Insights."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str] | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = selected_regions
        self._available_regions_cache: list[str] | None = None
        self._metadata = VpcFlowLogCollectionMetadata()
        self._query_reasons: set[str] = set()
        self._pagination = AwsPaginationHelper()
        self._regions = AwsEc2RegionDiscoveryHelper(
            self.session,
            audit_context=self.audit_context,
        )
        self._values = AwsInventoryValueHelper()

    def collect_attribution(  # noqa: D102
        self,
        scan_period: ScanPeriod,
        *,
        max_log_groups_per_region: int = 3,
        query_limit: int = 50,
        max_query_polls: int = 12,
        poll_seconds: float = 1.0,
        query_timeout_seconds: float = 120.0,
    ) -> tuple[list[FlowObservation], dict[str, Any]]:
        records: list[FlowObservation] = []
        metadata = VpcFlowLogCollectionMetadata()
        self._metadata = metadata
        for region in self.get_available_regions():
            region_records: list[FlowObservation] = []
            definitions = self.collect_flow_log_definitions(region)
            metadata.record_flow_log_count(len(definitions))
            if len(definitions) > max_log_groups_per_region:
                metadata.reasons.add("definition_cap_reached")
            for definition in definitions[:max_log_groups_per_region]:
                metadata.record_queried_log_group(region, definition.log_group_name)
                self._query_reasons = set() if definition.format_supported else {"unsupported_format"}
                try:
                    query_records = self.query_log_group(
                        definition,
                        scan_period,
                        query_limit=query_limit,
                        max_query_polls=max_query_polls,
                        poll_seconds=poll_seconds,
                        query_timeout_seconds=query_timeout_seconds,
                    )
                    region_records.extend(query_records)
                    capped = len(query_records) >= query_limit or "query_result_limit_reached" in self._query_reasons
                    metadata.queries.append(
                        FlowQuerySummary(
                            region,
                            definition.flow_log_id,
                            definition.log_group_name,
                            scan_period.current_start_datetime.isoformat(),
                            scan_period.current_end_exclusive_datetime.isoformat(),
                            query_limit,
                            len(query_records),
                            "partial" if "unsupported_format" in self._query_reasons else "capped" if capped else "complete",
                            tuple(sorted(self._query_reasons | ({"query_result_limit_reached"} if capped else set()))),
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    metadata.record_query_error(
                        region,
                        definition.log_group_name,
                        exc,
                    )
                    metadata.queries.append(
                        FlowQuerySummary(
                            region,
                            definition.flow_log_id,
                            definition.log_group_name,
                            scan_period.current_start_datetime.isoformat(),
                            scan_period.current_end_exclusive_datetime.isoformat(),
                            query_limit,
                            0,
                            "unavailable",
                            ("query_failure",),
                        )
                    )
            topology = FlowTopologyContext(self.session, self.audit_context)
            try:
                enriched_records = topology.enrich_records_with_network_interfaces(
                    region,
                    region_records,
                )
            except Exception as exc:  # noqa: BLE001
                enriched_records = region_records
                topology.reasons.add("address_unresolved")
                metadata.enrichment_errors.append(f"{region}:{exc}")
            try:
                enriched_records = topology.enrich_records_with_route_tables(region, enriched_records)
            except Exception as exc:  # noqa: BLE001
                topology.reasons.add("route_context_incomplete")
                metadata.route_table_enrichment_errors.append(f"{region}:{exc}")
            records.extend(enriched_records)
            metadata.topology[region] = topology.snapshot(enriched_records)
        return records, metadata.convert_to_dict()

    def collect_flow_log_definitions(self, region: str) -> list[VpcFlowLogDefinition]:  # noqa: D102
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        definitions: list[VpcFlowLogDefinition] = []
        pages = self._pagination.collect_token_pages(
            client,
            "describe_flow_logs",
            result_key="FlowLogs",
            request_parameters={"MaxResults": 1000},
        ).pages
        for flow_log in self._values.collect_dict_items(pages, "FlowLogs"):
            if flow_log.get("LogDestinationType") != "cloud-watch-logs":
                self._metadata.reasons.add("unsupported_destination")
                continue
            log_group_name = flow_log.get("LogGroupName")
            if not log_group_name:
                continue
            expected_fields = (
                "version",
                "account-id",
                "interface-id",
                "srcaddr",
                "dstaddr",
                "srcport",
                "dstport",
                "protocol",
                "packets",
                "bytes",
                "start",
                "end",
                "action",
                "log-status",
            )
            log_format = flow_log.get("LogFormat")
            format_supported = not bool(log_format) or str(log_format).split() == ["${" + name + "}" for name in expected_fields]
            definitions.append(
                VpcFlowLogDefinition(
                    flow_log_id=flow_log.get("FlowLogId", "unknown-flow-log"),
                    region=region,
                    resource_id=flow_log.get("ResourceId"),
                    resource_type=flow_log.get("ResourceType"),
                    log_group_name=log_group_name,
                    traffic_type=flow_log.get("TrafficType"),
                    format_supported=format_supported,
                ),
            )
        return sorted(definitions, key=lambda item: (item.log_group_name, item.flow_log_id, item.resource_id or ""))

    def query_log_group(  # noqa: D102
        self,
        definition: VpcFlowLogDefinition,
        scan_period: ScanPeriod,
        *,
        query_limit: int,
        max_query_polls: int,
        poll_seconds: float,
        query_timeout_seconds: float,
    ) -> list[FlowObservation]:
        client = self.session.create_client(
            "logs",
            region_name=definition.region,
            audit_context=self.audit_context,
        )
        response = client.start_query(
            logGroupName=definition.log_group_name,
            startTime=int(scan_period.current_start_datetime.timestamp()),
            endTime=int(scan_period.current_end_exclusive_datetime.timestamp()),
            queryString=build_flow_log_insights_query(query_limit),
            limit=query_limit,
        )
        query_id = response["queryId"]
        polling = LogsInsightsPollingConfig(
            timeout_seconds=query_timeout_seconds,
            poll_seconds=poll_seconds,
        )
        deadline = polling.get_deadline()
        attempts = 0
        while time.monotonic() <= deadline:
            attempts += 1
            result = client.get_query_results(queryId=query_id)
            status = result.get("status")
            if status == "Complete":
                rows = result.get("results", [])
                if len(rows) >= query_limit:
                    self._query_reasons.add("query_result_limit_reached")
                return self.convert_query_results(definition, rows[:query_limit])
            if status in {"Failed", "Cancelled", "Timeout"}:
                msg = f"Logs Insights query ended with status {status}."
                raise RuntimeError(msg)
            if max_query_polls > 0 and attempts >= max_query_polls and attempts * polling.poll_seconds >= polling.timeout_seconds:
                break
            sleep_seconds = polling.get_sleep_seconds(deadline)
            if sleep_seconds <= 0:
                break
            time.sleep(sleep_seconds)
        msg = f"Timed out waiting for VPC Flow Log Logs Insights query after {format_count(int(max(1.0, query_timeout_seconds)), 'second')}."
        raise TimeoutError(
            msg,
        )

    def convert_query_result(  # noqa: D102
        self,
        definition: VpcFlowLogDefinition,
        row: list[dict[str, str]],
    ) -> FlowObservation | None:
        values = {item.get("field"): item.get("value") for item in row}
        srcaddr = values.get("srcaddr")
        dstaddr = values.get("dstaddr")
        if not srcaddr or not dstaddr:
            return None
        return FlowObservation(
            region=definition.region,
            flow_log_id=definition.flow_log_id,
            log_group_name=definition.log_group_name,
            resource_id=definition.resource_id,
            srcaddr=srcaddr,
            dstaddr=dstaddr,
            action=values.get("action") or "ACCEPT",
            bytes=int(Decimal(values.get("totalBytes") or values.get("bytes") or "0")),
            packets=int(
                Decimal(values.get("totalPackets") or values.get("packets") or "0"),
            ),
            flows=int(Decimal(values.get("flowCount") or values.get("flows") or "0")),
        )

    def convert_query_results(  # noqa: D102
        self,
        definition: VpcFlowLogDefinition,
        rows: list[list[dict[str, str]]],
    ) -> list[FlowObservation]:
        records: list[FlowObservation] = []
        for row in rows:
            record = self.convert_query_result(definition, row)
            if record is not None:
                records.append(record)
            else:
                self._query_reasons.add("unsupported_format")
        return sorted(records, key=lambda item: (-item.bytes, item.srcaddr, item.dstaddr, item.action))

    def get_available_regions(self) -> list[str]:  # noqa: D102
        if self._available_regions_cache is not None:
            return self._available_regions_cache
        self._available_regions_cache = self._regions.get_available_regions(
            self.selected_regions,
        )
        return self._available_regions_cache
