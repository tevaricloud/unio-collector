"""Read-only topology enrichment with bounded, deduplicated evidence."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from unio_collector.aws.flow.collection.helpers import (
    build_main_route_table_context,
    build_network_interface_context,
    build_subnet_route_table_contexts,
    enrich_record_with_interface_context,
    enrich_record_with_route_context,
    is_private_ip,
)
from unio_collector.aws.flow.route_record import FlowRouteRecord
from unio_collector.aws.inventory_helpers import AwsInventoryValueHelper

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.flow.observation import FlowObservation
    from unio_collector.aws.route_table_context import RouteTableContext

TOPOLOGY_BUDGET_BYTES = 256 * 1024


class FlowTopologyContext:
    """Join observed topology without choosing optimization paths."""

    def __init__(self, session: Any, audit_context: AwsAuditContext) -> None:  # noqa: ANN401
        """Use the existing audited session; no clients are constructed eagerly."""
        self.session = session
        self.audit_context = audit_context
        self._values = AwsInventoryValueHelper()
        self._facts: dict[str, dict[str, Any]] = {}
        self.reasons: set[str] = set()

    def _add_fact(self, fact: dict[str, Any]) -> None:
        key = json.dumps(fact, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self._facts[key] = fact

    def _record_routes(self, table: dict[str, Any]) -> None:
        for route in table.get("Routes", []):
            self._add_fact({"kind": "route", **asdict(FlowRouteRecord.from_response(table, route))})

    def _record_continuation(self, response: dict[str, Any]) -> None:
        if response.get("NextToken"):
            self.reasons.add("continuation_not_followed")

    def _associate_address(self, mapping: dict[str, dict[str, Any]], address: str, context: dict[str, Any]) -> None:
        previous = mapping.get(address)
        if previous and previous.get("eni_id") != context.get("eni_id"):
            mapping[address] = {"address_status": "ambiguous"}
            self.reasons.add("ambiguous_address")
        else:
            mapping[address] = context

    def snapshot(self, records: list[FlowObservation]) -> dict[str, Any]:
        """Bound the canonical JSON facts array, retaining whole facts only."""
        retained: list[dict[str, Any]] = []
        used = 2
        for key, fact in sorted(self._facts.items()):
            required = len(key.encode("utf-8")) + bool(retained)
            if used + required > TOPOLOGY_BUDGET_BYTES:
                continue
            retained.append(fact)
            used += required
        omitted = len(self._facts) - len(retained)
        if omitted:
            self.reasons.add("topology_evidence_omitted_by_bound")
        statuses = {status for record in records for status in (record.src_address_status, record.dst_address_status)}
        if "unresolved" in statuses:
            self.reasons.add("address_unresolved")
        if any((record.src_eni_id and not record.src_route_table_id) or (record.dst_eni_id and not record.dst_route_table_id) for record in records):
            self.reasons.add("route_context_incomplete")
        if "ambiguous" in statuses:
            state = "ambiguous"
        elif self.reasons:
            state = "partial" if retained else "unavailable"
        else:
            state = "complete" if retained else "unavailable"
        return {
            "state": state,
            "reason_codes": sorted(self.reasons),
            "facts": retained,
            "budget_bytes": TOPOLOGY_BUDGET_BYTES,
            "bytes_used": used,
            "facts_retained": len(retained),
            "facts_omitted": omitted,
            "bound_hit": bool(omitted),
            "selection": "canonical-json-ascending-v1",
            "route_scope": "observed-default-context-not-destination-path",
        }

    def enrich_records_with_network_interfaces(  # noqa: D102
        self,
        region: str,
        records: list[FlowObservation],
    ) -> list[FlowObservation]:
        if not records:
            return []
        private_ips = sorted(
            {address for record in records for address in (record.srcaddr, record.dstaddr) if is_private_ip(address)},
        )
        if not private_ips:
            return records
        eni_by_ip = self.collect_network_interfaces_by_private_ip(region, private_ips)
        return [enrich_record_with_interface_context(record, eni_by_ip) for record in records]

    def collect_network_interfaces_by_private_ip(  # noqa: D102
        self,
        region: str,
        private_ips: list[str],
    ) -> dict[str, dict[str, Any]]:
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        interfaces_by_ip: dict[str, dict[str, Any]] = {}
        for chunk in self._values.chunk_values(private_ips, 100):
            response = client.describe_network_interfaces(
                Filters=[
                    {
                        "Name": "addresses.private-ip-address",
                        "Values": chunk,
                    },
                ],
            )
            self._record_continuation(response)
            for interface in self._values.collect_response_items(
                response,
                "NetworkInterfaces",
            ):
                context = build_network_interface_context(interface)
                self._add_fact(
                    {
                        "kind": "interface",
                        **context,
                        "private_addresses": sorted(
                            {str(item.get("PrivateIpAddress")) for item in interface.get("PrivateIpAddresses", []) if item.get("PrivateIpAddress")}
                            | ({str(interface["PrivateIpAddress"])} if interface.get("PrivateIpAddress") else set())
                        ),
                    }
                )
                for private_address in interface.get("PrivateIpAddresses", []):
                    private_ip = private_address.get("PrivateIpAddress")
                    if private_ip:
                        self._associate_address(interfaces_by_ip, private_ip, context)
                primary_ip = interface.get("PrivateIpAddress")
                if primary_ip:
                    self._associate_address(interfaces_by_ip, primary_ip, context)
        return interfaces_by_ip

    def enrich_records_with_route_tables(  # noqa: D102
        self,
        region: str,
        records: list[FlowObservation],
    ) -> list[FlowObservation]:
        if not records:
            return []
        subnet_ids = sorted(
            {subnet_id for record in records for subnet_id in (record.src_subnet_id, record.dst_subnet_id) if subnet_id},
        )
        vpc_ids = sorted(
            {vpc_id for record in records for vpc_id in (record.src_vpc_id, record.dst_vpc_id) if vpc_id},
        )
        if not subnet_ids and not vpc_ids:
            return records
        subnet_routes, main_routes = self.collect_route_table_contexts(
            region,
            subnet_ids=subnet_ids,
            vpc_ids=vpc_ids,
        )
        return [enrich_record_with_route_context(record, subnet_routes, main_routes) for record in records]

    def collect_route_table_contexts(  # noqa: D102
        self,
        region: str,
        *,
        subnet_ids: list[str],
        vpc_ids: list[str],
    ) -> tuple[dict[str, RouteTableContext], dict[str, RouteTableContext]]:
        client = self.session.create_client(
            "ec2",
            region_name=region,
            audit_context=self.audit_context,
        )
        subnet_routes: dict[str, RouteTableContext] = {}
        main_routes: dict[str, RouteTableContext] = {}
        for chunk in self._values.chunk_values(subnet_ids, 100):
            response = client.describe_route_tables(
                Filters=[{"Name": "association.subnet-id", "Values": chunk}],
            )
            self._record_continuation(response)
            for route_table in self._values.collect_response_items(
                response,
                "RouteTables",
            ):
                self._record_routes(route_table)
                subnet_routes.update(build_subnet_route_table_contexts(route_table))
        for chunk in self._values.chunk_values(vpc_ids, 100):
            response = client.describe_route_tables(
                Filters=[
                    {"Name": "vpc-id", "Values": chunk},
                    {"Name": "association.main", "Values": ["true"]},
                ],
            )
            self._record_continuation(response)
            for route_table in self._values.collect_response_items(
                response,
                "RouteTables",
            ):
                self._record_routes(route_table)
                context = build_main_route_table_context(route_table)
                if context.vpc_id:
                    main_routes[context.vpc_id] = context
        return subnet_routes, main_routes
