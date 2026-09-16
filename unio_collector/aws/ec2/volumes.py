# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from typing import Any

from unio_collector.aws.ec2.helpers import build_ec2_arn
from unio_collector.aws.inventory_helpers import (
    AwsInventoryTagHelper,
)
from unio_collector.aws.taggable_resource_record import TaggableResourceRecord

_TAG_HELPER = AwsInventoryTagHelper()


class Ec2VolumeMixin:  # noqa: D101
    def _collect_taggable_nat_gateways(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        records: list[TaggableResourceRecord],
        subnet_context: dict[str, TaggableResourceRecord],
        vpc_context: dict[str, TaggableResourceRecord],
    ) -> None:
        for gateway in self._collect_nat_gateway_items(client):
            gateway_id = gateway["NatGatewayId"]
            tags = self._tags.tags_to_dict(gateway.get("Tags", []))
            associated_record = subnet_context.get(
                str(gateway.get("SubnetId") or ""),
            ) or vpc_context.get(str(gateway.get("VpcId") or ""))
            records.append(
                TaggableResourceRecord(
                    resource_id=gateway_id,
                    resource_type="NAT Gateway",
                    service="Amazon VPC",
                    account_id=self.account_id,
                    region=region,
                    resource_name=tags.get("Name"),
                    arn=build_ec2_arn(
                        region,
                        self.account_id,
                        "natgateway",
                        gateway_id,
                    ),
                    tags=tags,
                    associated_resource_id=(associated_record.resource_id if associated_record else None),
                    associated_resource_type=(associated_record.resource_type if associated_record else None),
                    associated_resource_tags=(associated_record.tags if associated_record else {}),
                    association_reason=("NAT Gateway is deployed in this tagged network resource." if associated_record else None),
                ),
            )

    def _collect_volume_items(
        self,
        client: Any,  # noqa: ANN401
        *,
        request_parameters: dict[str, Any],
    ) -> list[dict[str, Any]]:
        pages = self._pagination.collect_token_pages(
            client,
            "describe_volumes",
            result_key="Volumes",
            request_parameters=request_parameters,
        ).pages
        return self._values.collect_dict_items(pages, "Volumes")

    def _collect_nat_gateway_items(self, client: Any) -> list[dict[str, Any]]:  # noqa: ANN401
        pages = self._pagination.collect_token_pages(
            client,
            "describe_nat_gateways",
            result_key="NatGateways",
            request_parameters={"MaxResults": 1000},
        ).pages
        return self._values.collect_dict_items(pages, "NatGateways")
