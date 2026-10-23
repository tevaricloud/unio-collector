"""Independent explicit field inventory for FlowObservation and its nullable context."""

from unio_collector.privacy.s3.fields import fields

FIELDS = {
    **fields("records[]", "object"),
    **fields("records[].region", "string", "region"),
    **fields("records[].flow_log_id records[].log_group_name", "string", "resource_id"),
    **fields("records[].resource_id", "string", "resource_id", nullable=True),
    **fields("records[].srcaddr records[].dstaddr", "string", "network_identity"),
    **fields("records[].action", "flow_action"),
    **fields("records[].bytes records[].packets records[].flows", "count", "summary_count"),
    **fields("records[].traffic_classification", "string", "free_text", nullable=True),
}
for side in ("src", "dst"):
    prefix = "records[]." + side + "_"
    FIELDS.update(
        {
            **fields(
                " ".join(prefix + name for name in ("eni_id", "vpc_id", "subnet_id", "attachment_instance_id", "route_table_id", "default_route_target")),
                "string",
                "resource_id",
                nullable=True,
            ),
            **fields(prefix + "resource_owner_id", "string", "aws_account_id", nullable=True),
            **fields(prefix + "availability_zone", "string", "region", nullable=True),
            **fields(prefix + "description", "string", "free_text", nullable=True),
            **fields(prefix + "private_dns_name", "string", "resource_name", nullable=True),
            **fields(prefix + "interface_type", "interface_type", nullable=True),
            **fields(prefix + "default_route_target_type", "target_type", nullable=True),
            **fields(prefix + "route_table_association", "association", nullable=True),
            **fields(prefix + "address_status", "address_status"),
            **fields(prefix + "attribution_tags", "tag_map", "tag_value", nullable=True),
            **fields(prefix + "attribution_tags.0", "string", "tag_value"),
        }
    )
