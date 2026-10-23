"""Explicit tagging DTO fields, typed maps and finite producer resource categories."""

from unio_collector.privacy.s3.fields import fields

SCANNER = "tagging-missing-cost-tags"
RESOURCES = {"VPC", "Subnet", "EC2 instance", "EBS volume", "EBS snapshot", "Elastic IP", "NAT Gateway", "Load balancer", "Target group", "Auto Scaling group"}
SERVICES = {"Amazon EC2", "Amazon VPC", "Amazon Elastic Block Store", "Elastic Load Balancing", "Amazon EC2 Auto Scaling", "AWS"}
MAPS = {"records[].tags", "records[].associated_resource_tags"}
FIELDS = {
    "": ("object", "safe_metadata", False),
    **fields("regions records required_tags", "array"),
    **fields("records[]", "object"),
    **fields("regions[] records[].region", "string", "region"),
    **fields("required_tags[]", "string", "tag_key"),
    **fields("analysis_inputs_version", "version"),
    **fields("required_tags_supplied", "boolean"),
    **fields("records[].resource_id", "string", "resource_id"),
    **fields("records[].associated_resource_id", "string", "resource_id", nullable=True),
    **fields("records[].resource_name", "string", "resource_name", nullable=True),
    **fields("records[].arn", "string", "arn", nullable=True),
    **fields("records[].account_id", "string", "aws_account_id"),
    **fields("records[].resource_type", "resource_type"),
    **fields("records[].associated_resource_type", "resource_type", nullable=True),
    **fields("records[].service", "service"),
    **fields("records[].association_reason", "string", "free_text", nullable=True),
    **fields(" ".join(sorted(MAPS)), "tag_map", "tag_value", nullable=True),
    **fields(" ".join(path + ".0" for path in sorted(MAPS)), "string", "tag_value"),
}
