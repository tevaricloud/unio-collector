from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws.parsed_resource_arn import ParsedResourceArn

DEFAULT_RESOURCE_TYPE_FILTERS = (
    "ec2:instance",
    "ec2:volume",
    "ec2:elastic-ip",
    "ec2:natgateway",
    "ec2:snapshot",
)


def parse_resource_arn(arn: str) -> ParsedResourceArn | None:  # noqa: D103
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":  # noqa: PLR2004
        return None
    resource_type, resource_id = split_resource_part(parts[5])
    if not resource_type or not resource_id:
        return None
    return ParsedResourceArn(
        partition=parts[1],
        service=parts[2],
        region=parts[3],
        account_id=parts[4],
        resource_type=resource_type,
        resource_id=resource_id,
    )


def split_resource_part(resource: str) -> tuple[str, str]:  # noqa: D103
    for separator in ("/", ":"):
        if separator in resource:
            resource_type, resource_id = resource.split(separator, 1)
            return resource_type, resource_id
    return "", resource


def describe_supported_resource_type(parsed: ParsedResourceArn) -> str | None:  # noqa: D103
    if parsed.service != "ec2":
        return None
    return {
        "instance": "EC2 instance",
        "volume": "EBS volume",
        "elastic-ip": "Elastic IP",
        "natgateway": "NAT Gateway",
        "snapshot": "EBS snapshot",
    }.get(parsed.resource_type)


def describe_supported_service(resource_type: str) -> str:  # noqa: D103
    return {
        "EC2 instance": "Amazon EC2",
        "EBS volume": "Amazon Elastic Block Store",
        "EBS snapshot": "Amazon Elastic Block Store",
        "Elastic IP": "Amazon EC2",
        "NAT Gateway": "Amazon VPC",
    }.get(resource_type, "AWS")


def tags_to_dict(tags: Any) -> dict[str, str]:  # noqa: ANN401, D103
    if not isinstance(tags, list):
        return {}
    return {str(tag.get("Key")): str(tag.get("Value")) for tag in tags if isinstance(tag, dict) and tag.get("Key") is not None}
