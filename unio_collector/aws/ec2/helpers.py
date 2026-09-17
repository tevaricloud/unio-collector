from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws.inventory_helpers import AwsInventoryTagHelper

_TAG_HELPER = AwsInventoryTagHelper()


def tags_to_dict(tags: list[dict[str, Any]]) -> dict[str, str]:  # noqa: D103
    return _TAG_HELPER.tags_to_dict(tags)


def build_ec2_arn(  # noqa: D103
    region: str,
    account_id: str,
    resource_type: str,
    resource_id: str,
) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:{resource_type}/{resource_id}"


def first_attachment(attachments: list[dict[str, Any]]) -> dict[str, Any] | None:  # noqa: D103
    return attachments[0] if attachments else None
