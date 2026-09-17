"""Neutral AWS organization ARN partition lookup."""


def arn_partition(discovery_arn: str) -> str:
    """Return the role ARN partition."""
    return discovery_arn.split(":", maxsplit=2)[1] if discovery_arn.startswith("arn:") else "aws"
