from __future__ import annotations  # noqa: D100

from typing import Any


def infer_partition(bundle: Any) -> str:  # noqa: ANN401
    """Infer the AWS partition from bundle account context."""
    arn = str(bundle.account_context.get("arn") or "")
    for prefix, partition in (
        ("arn:aws-us-gov:", "aws-us-gov"),
        ("arn:aws-cn:", "aws-cn"),
    ):
        if arn.startswith(prefix):
            return partition
    return "aws"
