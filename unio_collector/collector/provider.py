from __future__ import annotations  # noqa: D100

AWS_COLLECTOR_PROVIDER_ID = "aws"


def normalize_collector_provider_id(value: str | None) -> str:
    """Validate the AWS-only standalone collector provider selection."""
    provider_id = (value or AWS_COLLECTOR_PROVIDER_ID).strip().lower()
    if provider_id != AWS_COLLECTOR_PROVIDER_ID:
        msg = "The standalone collector distribution currently supports AWS only."
        raise ValueError(msg)
    return provider_id
