from __future__ import annotations  # noqa: D100

from unio_collector.providers.aws.identity import AWS_PROVIDER

AWS_PROVIDER_ID = AWS_PROVIDER.provider_id


def build_unknown_scanner_ids_message(
    scanner_ids: list[str] | tuple[str, ...] | set[str],
    *,
    provider_id: str | None,
) -> str:
    """Return the provider-scoped unknown scanner ID validation message."""
    resolved_provider_id = provider_id or AWS_PROVIDER_ID
    unknown = ", ".join(sorted(set(scanner_ids)))
    return f"Unknown scanner IDs for provider {resolved_provider_id!r}: {unknown}. Use scanner IDs from the {resolved_provider_id} scanner catalog."
