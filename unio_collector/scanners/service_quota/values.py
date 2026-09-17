"""Stable normalization of service quota collection values."""


def deduplicate_strings(values: list[str]) -> list[str]:  # noqa: D103
    return list(dict.fromkeys(value for value in values if value))
