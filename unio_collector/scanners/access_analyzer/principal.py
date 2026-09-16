from __future__ import annotations  # noqa: D100


def format_access_analyzer_principal(value: object) -> str | None:  # noqa: D103
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts = [f"{key}={value[key]}" for key in sorted(value) if value[key] is not None]
        return ", ".join(parts) or None
    return str(value)
