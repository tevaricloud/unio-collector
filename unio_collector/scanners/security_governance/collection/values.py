from __future__ import annotations  # noqa: D100

from typing import Any


def chunk_values(values: list[str], size: int) -> list[list[str]]:  # noqa: D103
    return [values[index : index + size] for index in range(0, len(values), size)]


def normalize_reportable_metadata(metadata: dict[str, Any]) -> dict[str, Any]:  # noqa: D103
    normalized: dict[str, Any] = {}
    for key, value in metadata.items():
        if isinstance(value, tuple):
            normalized[key] = list(value)
            continue
        normalized[key] = value
    return normalized
