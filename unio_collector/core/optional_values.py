from __future__ import annotations  # noqa: D100

from typing import Any


def optional_string(value: Any) -> str | None:  # noqa: ANN401, D103
    if value in (None, ""):
        return None
    return str(value)


__all__ = ["optional_string"]
