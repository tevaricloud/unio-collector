from __future__ import annotations  # noqa: D100

from decimal import Decimal
from typing import Any


def parse_decimal(value: Any) -> Decimal:  # noqa: ANN401, D103
    if value in (None, ""):
        return Decimal(0)
    return Decimal(str(value))
