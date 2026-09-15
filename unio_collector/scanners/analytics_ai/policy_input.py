"""Parse explicit numeric inputs without supplying application policy defaults."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scanners.scanner.context import ScannerContext


def read_analytics_policy_input[T: (int, float)](context: ScannerContext, key: str, parser: Callable[[object], T]) -> T | None:
    """Keep absent input distinct from an explicitly malformed configuration."""
    absent = object()
    value = context.options.get_for_scanner(context.definition.scanner_id, key, absent)
    if value is absent:
        return None
    parsed = parser(value)
    if isinstance(parsed, float) and not math.isfinite(parsed):
        msg = "Analytics numeric configuration must be finite."
        raise ValueError(msg)
    return parsed
