"""Bounded, deterministic privacy classification diagnostics without values."""

from __future__ import annotations

import logging

MAX_DISPLAYED_UNKNOWN_PATHS = 20


def format_unknown_paths(paths: list[str]) -> str:
    """Summarise distinct paths deterministically; never include field values."""
    unique = sorted(set(paths))
    logging.getLogger(__name__).debug("Unclassified privacy paths: %s", "; ".join(unique))
    details = "; ".join(unique[:MAX_DISPLAYED_UNKNOWN_PATHS])
    return details + (
        f"; {len(unique) - MAX_DISPLAYED_UNKNOWN_PATHS} additional distinct paths (debug diagnostics contain the full list)."
        if len(unique) > MAX_DISPLAYED_UNKNOWN_PATHS
        else ""
    )
