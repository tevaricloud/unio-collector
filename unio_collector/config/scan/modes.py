from __future__ import annotations  # noqa: D100

from unio_collector.scanners.pillars import normalize_scan_pillars

SCAN_MODE_IDS = ("optimise", "secure", "govern", "automate", "readiness", "full")


def normalize_scan_mode(value: str | None) -> str | None:  # noqa: D103
    if value in (None, ""):
        return None
    normalized = str(value).strip().lower()
    if normalized not in SCAN_MODE_IDS:
        allowed = ", ".join(SCAN_MODE_IDS)
        msg = f"Scan mode must be one of: {allowed}."
        raise ValueError(msg)
    return normalized


def resolve_scan_mode_pillars(scan_mode: str | None) -> tuple[str, ...]:  # noqa: D103
    normalized = normalize_scan_mode(scan_mode)
    if normalized in (None, "full"):
        return ()
    if normalized == "readiness":
        return ("secure", "govern", "automate")
    return normalize_scan_pillars([normalized])
