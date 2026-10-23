"""Closed nested scheduled-shutdown metadata emitted by the running EC2 wrapper."""

from __future__ import annotations

import re
from typing import Any

SCHEDULE = "metadata.scheduled_shutdown"
FIELDS: dict[str, tuple[str, str, bool]] = {
    SCHEDULE: ("object", "safe_metadata", True),
    SCHEDULE + ".schedule_tag_key": ("string", "free_text", False),
    SCHEDULE + ".minimum_observation_days": ("count", "safe_metadata", False),
    SCHEDULE + ".minimum_hourly_coverage_percent": ("count", "safe_metadata", False),
    SCHEDULE + ".schedules": ("object", "safe_metadata", False),
    SCHEDULE + ".schedules.<schedule>": ("object", "safe_metadata", False),
    SCHEDULE + ".schedules.<schedule>.timezone": ("string", "free_text", False),
    SCHEDULE + ".schedules.<schedule>.periods": ("array", "safe_metadata", False),
    SCHEDULE + ".schedules.<schedule>.periods[]": ("object", "safe_metadata", False),
    SCHEDULE + ".schedules.<schedule>.periods[].days": ("array", "safe_metadata", False),
    SCHEDULE + ".schedules.<schedule>.periods[].days[]": ("day", "safe_metadata", False),
    SCHEDULE + ".schedules.<schedule>.periods[].start": ("clock", "free_text", False),
    SCHEDULE + ".schedules.<schedule>.periods[].stop": ("clock", "free_text", False),
}


class ShutdownPrivacySchema:
    """Bind one explicit dynamic schedule-ID map to a closed period schema."""

    @staticmethod
    def canonical(suffix: str, keys: frozenset[str]) -> str:
        """Use the admitted record's complete keys, preserving punctuation in IDs."""
        prefix = SCHEDULE + ".schedules."
        for key in sorted(keys, key=len, reverse=True):
            if suffix == prefix + key or suffix.startswith(prefix + key + "."):
                return prefix + "<schedule>" + suffix[len(prefix + key) :]
        return suffix

    @staticmethod
    def validate(value: Any, member: str, suffix: str = SCHEDULE) -> list[str]:  # noqa: ANN401
        """Walk one closed schema cursor; IDs are data, never parsed field syntax."""
        path = member + ".scanner_evidence[].payload." + suffix
        if value is None and suffix == SCHEDULE:
            return []
        spec = FIELDS.get(suffix)
        if spec is None or not ShutdownPrivacySchema._valid(value, spec[0], suffix):
            return [path]
        if isinstance(value, dict):
            return ShutdownPrivacySchema._mapping(value, member, suffix, path)
        if isinstance(value, list):
            return [failure for child in value for failure in ShutdownPrivacySchema.validate(child, member, suffix + "[]")]
        return []

    @staticmethod
    def _valid(value: object, kind: str, suffix: str) -> bool:
        if kind == "object":
            return isinstance(value, dict)
        if kind == "array":
            return isinstance(value, list) and bool(value)
        if kind == "day":
            return isinstance(value, str) and value.strip().lower() in {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
        if kind == "clock":
            return isinstance(value, str) and re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value) is not None
        if kind == "count":
            maximum = 366 if suffix.endswith("minimum_observation_days") else 100
            return type(value) is int and 1 <= value <= maximum
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _mapping(value: dict[str, Any], member: str, suffix: str, path: str) -> list[str]:
        if suffix == SCHEDULE and not value:
            return []
        required = (
            {"schedule_tag_key", "schedules"}
            if suffix == SCHEDULE
            else {"timezone", "periods"}
            if suffix.endswith(".<schedule>")
            else {"days", "start", "stop"}
            if suffix.endswith(".periods[]")
            else set()
        )
        if not required <= set(value):
            return [path]
        if suffix == SCHEDULE + ".schedules":
            if not value or any(not isinstance(key, str) or not key.strip() for key in value):
                return [path]
            return [failure for child in value.values() for failure in ShutdownPrivacySchema.validate(child, member, suffix + ".<schedule>")]
        return [failure for key, child in value.items() for failure in ShutdownPrivacySchema.validate(child, member, suffix + "." + key)]
