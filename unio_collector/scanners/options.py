from __future__ import annotations  # noqa: D100


def parse_scanner_option_bool(value: object) -> bool:  # noqa: D103
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    msg = f"Scanner option must be true or false, got {value!r}."
    raise ValueError(msg)


def parse_scanner_option_float(value: object) -> float:  # noqa: D103
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return float(value)
    msg = f"Scanner option must be a number, got {value!r}."
    raise ValueError(msg)


def parse_scanner_option_int(value: object) -> int:  # noqa: D103
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    msg = f"Scanner option must be an integer, got {value!r}."
    raise ValueError(msg)
