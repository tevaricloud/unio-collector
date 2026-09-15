from __future__ import annotations  # noqa: D100

from typing import Any


def format_count(count: Any, singular: str, plural: str | None = None) -> str:  # noqa: ANN401, D103
    count_text = str(count)
    noun = pluralize(singular, count, plural)
    return f"{count_text} {noun}"


def pluralize(singular: str, count: Any, plural: str | None = None) -> str:  # noqa: ANN401, D103
    if _parse_count_value(count) == 1:
        return singular
    if plural is not None:
        return plural
    if singular.endswith("y") and singular[-2:].lower() not in {
        "ay",
        "ey",
        "iy",
        "oy",
        "uy",
    }:
        return f"{singular[:-1]}ies"
    if singular.endswith(("s", "x", "z", "ch", "sh")):
        return f"{singular}es"
    return f"{singular}s"


def _parse_count_value(count: Any) -> int | None:  # noqa: ANN401
    text = str(count).strip("* ")
    try:
        return int(text)
    except ValueError:
        return None
