"""Admit provider response shapes without manufacturing empty observations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, cast

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


class ProviderResponseError(ValueError):
    """A local evidence limitation with a stable, non-sensitive reason code."""

    def __init__(self, reason: Literal["MalformedEvidence", "CappedEvidence", "RepeatedCursor"] = "MalformedEvidence") -> None:
        """Expose a local reason through the established AWS error-code reader."""
        self.aws_error_code = reason
        super().__init__(reason)


def require_response_mapping(value: object) -> dict[str, Any]:
    """Require an object with provider JSON field names."""
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ProviderResponseError
    return cast("dict[str, Any]", value)


def require_response_rows(response: object, key: str) -> list[dict[str, Any]]:
    """Accept an explicitly empty list, but reject absent or malformed rows."""
    values = require_response_mapping(response).get(key)
    if not isinstance(values, list):
        raise ProviderResponseError
    return [require_response_mapping(value) for value in values]


def iter_response_rows(pages: Iterable[object], key: str) -> Iterator[dict[str, Any]]:
    """Yield admitted rows and require an observed, exhausted final page."""
    last_page: object = None
    for page in pages:
        yield from require_response_rows(page, key)
        last_page = page
    require_complete_response(last_page)


def require_response_strings(response: object, key: str) -> list[str]:
    """Require a complete list of nonempty provider identifiers."""
    values = require_response_mapping(response).get(key)
    if not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values):
        raise ProviderResponseError
    return cast("list[str]", values)


def require_response_bool(value: object) -> bool:
    """Require an observed boolean without truthiness or numeric coercion."""
    if not isinstance(value, bool):
        raise ProviderResponseError
    return value


def require_response_string(value: object) -> str:
    """Require a nonempty observed identifier or provider status."""
    if not isinstance(value, str) or not value:
        raise ProviderResponseError
    return value


def response_cursor(response: object, keys: tuple[str, ...]) -> str | None:
    """Read an optional opaque cursor without coercion or ambiguous aliases."""
    mapping = require_response_mapping(response)
    cursors: set[str] = set()
    for key in keys:
        value = mapping.get(key)
        if value is None or value == "":
            continue
        if not isinstance(value, str):
            raise ProviderResponseError
        cursors.add(value)
    if len(cursors) > 1:
        raise ProviderResponseError
    return next(iter(cursors), None)


def require_complete_response(
    response: object,
    *,
    cursor_keys: tuple[str, ...] = ("NextToken", "nextToken", "NextMarker", "NextContinuationToken"),
    truncated_keys: tuple[str, ...] = ("IsTruncated",),
) -> None:
    """Refuse to label a bounded single response as a complete observation."""
    mapping = require_response_mapping(response)
    cursor = response_cursor(mapping, cursor_keys)
    truncated = False
    for key in truncated_keys:
        if key not in mapping:
            continue
        if not isinstance(mapping[key], bool):
            raise ProviderResponseError
        truncated = truncated or mapping[key]
    if cursor is not None or truncated:
        reason = "CappedEvidence"
        raise ProviderResponseError(reason)
