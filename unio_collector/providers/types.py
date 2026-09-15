from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Iterable

ProviderScopeType = Literal[
    "account",
    "subscription",
    "tenant",
    "organization",
    "management_group",
    "project",
    "folder",
    "domain",
    "unknown",
]
ProviderLocationType = Literal[
    "region",
    "global",
    "tenant",
    "subscription",
    "zone",
    "unknown",
]
ProviderCollectionStatus = Literal[
    "collected",
    "partial",
    "limited",
    "unavailable",
    "unknown",
]
ProviderPillarId = Literal["optimise", "secure", "govern", "automate"]


def normalize_string_tuple(values: Iterable[str] | None) -> tuple[str, ...]:  # noqa: D103
    if values is None:
        return ()
    return tuple(str(value) for value in values)


def normalize_string_pairs(  # noqa: D103
    values: Iterable[tuple[str, str]] | None,
) -> tuple[tuple[str, str], ...]:
    if values is None:
        return ()
    return tuple(sorted((str(key), str(value)) for key, value in values))


def normalize_object_pairs(  # noqa: D103
    values: Iterable[tuple[str, object]] | None,
) -> tuple[tuple[str, object], ...]:
    if values is None:
        return ()
    return tuple(sorted(((str(key), value) for key, value in values), key=lambda item: item[0]))
