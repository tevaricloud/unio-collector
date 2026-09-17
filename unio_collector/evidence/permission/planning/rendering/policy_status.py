from __future__ import annotations  # noqa: D100

from typing import TypedDict


class PolicyRenderingStatus(TypedDict):
    """Deployability of the complete enabled-scanner plan."""

    status: str
    deployable: bool
    unresolved_actions: list[str]


__all__ = ["PolicyRenderingStatus"]
