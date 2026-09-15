from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class CommandResult:
    """Safe subprocess outcome shown by the launcher."""

    argv: tuple[str, ...]
    exit_code: int
    output: str


__all__ = ["CommandResult"]
