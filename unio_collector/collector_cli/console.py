from __future__ import annotations  # noqa: D100

import os
import sys
from importlib import import_module
from typing import Any

from unio_collector.collector_cli.rich_console import RichCollectorConsole


def _plain_text(values: tuple[object, ...], sep: str) -> str:
    return sep.join(str(value) for value in values)


class PlainConsole:
    """Small console implementation used when Rich is not installed."""

    def print(
        self,
        *values: object,
        sep: str = " ",
        end: str = "\n",
        **_: object,
    ) -> None:
        """Write values to stdout."""
        sys.stdout.write(sep.join(str(value) for value in values))
        sys.stdout.write(end)

    def success(
        self,
        *values: object,
        sep: str = " ",
        end: str = "\n",
        **_: object,
    ) -> None:
        """Write a success message without markup."""
        self.print(*values, sep=sep, end=end)

    def warning(
        self,
        *values: object,
        sep: str = " ",
        end: str = "\n",
        **_: object,
    ) -> None:
        """Write a warning message without markup."""
        self.print(*values, sep=sep, end=end)

    def error(
        self,
        *values: object,
        sep: str = " ",
        end: str = "\n",
        **_: object,
    ) -> None:
        """Write an error message without markup."""
        self.print(*values, sep=sep, end=end)


def _pop_sep(kwargs: dict[str, object]) -> str:
    value = kwargs.pop("sep", " ")
    return value if isinstance(value, str) else str(value)


def print_success(console: Any, *values: object, **kwargs: object) -> None:  # noqa: ANN401
    """Print a collector success message without embedding markup."""
    writer = getattr(console, "success", None)
    if callable(writer):
        writer(*values, **kwargs)
        return
    console.print(_plain_text(values, _pop_sep(kwargs)), **kwargs)


def print_warning(console: Any, *values: object, **kwargs: object) -> None:  # noqa: ANN401
    """Print a collector warning message without embedding markup."""
    writer = getattr(console, "warning", None)
    if callable(writer):
        writer(*values, **kwargs)
        return
    console.print(_plain_text(values, _pop_sep(kwargs)), **kwargs)


def print_error(console: Any, *values: object, **kwargs: object) -> None:  # noqa: ANN401
    """Print a collector error message without embedding markup."""
    writer = getattr(console, "error", None)
    if callable(writer):
        writer(*values, **kwargs)
        return
    console.print(_plain_text(values, _pop_sep(kwargs)), **kwargs)


def build_console() -> Any:  # noqa: ANN401
    """Return the preferred console without making Rich a hard dependency."""
    try:  # pragma: no cover
        rich_console = import_module("rich.console")
    except Exception:  # pragma: no cover  # noqa: BLE001
        return PlainConsole()
    no_color = os.getenv("NO_COLOR") is not None
    return RichCollectorConsole(rich_console.Console(no_color=no_color))


__all__ = [
    "PlainConsole",
    "build_console",
    "print_error",
    "print_success",
    "print_warning",
]
