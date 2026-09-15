from __future__ import annotations  # noqa: D100

from typing import Any


class RichCollectorConsole:
    """Collector-safe Rich wrapper with semantic styling methods."""

    def __init__(self, rich_console: Any) -> None:  # noqa: ANN401
        """Store the wrapped Rich console."""
        self._console = rich_console

    def print(self, *values: object, **kwargs: object) -> None:
        """Delegate ordinary output to Rich without requiring markup."""
        kwargs.setdefault("markup", False)
        self._console.print(*values, **kwargs)

    def success(self, *values: object, **kwargs: object) -> None:
        """Print a success message with style when available."""
        kwargs.setdefault("style", "green")
        kwargs.setdefault("markup", False)
        self._console.print(*values, **kwargs)

    def warning(self, *values: object, **kwargs: object) -> None:
        """Print a warning message with style when available."""
        kwargs.setdefault("style", "yellow")
        kwargs.setdefault("markup", False)
        self._console.print(*values, **kwargs)

    def error(self, *values: object, **kwargs: object) -> None:
        """Print an error message with style when available."""
        kwargs.setdefault("style", "red")
        kwargs.setdefault("markup", False)
        self._console.print(*values, **kwargs)


__all__ = ["RichCollectorConsole"]
