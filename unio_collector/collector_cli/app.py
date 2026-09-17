from __future__ import annotations  # noqa: D100

import os
from typing import Any

from botocore.exceptions import ProfileNotFound

from unio_collector.collector_cli.catalogue import find_collector_command
from unio_collector.collector_cli.console import build_console, print_error
from unio_collector.collector_cli.parser import build_parser
from unio_collector.runtime_diagnostics.exception_record import sanitize_diagnostic_text

console: Any = build_console()


def main(argv: list[str] | None = None) -> int:
    """Run the standalone collector CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except Exception as exc:
        if _debug_enabled(args) and not isinstance(exc, ProfileNotFound):
            raise
        print_error(console, f"Error: {_format_error(exc, args)}")
        return 1


def _dispatch(args: object) -> int:
    command = getattr(args, "command", "")
    specification = find_collector_command(str(command))
    if specification is None:
        return 1
    return specification.service_builder(console).run(args)


def _format_error(exc: Exception, args: object) -> str:
    if isinstance(exc, ProfileNotFound):
        requested_profile = getattr(args, "profile", None) or _missing_profile(exc)
        if requested_profile:
            return (
                f"AWS profile '{requested_profile}' could not be found. "
                "--profile selects the local AWS credentials/config profile used "
                "for read-only AWS API calls."
            )
        return "The requested AWS profile could not be found."
    return sanitize_diagnostic_text(exc)


def _missing_profile(exc: ProfileNotFound) -> str | None:
    profile = getattr(exc, "profile", None)
    if profile:
        return str(profile)
    kwargs = getattr(exc, "kwargs", None)
    if isinstance(kwargs, dict) and kwargs.get("profile"):
        return str(kwargs["profile"])
    return None


def _debug_enabled(args: object) -> bool:
    value = os.getenv("UNIO_COLLECTOR_DEBUG", "")
    return bool(getattr(args, "debug", False)) or value.casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }


__all__ = ["console", "main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
