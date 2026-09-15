from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,TRY003
import getpass
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from unio_collector.collector_cli.passphrase_resolution import PassphraseResolution
from unio_collector.privacy.security_warning import SecurityWarning

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import TextIO


class PassphraseResolver:
    """Resolve CLI passphrases at one secret-input boundary."""

    def __init__(
        self,
        *,
        stdin: TextIO | None = None,
        prompt: Callable[[str], str] | None = None,
    ) -> None:
        """Create an injectable resolver for terminal and automation input."""
        self._stdin = stdin or sys.stdin
        self._prompt = prompt or getpass.getpass

    def resolve(  # noqa: C901
        self,
        *,
        required: bool,
        legacy_value: str | None,
        file_path: str | None,
        use_stdin: bool,
        confirm: bool,
        artifact: str,
    ) -> PassphraseResolution:
        """Resolve one mutually exclusive passphrase source."""
        selected = sum(
            (
                legacy_value is not None,
                file_path is not None,
                use_stdin,
            ),
        )
        if selected > 1:
            raise ValueError("Passphrase input options are mutually exclusive.")
        if legacy_value is not None:
            return PassphraseResolution(
                value=self._validate_value(legacy_value),
                warning_details=(
                    SecurityWarning(
                        code="secret_input.argv_exposure",
                        category="security",
                        artifact=artifact,
                        message=(
                            "--passphrase is deprecated because command-line values may be exposed "
                            "through process listings or logs; use --passphrase-file or --passphrase-stdin."
                        ),
                    ),
                ),
            )
        if file_path is not None:
            try:
                value = Path(file_path).read_text(encoding="utf-8")
            except OSError as exc:
                raise ValueError("Could not read the passphrase file.") from exc
            except UnicodeError as exc:
                raise ValueError("The passphrase file must contain valid UTF-8.") from exc
            return PassphraseResolution(value=self._parse_single_line(value))
        if use_stdin:
            if self._is_interactive():
                raise ValueError(
                    "--passphrase-stdin requires redirected standard input; omit it to use the hidden terminal prompt.",
                )
            return PassphraseResolution(value=self._parse_single_line(self._stdin.read()))
        if not required:
            return PassphraseResolution(value=None)
        if not self._is_interactive():
            raise ValueError(
                "A passphrase is required, but no interactive terminal is available. Use --passphrase-file or --passphrase-stdin.",
            )
        value = self._validate_value(self._prompt("Passphrase: "))
        if confirm:
            confirmation = self._validate_value(
                self._prompt("Confirm passphrase: "),
            )
            if value != confirmation:
                raise ValueError("Passphrase confirmation did not match.")
        return PassphraseResolution(value=value)

    def _is_interactive(self) -> bool:
        isatty = getattr(self._stdin, "isatty", None)
        return bool(isatty and isatty())

    def _parse_single_line(self, value: str) -> str:
        if value.endswith("\n"):
            value = value[:-1]
            value = value.removesuffix("\r")
        if "\n" in value or "\r" in value:
            raise ValueError("Passphrase input must contain exactly one line.")
        return self._validate_value(value)

    def _validate_value(self, value: str) -> str:
        if not value:
            raise ValueError("Passphrase input must not be empty.")
        return value
