from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.privacy.security_warning import SecurityWarning


@dataclass(frozen=True)
class PassphraseResolution:
    """Resolved secret plus non-secret input warnings."""

    value: str | None
    warning_details: tuple[SecurityWarning, ...] = ()
