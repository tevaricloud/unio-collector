from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.config.scan.detail.profile import FULL_SCAN_DETAIL_PROFILE
from unio_collector.config.scan.detail.source import ScanDetailProfileSource


@dataclass(frozen=True)
class ScanDetailProfileSelection:
    """Resolved scan-detail profile and its selection provenance."""

    profile_id: str
    profile_source: ScanDetailProfileSource

    @property
    def explicit_cli_selection(self) -> bool:
        """Return whether the profile was explicitly supplied on the CLI."""
        return self.profile_source is ScanDetailProfileSource.EXPLICIT_CLI

    @property
    def authoritative(self) -> bool:
        """Return whether the profile overrides profile-owned scanner YAML."""
        return self.explicit_cli_selection

    def convert_to_dict(self) -> dict[str, object]:
        """Return a manifest-safe representation."""
        return {
            "profile_id": self.profile_id,
            "profile_source": self.profile_source.value,
            "explicit_cli_selection": self.explicit_cli_selection,
            "authoritative": self.authoritative,
        }


DEFAULT_SCAN_DETAIL_PROFILE_SELECTION = ScanDetailProfileSelection(
    profile_id=FULL_SCAN_DETAIL_PROFILE,
    profile_source=ScanDetailProfileSource.DEFAULT,
)


__all__ = [
    "DEFAULT_SCAN_DETAIL_PROFILE_SELECTION",
    "ScanDetailProfileSelection",
]
