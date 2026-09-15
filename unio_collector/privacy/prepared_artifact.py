from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.privacy.owned_file import OwnedArtifactFile

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.privacy.security_warning import SecurityWarning


@dataclass
class PreparedArtifact:
    """A fully written same-directory artifact awaiting final publication."""

    final_path: Path
    temporary_path: Path
    artifact: str
    overwrite: bool
    private: bool
    content_hash: str = ""
    warning_details: tuple[SecurityWarning, ...] = ()
    file_identity: tuple[int, int] | None = None

    def cleanup(self) -> None:
        """Remove uncommitted temporary state."""
        OwnedArtifactFile(self.temporary_path, self.file_identity).remove()
