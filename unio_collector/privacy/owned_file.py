"""Identity checks for files created or reserved by a privacy transaction."""

from __future__ import annotations

import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class OwnedArtifactFile:
    """A path bound to the regular file the transaction actually owns."""

    path: Path
    identity: tuple[int, int] | None

    @staticmethod
    def identity_at(path: Path) -> tuple[int, int]:
        """Read identity without following links or reparse points."""
        metadata = path.lstat()
        reparse = getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if not stat.S_ISREG(metadata.st_mode) or reparse:
            message = "Artifact path is not a regular owned file."
            raise OSError(message)
        return metadata.st_dev, metadata.st_ino

    def verify(self) -> None:
        """Refuse a missing identity or an unexpected path replacement."""
        actual = self.identity_at(self.path)
        if self.identity is None or actual != self.identity:
            message = "Artifact file identity verification failed."
            raise OSError(message)

    def remove(self) -> None:
        """Remove only the expected file, allowing already absent staging."""
        try:
            self.verify()
        except FileNotFoundError:
            return
        self.path.unlink()
