"""Ordered Windows Installer versions, independent of displayed app versions."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

UPGRADE_CODE = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://tevari.co.uk/unio-collector/windows")).upper()
REVISION_STRIDE = 1000
RELEASE_REVISION = 999
MAX_MAJOR_MINOR = 255
MAX_BUILD = 65535


@dataclass(frozen=True)
class WindowsInstallerIdentity:
    """Reserve test revisions below the final release within each app patch."""

    application_version: str
    revision: int
    channel: str = "test"

    def __post_init__(self) -> None:
        """Reject unordered, exhausted or malformed version allocations."""
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.application_version):
            message = "Windows app version must have three numeric fields."
            raise ValueError(message)
        major, minor, patch = map(int, self.application_version.split("."))
        if self.channel not in {"test", "release"} or type(self.revision) is not int:
            message = "Invalid Windows installer channel or revision."
            raise ValueError(message)
        if (self.channel == "test" and not 1 <= self.revision < RELEASE_REVISION) or (self.channel == "release" and self.revision != RELEASE_REVISION):
            message = "Test revisions must be 1..998; release revision must be 999."
            raise ValueError(message)
        if major > MAX_MAJOR_MINOR or minor > MAX_MAJOR_MINOR or patch * REVISION_STRIDE + self.revision > MAX_BUILD:
            message = "Windows installer version allocation exceeds MSI limits."
            raise ValueError(message)

    @property
    def installer_version(self) -> str:
        """Use only MSI's three compared fields; never a fourth-field suffix."""
        major, minor, patch = map(int, self.application_version.split("."))
        return f"{major}.{minor}.{patch * REVISION_STRIDE + self.revision}"

    @classmethod
    def for_repository(cls, root: Path, version: str) -> WindowsInstallerIdentity:
        """Require an explicitly reviewed revision for this application version."""
        payload = json.loads((root / "tools/windows_installer/policy.json").read_text(encoding="utf-8"))
        if (
            set(payload) != {"schema_version", "application_version", "channel", "revision"}
            or payload["schema_version"] != 1
            or payload["application_version"] != version
        ):
            message = "Windows installer policy must match the canonical application version."
            raise ValueError(message)
        return cls(version, payload["revision"], payload["channel"])
