"""Inspect bounded artifact ZIPs completely before any extraction."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import PureWindowsPath
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

from tools.collector_repository.paths import relative_path, require, unlinked

if TYPE_CHECKING:
    from pathlib import Path

CONTROL_SPACE = 32
CONTROL_DELETE = 127

MAX_FILES = 12000
MAX_BYTES = 4 * 1024**3


class SafeArtifactArchive:
    """Reject traversal, links, duplicates, bombs and unexpected members."""

    def inspect(self, archive: Path) -> dict[str, str]:
        """Stream every member through CRC and hash validation without extraction."""
        result: dict[str, str] = {}
        with ZipFile(archive) as zipped:
            entries = zipped.infolist()
            require(len(entries) <= MAX_FILES and sum(e.file_size for e in entries) <= MAX_BYTES, "Oversized artifact archive.")
            seen: set[str] = set()
            for entry in entries:
                require(entry.orig_filename == entry.filename and "\\" not in entry.orig_filename, "Non-portable archive filename.")
                name = relative_path(entry.filename)
                require(not PureWindowsPath(name).is_reserved(), "Reserved archive path.")
                require(all(ord(c) >= CONTROL_SPACE and ord(c) != CONTROL_DELETE for c in name), "Control character in archive path.")
                require(name.casefold() not in seen and not entry.is_dir(), "Duplicate/directory artifact member.")
                seen.add(name.casefold())
                mode = entry.external_attr >> 16
                require(stat.S_IFMT(mode) in {0, stat.S_IFREG} and not entry.flag_bits & 1, "Links or encrypted members forbidden.")
                require(entry.file_size <= 512 * 1024**2 and entry.file_size <= max(entry.compress_size, 1) * 500, "Artifact member exceeds limits.")
                digest = hashlib.sha256()
                with zipped.open(entry) as stream:
                    for chunk in iter(lambda: stream.read(1024**2), b""):
                        digest.update(chunk)
                result[name] = digest.hexdigest()
        return result

    def read(self, archive: Path, name: str) -> bytes:
        """Read only bounded structured metadata after inspect succeeds."""
        with ZipFile(archive) as zipped:
            require(zipped.getinfo(name).file_size <= 8 * 1024**2, "Oversized structured evidence.")
            return zipped.read(name)

    def document(self, archive: Path, name: str) -> dict[str, Any]:
        """Reject duplicate JSON keys at every level, including file inventories."""

        def unique(rows: list[tuple[str, Any]]) -> dict[str, Any]:
            """Reject repeated object keys before building a dictionary."""
            result: dict[str, Any] = {}
            for key, value in rows:
                require(key not in result, "Duplicate JSON key.")
                result[key] = value
            return result

        value = json.loads(self.read(archive, name), object_pairs_hook=unique)
        require(isinstance(value, dict), "Expected structured object.")
        return value

    def extract(self, archive: Path, destination: Path, hashes: dict[str, str]) -> None:
        """Recheck the exact inventory before streaming to a fresh unlinked directory."""
        require(self.inspect(archive) == hashes, "Unexpected artifact membership or hash.")
        require(not destination.exists() and not destination.is_symlink(), "Selection destination exists.")
        unlinked(destination)
        destination.mkdir()
        with ZipFile(archive) as zipped:
            for name in hashes:
                path = destination / name
                path.parent.mkdir(parents=True, exist_ok=True)
                with zipped.open(name) as source, path.open("xb") as output:
                    for chunk in iter(lambda: source.read(1024**2), b""):
                        output.write(chunk)
