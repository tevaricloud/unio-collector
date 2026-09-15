"""Complete public-tree naming admission, independent of private source policy."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tools.collector_repository.paths import regular_file, repository_files, require, unlinked

if TYPE_CHECKING:
    from pathlib import Path

TRANSFORMATION_VERSION = "2026-09-unio-publication-v2"

LEGACY_NAME = bytes.fromhex("636c6f7564636f7374").decode("ascii")
_BINARY_SIGNATURES = (b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"%PDF-", b"PK\x03\x04", b"MZ", b"\x7fELF", b"wOFF", b"wOF2")
_TEXT_SUFFIXES = frozenset({".py", ".pyi", ".md", ".json", ".toml", ".yml", ".yaml", ".txt", ".lock"})


def repository_text(path: Path) -> str | None:
    """Decode supported text; recognise binary assets before attempting decoding."""
    content = path.read_bytes()
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        return content.decode("utf-16")
    if path.suffix.casefold() not in _TEXT_SUFFIXES and content.startswith(_BINARY_SIGNATURES):
        return None
    if b"\0" in content:
        require(path.suffix.casefold() not in _TEXT_SUFFIXES, f"Binary bytes in repository text: {path.name}.")
        return None
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        require(path.suffix.casefold() not in _TEXT_SUFFIXES, f"Unsupported repository text encoding: {path.name}.")
        return None


class PublicNamingValidator:
    """Reject legacy branding in every public path and supported text asset."""

    def validate(self, root: Path) -> None:
        """Report only the offending relative path, never its file contents."""
        names = repository_files(root)
        for path in root.rglob("*"):
            name = path.relative_to(root).as_posix()
            if name == ".git" or name.startswith(".git/"):
                continue
            unlinked(path, boundary=root)
            require(LEGACY_NAME not in name.casefold(), f"Legacy public name in path: {name}.")
        for name in names:
            path = regular_file(root, name)
            text = repository_text(path)
            require(text is None or LEGACY_NAME not in text.casefold(), f"Legacy public name in text: {name}.")
            if text is None:
                require(LEGACY_NAME.encode("ascii") not in path.read_bytes().lower(), f"Legacy public name in binary bytes: {name}.")
