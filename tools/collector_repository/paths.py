"""Strict filesystem boundaries for standalone repository operations."""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath


def require(condition: bool, message: str) -> None:  # noqa: FBT001
    """Fail closed with a bounded diagnostic."""
    if not condition:
        raise ValueError(message)


def relative_path(value: str) -> str:
    """Accept only portable, non-ambiguous relative file paths."""
    path = PurePosixPath(value)
    require(bool(value) and not path.is_absolute() and str(path) == value, "Invalid repository-relative path.")
    require(not any(part in {"", ".", ".."} or part.endswith((".", " ")) for part in path.parts), "Unsafe repository path segment.")
    require(not any(char in value for char in '\\:*?[]<>|"\x00'), "Non-portable repository path.")
    require(
        all(part.casefold() not in {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(10)), *(f"lpt{i}" for i in range(10))} for part in path.parts),
        "Reserved repository path.",
    )
    return value


def unlinked(path: Path, *, boundary: Path | None = None, include_boundary: bool = True) -> None:
    """Reject links and reparse points inside a trusted lexical boundary."""
    path = path.absolute()
    boundary = boundary.absolute() if boundary is not None else Path(path.anchor)

    require(
        path == boundary or path.is_relative_to(boundary),
        "Repository path escaped its trusted filesystem boundary.",
    )

    candidates: list[Path] = []
    candidate = path
    while candidate != boundary:
        candidates.append(candidate)
        candidate = candidate.parent
    if include_boundary:
        candidates.append(boundary)

    for candidate in candidates:
        if not candidate.exists() and not candidate.is_symlink():
            continue
        metadata = candidate.lstat()
        require(
            not candidate.is_symlink() and not int(getattr(metadata, "st_file_attributes", 0)) & 0x400,
            "Repository paths must not traverse links or reparse points.",
        )


def regular_file(root: Path, name: str) -> Path:
    """Resolve an unlinked regular file within a repository."""
    path = root / relative_path(name)
    unlinked(path, boundary=root)
    require(path.resolve().is_relative_to(root.resolve()), "File escaped repository boundary.")
    require(path.is_file() and stat.S_ISREG(path.stat().st_mode), f"Missing regular repository file: {name}.")
    return path


def external_output(root: Path, output: Path, *, empty: bool = False) -> Path:
    """Validate an absolute external output without creating or deleting it."""
    require(output.is_absolute(), "Output must be an absolute external path.")
    root_absolute = root.absolute()
    output_absolute = output.absolute()
    try:
        shared_boundary = Path(os.path.commonpath((root_absolute, output_absolute)))
    except ValueError:
        shared_boundary = Path(output_absolute.anchor)
    unlinked(output_absolute, boundary=shared_boundary, include_boundary=False)
    resolved = output.resolve()
    require(
        not resolved.is_relative_to(root.resolve()) and not root.resolve().is_relative_to(resolved),
        "Output must be outside and must not contain the source checkout.",
    )
    if output.exists():
        require(output.is_dir(), "Output must be a directory.")
        if empty:
            require(not any(output.iterdir()), "Output destination must be empty.")
    return resolved


def repository_files(root: Path) -> tuple[str, ...]:
    """Enumerate exact regular payload files, excluding only root Git metadata."""
    unlinked(root, boundary=root)
    names: list[str] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for child in directory.iterdir():
            if directory == root and child.name == ".git":
                continue
            unlinked(child, boundary=root)
            if child.is_dir():
                pending.append(child)
            else:
                name = child.relative_to(root).as_posix()
                regular_file(root, name)
                names.append(name)
    require(len({name.casefold() for name in names}) == len(names), "Case-colliding repository paths.")
    return tuple(sorted(names))
