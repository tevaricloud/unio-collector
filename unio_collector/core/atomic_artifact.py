"""Focused atomic replacement support for report-run artifacts."""

from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


def replace_artifact_atomically(
    path: Path,
    write_temporary: Callable[[Path], object],
) -> None:
    """Write a same-directory temporary artifact and atomically replace ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.stem}.",
        suffix=f".unio-report.tmp{path.suffix}",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    os.close(descriptor)
    try:
        write_temporary(temporary_path)
        with temporary_path.open("rb+") as handle:
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)  # noqa: PTH105
    except BaseException:
        with suppress(OSError):
            temporary_path.unlink(missing_ok=True)
        raise


def write_text_atomically(path: Path, content: str) -> None:
    """Write UTF-8 text through same-directory atomic replacement."""
    replace_artifact_atomically(
        path,
        lambda temporary: temporary.write_text(content, encoding="utf-8"),
    )


def write_bytes_atomically(path: Path, content: bytes) -> None:
    """Write bytes through same-directory atomic replacement."""
    replace_artifact_atomically(path, lambda temporary: temporary.write_bytes(content))
