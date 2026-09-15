from __future__ import annotations  # noqa: D100

import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

if TYPE_CHECKING:
    from collections.abc import Callable

_WINDOWS_REPLACE_ATTEMPTS = 200
_WINDOWS_REPLACE_DELAY_SECONDS = 0.05


def write_bundle_archive(
    path: Path,
    files: dict[str, bytes],
    *,
    validate_path: Callable[[str], None],
    validate_archive: Callable[[Path], None] | None = None,
) -> None:
    """Atomically write deterministic bundle members to a ZIP archive."""
    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(mode="w+b", prefix="unio-collector-bundle-", suffix=".tmp", dir=path.parent, delete=False) as temporary:
            temporary_path = Path(temporary.name)
            with ZipFile(temporary, "w", compression=ZIP_DEFLATED) as archive:
                write_bundle_members(archive, files, validate_path=validate_path)
        if validate_archive is not None:
            validate_archive(temporary_path)
        _replace_with_bounded_retry(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def write_bundle_members(archive: ZipFile, files: dict[str, bytes], *, validate_path: Callable[[str], None]) -> None:
    """Write canonical members through a caller-owned archive handle."""
    for name, data in sorted(files.items()):
        validate_path(name)
        info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.create_system = 3
        info.external_attr = 0o600 << 16
        archive.writestr(info, data)


def _replace_with_bounded_retry(source: Path, target: Path) -> None:
    for attempt in range(_WINDOWS_REPLACE_ATTEMPTS):
        try:
            source.replace(target)
            return  # noqa: TRY300
        except PermissionError:
            if attempt + 1 == _WINDOWS_REPLACE_ATTEMPTS:
                raise
            time.sleep(_WINDOWS_REPLACE_DELAY_SECONDS)
