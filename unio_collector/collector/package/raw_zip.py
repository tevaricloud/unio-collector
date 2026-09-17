from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING
from zipfile import BadZipFile, ZipFile

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path
    from zipfile import ZipInfo


ZIP_SIGNATURE_LENGTH = 4
LOCAL_FILE_HEADER_SIGNATURE = b"PK\x03\x04"
CENTRAL_FILE_HEADER_SIGNATURE = b"PK\x01\x02"
LOCAL_FILE_HEADER_LENGTH = 30
CENTRAL_FILE_HEADER_LENGTH = 46


def validate_raw_zip_paths(
    path: Path,
    errors: list[str],
    infos: Iterable[ZipInfo] | None = None,
    archive: ZipFile | None = None,
) -> None:
    """Validate ZIP entry names without loading the bundle into memory."""
    try:
        if infos is not None and archive is not None:
            validate_zip_entry_names(_raw_zip_names(path, archive, infos), errors)
            return
        if infos is None:
            with ZipFile(path, "r") as archive:
                collected_infos = archive.infolist()
                validate_zip_entry_names(
                    _raw_zip_names(path, archive, collected_infos),
                    errors,
                )
            return
        with ZipFile(path, "r") as archive:
            validate_zip_entry_names(_raw_zip_names(path, archive, infos), errors)
    except FileNotFoundError:
        return
    except BadZipFile:
        errors.append("Bundle is not a readable ZIP file.")


def validate_zip_entry_names(names: Iterable[str], errors: list[str]) -> None:
    """Validate that ZIP entry names are platform-neutral relative paths."""
    for name in sorted(set(names)):
        if "\\" in name:
            errors.append(f"Bundle path uses Windows separators: {name}")
        if name.startswith("/") or ".." in name.split("/"):
            errors.append(f"Bundle path is not platform-neutral: {name}")


def _raw_zip_names(
    path: Path,
    archive: ZipFile,
    infos: Iterable[ZipInfo],
) -> set[str]:
    names = {info.filename for info in infos}
    names.update(_raw_local_file_names(path, infos))
    names.update(_raw_central_file_names(archive))
    return names


def _raw_local_file_names(path: Path, infos: Iterable[ZipInfo]) -> set[str]:
    names: set[str] = set()
    with path.open("rb") as stream:
        for info in infos:
            stream.seek(info.header_offset)
            header = stream.read(LOCAL_FILE_HEADER_LENGTH)
            if len(header) < LOCAL_FILE_HEADER_LENGTH or not header.startswith(
                LOCAL_FILE_HEADER_SIGNATURE,
            ):
                names.add(info.filename)
                continue
            name_length = int.from_bytes(header[26:28], "little")
            names.add(_decode_name(stream.read(name_length)))
    return names


def _raw_central_file_names(archive: ZipFile) -> set[str]:
    if archive.fp is None:
        return set()
    names: set[str] = set()
    archive.fp.seek(archive.start_dir)
    while True:
        header = archive.fp.read(CENTRAL_FILE_HEADER_LENGTH)
        if len(header) < ZIP_SIGNATURE_LENGTH or not header.startswith(CENTRAL_FILE_HEADER_SIGNATURE):
            break
        if len(header) < CENTRAL_FILE_HEADER_LENGTH:
            names.add("")
            break
        name_length = int.from_bytes(header[28:30], "little")
        extra_length = int.from_bytes(header[30:32], "little")
        comment_length = int.from_bytes(header[32:34], "little")
        names.add(_decode_name(archive.fp.read(name_length)))
        archive.fp.seek(extra_length + comment_length, 1)
    return names


def _decode_name(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")
