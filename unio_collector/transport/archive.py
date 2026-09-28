"""Strict transport-container reading and deterministic ZIP metadata."""

from __future__ import annotations

# ruff: noqa: EM101,TRY003
from typing import TYPE_CHECKING
from zipfile import ZIP_STORED, BadZipFile, ZipFile, ZipInfo

from unio_collector.transport.constants import (
    MANIFEST_MEMBER,
    PACKAGE_MEMBERS,
)
from unio_collector.transport.envelope import TransportEnvelope

if TYPE_CHECKING:
    from pathlib import Path


def transport_member(name: str) -> ZipInfo:
    """Return platform-neutral deterministic metadata for one package member."""
    info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o600 << 16
    return info


def read_envelope(path: Path) -> TransportEnvelope:
    """Read a strict two-member transport package manifest."""
    try:
        with ZipFile(path, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(PACKAGE_MEMBERS) or set(names) != PACKAGE_MEMBERS:
                raise ValueError("Transport package has missing or unexpected members.")
            if any(info.is_dir() for info in infos):
                raise ValueError("Transport package contains an unexpected directory member.")
            if any(info.compress_type != ZIP_STORED for info in infos):
                raise ValueError("Transport package members must use stored ZIP encoding.")
            manifest = archive.getinfo(MANIFEST_MEMBER)
            if manifest.file_size > 64 * 1024:
                raise ValueError("Transport envelope manifest is too large.")
            envelope = TransportEnvelope.from_bytes(archive.read(manifest))
            if archive.getinfo(envelope.ciphertext_member).file_size != envelope.payload_size:
                raise ValueError("Transport ciphertext size does not match the envelope.")
            return envelope
    except (BadZipFile, FileNotFoundError) as exc:
        raise ValueError("Transport package is missing, truncated, or unreadable.") from exc


def is_transport_package(path: Path) -> bool:
    """Detect a transport package without treating ordinary bundle ZIPs as envelopes."""
    try:
        with ZipFile(path, "r") as archive:
            return MANIFEST_MEMBER in archive.namelist()
    except (BadZipFile, FileNotFoundError, OSError):
        return path.suffix.casefold() == ".uet"


__all__ = ["is_transport_package", "read_envelope", "transport_member"]
