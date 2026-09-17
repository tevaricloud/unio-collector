from __future__ import annotations  # noqa: D100

import tempfile
from pathlib import Path

from unio_collector.collector.bundle.archive_writer import write_bundle_archive
from unio_collector.collector.bundle.encoding import validate_internal_path
from unio_collector.privacy.leak_scan import ProtectedArchiveLeakScanner


def scan_provisional_archive(
    files: dict[str, bytes],
    *,
    known_original_values: set[str],
) -> dict[str, object]:
    """Leak-scan a provisional archive before final metadata is staged."""
    with tempfile.TemporaryDirectory(prefix="unio-collector-privacy-") as temp_dir:
        temp_path = Path(temp_dir) / "protected-bundle.zip"
        write_bundle_archive(
            temp_path,
            files,
            validate_path=validate_internal_path,
            validate_archive=None,
        )
        return (
            ProtectedArchiveLeakScanner()
            .scan_zip_bytes(
                archive_path=temp_path,
                known_original_values=known_original_values,
            )
            .convert_to_dict()
        )
