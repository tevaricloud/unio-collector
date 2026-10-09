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
    generated_tokens: frozenset[str] = frozenset(),
    require_passed: bool = False,
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
        result = ProtectedArchiveLeakScanner().scan_zip_bytes(
            archive_path=temp_path,
            known_original_values=known_original_values,
            generated_tokens=generated_tokens,
        )
        if require_passed and not result.passed:
            findings = ", ".join(f"{finding.path}:{finding.category}" for finding in result.findings[:10])
            message = f"Protected archive provisional leak scan failed: {findings}"
            raise ValueError(message)
        return result.convert_to_dict()
