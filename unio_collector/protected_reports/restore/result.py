from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.privacy.security_warning import SecurityWarning


@dataclass(frozen=True)
class ProtectedReportRestoreResult:
    """Summary of local report restoration outputs."""

    output_dir: Path
    restored_json_path: Path
    markdown_path: Path
    html_path: Path
    audit_path: Path
    completion_path: Path
    audit: dict[str, object]
    warnings: tuple[str, ...] = ()
    warning_details: tuple[SecurityWarning, ...] = ()
    artifact_paths: tuple[Path, ...] = ()
