from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.privacy.security_warning import SecurityWarning

if TYPE_CHECKING:
    from pathlib import Path


def warn_if_private_file_in_transfer_dir(
    *,
    private_path: Path,
    protected_bundle_path: Path,
) -> tuple[SecurityWarning, ...]:
    """Warn if private material is being written beside the transfer bundle."""
    try:
        if private_path.parent.resolve() == protected_bundle_path.parent.resolve():
            return (
                SecurityWarning(
                    code="private_artifact.transfer_colocation",
                    category="security",
                    artifact="private_material",
                    message=("Private material is in the protected bundle output directory; keep vault and recovery material out of transfer folders."),
                ),
            )
    except OSError:
        return ()
    return ()
