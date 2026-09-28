"""Output-path resolution and collision checks for protected collection."""

from __future__ import annotations

# ruff: noqa: EM101,EM102,TRY003
from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.privacy.receipt import default_receipt_path

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class ProtectedCollectionPaths:
    """Resolved final destinations for a protected collection."""

    protected_bundle: Path
    vault: Path
    recovery_key: Path | None
    receipt: Path
    retained_raw_bundle: Path | None

    def validate(self, *, temporary_root: Path | None, overwrite: bool) -> None:
        """Reject destination collisions, temporary outputs, and overwrites."""
        paths = [self.protected_bundle, self.vault, self.receipt]
        paths.extend(path for path in (self.recovery_key, self.retained_raw_bundle) if path is not None)
        resolved = [path.resolve(strict=False) for path in paths]
        if len(resolved) != len(set(resolved)):
            raise ValueError("Protected workflow output paths must be distinct.")
        if temporary_root is not None:
            root = temporary_root.resolve(strict=False)
            for path in resolved:
                if path == root or root in path.parents:
                    raise ValueError("Final protected workflow outputs cannot be inside temporary storage.")
        if not overwrite:
            existing = [str(path) for path in paths if path.exists() or path.is_symlink()]
            if existing:
                raise FileExistsError(f"Refusing to overwrite existing workflow output: {existing[0]}")


def resolve_protected_collection_paths(
    protected_bundle: Path,
    *,
    vault: Path | None,
    recovery_key: Path | None,
    receipt: Path | None,
    retained_raw_bundle: Path | None,
    recovery_mode: str,
) -> ProtectedCollectionPaths:
    """Derive unmistakable sibling artifact names from the protected bundle."""
    suffix = protected_bundle.suffix or ".zip"
    stem = protected_bundle.name.removesuffix(suffix)
    parent = protected_bundle.parent
    resolved_recovery = recovery_key
    if recovery_mode in {"recovery-key", "passphrase-and-key"} and resolved_recovery is None:
        resolved_recovery = parent / f"{stem}.client-recovery-key.txt"
    return ProtectedCollectionPaths(
        protected_bundle=protected_bundle,
        vault=vault or parent / f"{stem}.client-identity-vault.json",
        recovery_key=resolved_recovery,
        receipt=receipt or default_receipt_path(protected_bundle),
        retained_raw_bundle=retained_raw_bundle,
    )


__all__ = ["ProtectedCollectionPaths", "resolve_protected_collection_paths"]
