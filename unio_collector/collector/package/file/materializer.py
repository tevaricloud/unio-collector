from __future__ import annotations  # noqa: D100

import shutil
from typing import TYPE_CHECKING

from unio_collector.collector.package.manifest import build_collector_package_file_plan

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.collector.package.file.plan import CollectorPackageFilePlan


class CollectorPackageSourceMaterializer:
    """Materialize the validated collector source closure into an empty directory."""

    def materialize(
        self,
        *,
        root: Path,
        destination: Path,
        plan: CollectorPackageFilePlan | None = None,
    ) -> tuple[str, ...]:
        """Copy only validated collector source files while preserving paths."""
        root = root.resolve()
        destination = destination.resolve()
        plan = plan or build_collector_package_file_plan(root=root)

        if destination == root or destination.is_relative_to(root):
            msg = "Collector source destination must be outside the repository checkout."
            raise RuntimeError(msg)

        errors = plan.validate()
        if errors:
            msg = "Collector package plan is invalid: " + "; ".join(errors)
            raise RuntimeError(msg)

        if destination.exists():
            if not destination.is_dir():
                msg = f"Collector source destination is not a directory: {destination}"
                raise RuntimeError(msg)
            if any(destination.iterdir()):
                msg = f"Collector source destination must be empty: {destination}"
                raise RuntimeError(msg)
        else:
            destination.mkdir(parents=True)

        copied: list[str] = []
        for relative in plan.source_files:
            source = root / relative
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            copied.append(relative)

        return tuple(copied)
