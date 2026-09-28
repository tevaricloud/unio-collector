"""Transactional publication for integrated protected-collection artifacts."""

from __future__ import annotations

import uuid
from contextlib import suppress
from typing import TYPE_CHECKING

from unio_collector.privacy.artifact_transaction import ArtifactTransaction
from unio_collector.privacy.private_artifact_writer import PrivateArtifactWriter
from unio_collector.privacy.public_writer import PublicArtifactWriter

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.collector.protected_workflow.paths import ProtectedCollectionPaths
    from unio_collector.privacy.prepared_artifact import PreparedArtifact


class ProtectedCollectionArtifactPublisher:
    """Stage and transactionally publish the complete approved artifact set."""

    def stage_paths(
        self,
        paths: ProtectedCollectionPaths,
        workspace: Path,
    ) -> tuple[Path, Path, Path, Path]:
        """Return collision-resistant protection targets inside the workspace."""
        token = uuid.uuid4().hex

        def staged(path: Path, role: str) -> Path:
            return workspace / f"{token}.{role}{path.suffix}"

        recovery_reference = paths.recovery_key or paths.vault
        return (
            staged(paths.protected_bundle, "protected"),
            staged(paths.vault, "vault"),
            staged(recovery_reference, "recovery"),
            staged(paths.receipt, "receipt"),
        )

    def publish(
        self,
        *,
        paths: ProtectedCollectionPaths,
        stage_paths: tuple[Path, ...],
        raw_bundle: Path,
        overwrite: bool,
    ) -> None:
        """Prepare final-directory artifacts and commit them as one transaction."""
        artifacts = self._prepare(
            paths=paths,
            stage_paths=stage_paths,
            raw_bundle=raw_bundle,
            overwrite=overwrite,
        )
        ArtifactTransaction(artifacts).commit()

    def cleanup(self, paths: tuple[Path, ...]) -> None:
        """Best-effort remove only exact generated workspace stage paths."""
        for path in paths:
            with suppress(OSError):
                if path.is_file() and not path.is_symlink():
                    path.unlink()

    def _prepare(
        self,
        *,
        paths: ProtectedCollectionPaths,
        stage_paths: tuple[Path, ...],
        raw_bundle: Path,
        overwrite: bool,
    ) -> tuple[PreparedArtifact, ...]:
        protected, vault, recovery, receipt = stage_paths
        artifacts: list[PreparedArtifact] = []
        try:
            artifacts.append(
                PrivateArtifactWriter().prepare(
                    paths.vault,
                    vault.read_bytes(),
                    overwrite=overwrite,
                    artifact="identity_vault",
                )
            )
            if paths.recovery_key is not None:
                artifacts.append(
                    PrivateArtifactWriter().prepare(
                        paths.recovery_key,
                        recovery.read_bytes(),
                        overwrite=overwrite,
                        artifact="recovery_key",
                    ),
                )
            if paths.retained_raw_bundle is not None:
                artifacts.append(
                    PrivateArtifactWriter().prepare(
                        paths.retained_raw_bundle,
                        raw_bundle.read_bytes(),
                        overwrite=overwrite,
                        artifact="retained_raw_bundle",
                    ),
                )
            artifacts.extend(
                (
                    PublicArtifactWriter().prepare(
                        paths.receipt,
                        receipt.read_bytes(),
                        overwrite=overwrite,
                        artifact="completion_receipt",
                    ),
                    PublicArtifactWriter().prepare(
                        paths.protected_bundle,
                        protected.read_bytes(),
                        overwrite=overwrite,
                        artifact="protected_bundle",
                    ),
                )
            )
        except BaseException:
            for artifact in artifacts:
                artifact.cleanup()
            raise
        return tuple(artifacts)


__all__ = ["ProtectedCollectionArtifactPublisher"]
