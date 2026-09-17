from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,EM102,TRY003,TRY301
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.privacy.prepared_artifact import PreparedArtifact

from unio_collector.privacy.content_hash import sha256_file
from unio_collector.privacy.owned_file import OwnedArtifactFile


class ArtifactTransaction:
    """Publish a staged artifact set with in-process rollback."""

    def __init__(self, artifacts: tuple[PreparedArtifact, ...]) -> None:
        """Create a transaction in caller-defined commit order."""
        self._artifacts = artifacts

    def commit(self) -> None:
        """Commit all staged artifacts and restore prior files on failure."""
        backups: dict[Path, OwnedArtifactFile] = {}
        committed: list[PreparedArtifact] = []
        try:
            self._validate_targets()
            for artifact in self._artifacts:
                OwnedArtifactFile(artifact.temporary_path, artifact.file_identity).verify()
                if artifact.content_hash and sha256_file(artifact.temporary_path) != artifact.content_hash:
                    raise OSError(f"Staged artifact hash verification failed: {artifact.artifact}")
                final_path = artifact.final_path
                if final_path.exists() or final_path.is_symlink():
                    if not artifact.overwrite:
                        raise FileExistsError(
                            f"Refusing to overwrite existing artifact: {final_path}",
                        )
                    original_identity = self._file_identity(final_path)
                    reservation = self._reserve_backup_path(final_path)
                    try:
                        reservation.verify()
                        final_path.replace(reservation.path)
                    except BaseException:
                        reservation.remove()
                        raise
                    backups[final_path] = OwnedArtifactFile(reservation.path, original_identity)
                    self._verify_file_identity(
                        reservation.path,
                        original_identity,
                        artifact=f"{artifact.artifact}_backup",
                    )
                committed.append(artifact)
                self._publish(artifact)
                self._sync_directory(final_path.parent)
                if artifact.file_identity is not None:
                    self._verify_file_identity(
                        final_path,
                        artifact.file_identity,
                        artifact=artifact.artifact,
                    )
                self._verify_published_hash(artifact)
        except BaseException as exc:
            rollback_errors = self._rollback(committed, backups)
            try:
                self._cleanup_temporaries()
            except OSError:
                rollback_errors.add("temporary staging")
            if rollback_errors:
                names = ", ".join(sorted(rollback_errors))
                raise RuntimeError(
                    f"Artifact publication failed and rollback was incomplete for: {names}",
                ) from exc
            raise
        self._cleanup_backups(backups)
        self._cleanup_temporaries()

    def abort(self) -> None:
        """Remove all uncommitted staged files."""
        self._cleanup_temporaries()

    def _validate_targets(self) -> None:
        resolved = [artifact.final_path.resolve(strict=False) for artifact in self._artifacts]
        if len(resolved) != len(set(resolved)):
            raise ValueError("Artifact output paths must be distinct.")

    def _publish(self, artifact: PreparedArtifact) -> None:
        OwnedArtifactFile(artifact.temporary_path, artifact.file_identity).verify()
        try:
            os.link(artifact.temporary_path, artifact.final_path)
        except OSError as exc:
            raise OSError(
                f"Could not atomically create artifact without overwrite: {artifact.final_path.name}",
            ) from exc
        artifact.cleanup()

    def _verify_published_hash(self, artifact: PreparedArtifact) -> None:
        if artifact.content_hash and sha256_file(artifact.final_path) != artifact.content_hash:
            raise OSError(f"Published artifact hash verification failed: {artifact.artifact}")

    def _verify_file_identity(
        self,
        path: Path,
        expected: tuple[int, int],
        *,
        artifact: str,
    ) -> None:
        if self._file_identity(path) != expected:
            raise OSError(f"Published artifact identity verification failed: {artifact}")

    def _file_identity(self, path: Path) -> tuple[int, int]:
        return OwnedArtifactFile.identity_at(path)

    def _rollback(
        self,
        committed: list[PreparedArtifact],
        backups: dict[Path, OwnedArtifactFile],
    ) -> set[str]:
        errors: set[str] = set()
        for artifact in reversed(committed):
            try:
                OwnedArtifactFile(artifact.final_path, artifact.file_identity).remove()
            except OSError:
                errors.add(artifact.artifact)
        for final_path, backup in reversed(tuple(backups.items())):
            try:
                backup.verify()
                os.link(backup.path, final_path)
                backup.remove()
                self._sync_directory(final_path.parent)
            except OSError:
                errors.add(final_path.name)
        return errors

    def _reserve_backup_path(self, path: Path) -> OwnedArtifactFile:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".unio-collector-backup.tmp",
            dir=path.parent,
        )
        try:
            metadata = os.fstat(descriptor)
            return OwnedArtifactFile(Path(name), (metadata.st_dev, metadata.st_ino))
        finally:
            os.close(descriptor)

    def _cleanup_backups(self, backups: dict[Path, OwnedArtifactFile]) -> None:
        for backup in backups.values():
            backup.remove()

    def _cleanup_temporaries(self) -> None:
        failed = False
        for artifact in self._artifacts:
            try:
                artifact.cleanup()
            except OSError:
                failed = True
        if failed:
            raise OSError("Artifact temporary cleanup could not verify ownership.")

    def _sync_directory(self, path: Path) -> None:
        if os.name == "nt":
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
