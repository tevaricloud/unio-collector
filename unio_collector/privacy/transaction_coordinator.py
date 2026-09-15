from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,EM102,TRY003
import os
import uuid
from contextlib import suppress
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from pathlib import Path
    from typing import BinaryIO


class ArtifactTransactionCoordinator:
    """Reserve destinations and refuse unverifiable abandoned staging."""

    def __init__(self, targets: tuple[Path, ...], *, overwrite: bool) -> None:
        """Create a coordinator without mutating destination directories."""
        self.targets = targets
        self.overwrite = overwrite
        self.transaction_id = uuid.uuid4().hex
        self._locks: list[tuple[Path, BinaryIO]] = []

    def __enter__(self) -> Self:
        """Validate, reserve, and recover the requested target set."""
        self.validate_destinations()
        try:
            for directory in sorted(
                {target.parent.resolve(strict=False) for target in self.targets},
                key=str,
            ):
                directory.mkdir(parents=True, exist_ok=True)
                self._locks.append((directory, self._acquire_directory_lock(directory)))
            self._recover_abandoned_staging()
            self._validate_collisions()
        except Exception:
            self.release()
            raise
        return self

    def __exit__(self, *_exc: object) -> None:
        """Release all destination reservations."""
        self.release()

    def validate_destinations(self) -> None:
        """Validate distinct paths and overwrite policy before staging."""
        resolved = [target.resolve(strict=False) for target in self.targets]
        if len(resolved) != len(set(resolved)):
            raise ValueError("Artifact output paths must be distinct.")
        self._validate_collisions()

    def release(self) -> None:
        """Release directory locks without masking an earlier failure."""
        for _directory, handle in reversed(self._locks):
            with suppress(OSError):
                self._unlock(handle)
            with suppress(OSError):
                handle.close()
        self._locks.clear()

    def _validate_collisions(self) -> None:
        if self.overwrite:
            return
        existing = next((target for target in self.targets if target.exists()), None)
        if existing is not None:
            raise FileExistsError(f"Refusing to overwrite existing artifact: {existing}")

    def _acquire_directory_lock(self, directory: Path) -> BinaryIO:
        lock_path = directory / ".unio-collector-artifact-transaction.lock"
        handle = lock_path.open("a+b")
        try:
            if lock_path.stat().st_size == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            self._lock(handle)
        except (OSError, ValueError):
            handle.close()
            raise RuntimeError(f"Could not reserve artifact destination directory: {directory.name}") from None
        return handle

    def _recover_abandoned_staging(self) -> None:
        suffixes = (
            ".unio-collector-private.tmp",
            ".unio-collector-public.tmp",
            ".unio-collector-protected.tmp",
            ".unio-collector-backup.tmp",
        )
        for target in self.targets:
            prefix = f".{target.name}."
            for candidate in target.parent.iterdir():
                if candidate.name.startswith(prefix) and candidate.name.endswith(suffixes):
                    raise RuntimeError("Artifact destination contains staging with unverifiable ownership; preserve it for recovery.")

    @staticmethod
    def _lock(handle: BinaryIO) -> None:
        if os.name == "nt":
            import msvcrt  # noqa: PLC0415

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return
        import fcntl  # noqa: PLC0415

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def _unlock(handle: BinaryIO) -> None:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt  # noqa: PLC0415

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            return
        import fcntl  # noqa: PLC0415

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
