from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,EM102,TRY003,TRY301
import os
import tempfile
from contextlib import suppress
from pathlib import Path

from unio_collector.privacy.content_hash import sha256_bytes
from unio_collector.privacy.owned_file import OwnedArtifactFile
from unio_collector.privacy.prepared_artifact import PreparedArtifact


class PublicArtifactWriter:
    """Stage a non-secret artifact for atomic publication."""

    def prepare(
        self,
        path: Path,
        data: bytes,
        *,
        overwrite: bool,
        artifact: str,
        transaction_id: str | None = None,
    ) -> PreparedArtifact:
        """Write and synchronize a public same-directory temporary file."""
        if path.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing public file: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        qualifier = f"{transaction_id}." if transaction_id else ""
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.{qualifier}",
            suffix=".unio-collector-public.tmp",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)
        descriptor_owned = True
        file_identity: tuple[int, int] | None = None
        try:
            metadata = os.fstat(descriptor)
            file_identity = (metadata.st_dev, metadata.st_ino)
            handle = os.fdopen(descriptor, "wb", buffering=0)
            descriptor_owned = False
            primary_error: BaseException | None = None
            try:
                offset = 0
                while offset < len(data):
                    written = handle.write(data[offset:])
                    if written is None or written <= 0:
                        raise OSError("Public artifact write made no progress.")
                    offset += written
                handle.flush()
                os.fsync(handle.fileno())
            except BaseException as exc:
                primary_error = exc
                raise
            finally:
                try:
                    handle.close()
                except OSError:
                    if primary_error is None:
                        raise
            OwnedArtifactFile(temporary_path, file_identity).verify()
            return PreparedArtifact(
                final_path=path,
                temporary_path=temporary_path,
                artifact=artifact,
                overwrite=overwrite,
                private=False,
                content_hash=sha256_bytes(data),
                file_identity=file_identity,
            )
        except BaseException:
            if descriptor_owned:
                with suppress(OSError):
                    os.close(descriptor)
            OwnedArtifactFile(temporary_path, file_identity).remove()
            raise
