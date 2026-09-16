from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,EM102,TRY003,TRY301
import os
import stat
import tempfile
from contextlib import suppress
from pathlib import Path

from unio_collector.privacy.acl_assessment import (
    WINDOWS_ACL_CONFIRMED_BROAD,
    WINDOWS_ACL_KNOWN_UNSUPPORTED,
    WINDOWS_ACL_REQUIRED_ACCESS_MISSING,
    WindowsAclState,
)
from unio_collector.privacy.content_hash import sha256_bytes
from unio_collector.privacy.owned_file import OwnedArtifactFile
from unio_collector.privacy.prepared_artifact import PreparedArtifact
from unio_collector.privacy.security_warning import SecurityWarning
from unio_collector.privacy.windows_acl import (
    assess_private_windows_acl,
    inspect_private_windows_acl,
    secure_private_windows_acl,
)


class PrivateArtifactWriter:
    """Stage and atomically publish restrictive private files."""

    def prepare(
        self,
        path: Path,
        data: bytes,
        *,
        overwrite: bool,
        artifact: str,
        transaction_id: str | None = None,
    ) -> PreparedArtifact:
        """Write and synchronize a private same-directory temporary file."""
        if path.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing private file: {path}")
        warning_details = list(
            self._preflight_existing_target(
                path,
                overwrite=overwrite,
                artifact=artifact,
            ),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        qualifier = f"{transaction_id}." if transaction_id else ""
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.{qualifier}",
            suffix=".unio-collector-private.tmp",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)
        descriptor_owned = True
        file_identity: tuple[int, int] | None = None
        try:
            metadata = os.fstat(descriptor)
            file_identity = (metadata.st_dev, metadata.st_ino)
            warning_details.extend(
                self._secure_temporary(
                    descriptor,
                    temporary_path,
                    artifact=artifact,
                ),
            )
            handle = os.fdopen(descriptor, "wb", buffering=0)
            descriptor_owned = False
            primary_error: BaseException | None = None
            try:
                offset = 0
                while offset < len(data):
                    written = handle.write(data[offset:])
                    if written is None or written <= 0:
                        raise OSError("Private artifact write made no progress.")
                    offset += written
                handle.flush()
                os.fsync(handle.fileno())
                metadata = os.fstat(handle.fileno())
                file_identity = (metadata.st_dev, metadata.st_ino)
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
            final_warnings = self._inspect_permissions(
                temporary_path,
                artifact=artifact,
            )
            warning_details.extend(final_warnings)
            if os.name == "nt":
                self._raise_for_unsafe_warning_codes(final_warnings, artifact=artifact)
            return PreparedArtifact(
                final_path=path,
                temporary_path=temporary_path,
                artifact=artifact,
                overwrite=overwrite,
                private=True,
                content_hash=sha256_bytes(data),
                warning_details=tuple(warning_details),
                file_identity=file_identity,
            )
        except BaseException:
            if descriptor_owned:
                with suppress(OSError):
                    os.close(descriptor)
            OwnedArtifactFile(temporary_path, file_identity).remove()
            raise

    def _apply_permissions(
        self,
        descriptor: int,
        *,
        artifact: str,
    ) -> tuple[SecurityWarning, ...]:
        try:
            fchmod = getattr(os, "fchmod", None)
            if fchmod is None:
                raise OSError("POSIX mode application is unavailable.")
            fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:
            return (
                SecurityWarning(
                    code="private_artifact.posix_mode_apply_failed",
                    category="permission",
                    artifact=artifact,
                    message=f"Could not apply POSIX mode 0600: {type(exc).__name__}.",
                ),
            )
        return ()

    def _secure_temporary(
        self,
        descriptor: int,
        path: Path,
        *,
        artifact: str,
    ) -> tuple[SecurityWarning, ...]:
        if os.name != "nt":
            return self._apply_permissions(descriptor, artifact=artifact)
        assessment = secure_private_windows_acl(
            descriptor,
            path,
            artifact=artifact,
        )
        self._raise_for_unsafe_windows_acl(assessment.state, artifact=artifact)
        return assessment.warnings

    def _preflight_existing_target(
        self,
        path: Path,
        *,
        overwrite: bool,
        artifact: str,
    ) -> tuple[SecurityWarning, ...]:
        if os.name != "nt" or not overwrite or not path.exists():
            return ()
        assessment = assess_private_windows_acl(path, artifact=artifact)
        self._raise_for_unsafe_windows_acl(assessment.state, artifact=artifact)
        return assessment.warnings

    def _raise_for_unsafe_windows_acl(
        self,
        state: WindowsAclState,
        *,
        artifact: str,
    ) -> None:
        if state in {
            WINDOWS_ACL_CONFIRMED_BROAD,
            WINDOWS_ACL_KNOWN_UNSUPPORTED,
            WINDOWS_ACL_REQUIRED_ACCESS_MISSING,
        }:
            raise PermissionError(
                f"Private artifact ACL policy could not be satisfied: {artifact} ({state}).",
            )

    def _raise_for_unsafe_warning_codes(
        self,
        warnings: tuple[SecurityWarning, ...],
        *,
        artifact: str,
    ) -> None:
        unsafe_codes = {
            "private_artifact.windows_acl_broad",
            "private_artifact.windows_acl_required_access_missing",
            "private_artifact.windows_acl_unsupported",
        }
        if any(warning.code in unsafe_codes for warning in warnings):
            raise PermissionError(
                f"Private artifact ACL policy could not be satisfied: {artifact}.",
            )

    def _inspect_permissions(
        self,
        path: Path,
        *,
        artifact: str,
    ) -> tuple[SecurityWarning, ...]:
        if os.name == "nt":
            return inspect_private_windows_acl(path, artifact=artifact)
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError as exc:
            return (
                SecurityWarning(
                    code="private_artifact.posix_mode_inspection_unavailable",
                    category="permission",
                    artifact=artifact,
                    message=f"POSIX permission inspection was inconclusive: {type(exc).__name__}.",
                ),
            )
        if mode & 0o077:
            return (
                SecurityWarning(
                    code="private_artifact.posix_mode_broad",
                    category="permission",
                    artifact=artifact,
                    message=f"Private artifact has broad POSIX permissions: {oct(mode)}.",
                ),
            )
        return ()
