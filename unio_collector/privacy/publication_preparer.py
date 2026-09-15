from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,TRY003
import base64
import json
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING
from zipfile import ZipFile

from unio_collector.collector.bundle.archive_writer import write_bundle_members
from unio_collector.collector.bundle.encoding import validate_internal_path
from unio_collector.privacy.constants import PRIVACY_POLICY_VERSION
from unio_collector.privacy.content_hash import sha256_file
from unio_collector.privacy.crypto import generate_root_key
from unio_collector.privacy.file_safety import warn_if_private_file_in_transfer_dir
from unio_collector.privacy.owned_file import OwnedArtifactFile
from unio_collector.privacy.prepared_artifact import PreparedArtifact
from unio_collector.privacy.private_artifact_writer import PrivateArtifactWriter
from unio_collector.privacy.security_warning import SecurityWarning
from unio_collector.privacy.vault import VaultWriteInput, encrypt_vault

if TYPE_CHECKING:
    from unio_collector.privacy.options import PrivacyProtectOptions
    from unio_collector.privacy.protection_state import ProtectionState
    from unio_collector.privacy.source_identity import SourceBundleIdentity


class ProtectionArtifactPreparer:
    """Stage the private and transferable artifacts for protected export."""

    def prepare_private_artifacts(
        self,
        options: PrivacyProtectOptions,
        *,
        state: ProtectionState,
        source_identity: SourceBundleIdentity,
        protected_bundle_id: str,
        transaction_id: str,
    ) -> tuple[tuple[PreparedArtifact, ...], tuple[SecurityWarning, ...]]:
        """Stage the vault and optional recovery key with restrictive access."""
        writer = PrivateArtifactWriter()
        artifacts: list[PreparedArtifact] = []
        warning_details: list[SecurityWarning] = []
        recovery_key = state.vault_context.recovery_key
        warning_details.extend(
            self._colocation_warnings(
                private_path=options.vault_path,
                protected_bundle_path=options.output_path,
                artifact="identity_vault",
            ),
        )
        if options.recovery_mode in {"recovery-key", "passphrase-and-key"} and recovery_key is None:
            recovery_key = generate_root_key()
            if options.recovery_key_path is None:
                raise ValueError("Recovery-key mode requires --recovery-key.")
            recovery_artifact = writer.prepare(
                options.recovery_key_path,
                base64.b64encode(recovery_key) + b"\n",
                overwrite=options.overwrite,
                artifact="recovery_key",
                transaction_id=transaction_id,
            )
            artifacts.append(recovery_artifact)
            warning_details.extend(recovery_artifact.warning_details)
            warning_details.extend(
                self._colocation_warnings(
                    private_path=options.recovery_key_path,
                    protected_bundle_path=options.output_path,
                    artifact="recovery_key",
                ),
            )
        elif options.recovery_mode in {"recovery-key", "passphrase-and-key"} and options.recovery_key_path is not None:
            if recovery_key is None:
                raise ValueError("Existing recovery-key material is unavailable.")
            recovery_artifact = writer.prepare(
                options.recovery_key_path,
                base64.b64encode(recovery_key) + b"\n",
                overwrite=options.overwrite,
                artifact="recovery_key",
                transaction_id=transaction_id,
            )
            artifacts.append(recovery_artifact)
            warning_details.extend(recovery_artifact.warning_details)
        try:
            vault_payload = encrypt_vault(
                VaultWriteInput(
                    root_key=state.root_key,
                    plaintext=state.vault_plaintext(),
                    recovery_mode=options.recovery_mode,
                    passphrase=options.passphrase,
                    recovery_key=recovery_key,
                    bundle_id=source_identity.value,
                    protected_bundle_id=protected_bundle_id,
                    engagement_id=options.engagement_id,
                    policy_version=PRIVACY_POLICY_VERSION,
                    token_scope=options.token_scope,
                    bundle_id_scheme=source_identity.scheme,
                    profile_id=state.profile.profile_id,
                    profile_version=state.profile.version,
                    vault_id=state.vault_context.vault_id,
                    revision=state.vault_context.revision,
                    previous_vault_sha256=state.vault_context.previous_vault_sha256,
                    scope_boundary_id=state.vault_context.token_domain.scope_boundary_id,
                ),
            )
            vault_artifact = writer.prepare(
                options.vault_path,
                json.dumps(vault_payload, indent=2, sort_keys=True).encode("utf-8"),
                overwrite=options.overwrite,
                artifact="identity_vault",
                transaction_id=transaction_id,
            )
        except BaseException:
            for artifact in artifacts:
                artifact.cleanup()
            raise
        artifacts.append(vault_artifact)
        warning_details.extend(vault_artifact.warning_details)
        return tuple(artifacts), tuple(warning_details)

    def prepare_protected_archive(
        self,
        options: PrivacyProtectOptions,
        files: dict[str, bytes],
        *,
        transaction_id: str,
    ) -> PreparedArtifact:
        """Stage and validate the protected ZIP in its destination directory."""
        options.output_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{options.output_path.name}.{transaction_id}.",
            suffix=".unio-collector-protected.tmp",
            dir=options.output_path.parent,
        )
        temporary_path = Path(temporary_name)
        file_identity: tuple[int, int] | None = None
        descriptor_owned = True
        try:
            metadata = os.fstat(descriptor)
            file_identity = (metadata.st_dev, metadata.st_ino)
            handle = os.fdopen(descriptor, "w+b")
            descriptor_owned = False
            with handle:
                with ZipFile(handle, "w") as archive:
                    write_bundle_members(archive, files, validate_path=validate_internal_path)
                handle.flush()
                os.fsync(handle.fileno())
            OwnedArtifactFile(temporary_path, file_identity).verify()
        except BaseException:
            if descriptor_owned:
                os.close(descriptor)
            OwnedArtifactFile(temporary_path, file_identity).remove()
            raise
        return PreparedArtifact(
            final_path=options.output_path,
            temporary_path=temporary_path,
            artifact="protected_bundle",
            overwrite=options.overwrite,
            private=False,
            content_hash=sha256_file(temporary_path),
            file_identity=file_identity,
        )

    def _colocation_warnings(
        self,
        *,
        private_path: Path,
        protected_bundle_path: Path,
        artifact: str,
    ) -> tuple[SecurityWarning, ...]:
        return tuple(
            SecurityWarning(
                code=warning.code,
                category=warning.category,
                artifact=artifact,
                message=warning.message,
            )
            for warning in warn_if_private_file_in_transfer_dir(
                private_path=private_path,
                protected_bundle_path=protected_bundle_path,
            )
        )
