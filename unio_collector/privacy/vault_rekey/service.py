from __future__ import annotations  # noqa: D100

# ruff: noqa: C901,EM101,TC003,TRY003,TRY301
import base64
import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from unio_collector.collector.protocol import DEFAULT_PROTOCOL, EvidenceProtocol
from unio_collector.privacy.admission.vault import VaultSource
from unio_collector.privacy.artifact_transaction import ArtifactTransaction
from unio_collector.privacy.crypto import generate_root_key
from unio_collector.privacy.private_artifact_writer import PrivateArtifactWriter
from unio_collector.privacy.transaction_coordinator import ArtifactTransactionCoordinator
from unio_collector.privacy.vault import VaultWriteInput, encrypt_vault, unlock_vault
from unio_collector.privacy.vault_rekey.result import VaultRekeyResult

if TYPE_CHECKING:
    from unio_collector.privacy.vault_rekey.options import VaultRekeyOptions


class VaultRekeyer:
    """Rotate vault wrapping material while retaining the client root key."""

    def rekey(self, options: VaultRekeyOptions) -> VaultRekeyResult:
        """Write an authenticated next vault revision atomically."""
        same_path = options.vault_path.resolve(strict=False) == options.output_vault_path.resolve(strict=False)
        if same_path != options.in_place:
            raise ValueError("In-place rekey requires matching vault paths and explicit opt-in.")
        source = VaultSource.read(options.vault_path)
        payload = source.payload
        old_key = self._read_key(options.old_recovery_key_path)
        unlocked = unlock_vault(payload, passphrase=options.old_passphrase, recovery_key=old_key)
        metadata = unlocked.metadata
        if EvidenceProtocol.from_identifier(metadata.get("format"), ("vault-v1", "vault-v2")) != DEFAULT_PROTOCOL:
            raise ValueError("Vault rekey cannot migrate evidence protocol families.")
        boundary = unlocked.plaintext.get("scope_boundary_id", metadata.get("engagement_id"))
        if not isinstance(boundary, str) or not boundary:
            raise ValueError("Vault scope boundary is missing or invalid.")
        new_key = None
        if options.new_recovery_mode in {"recovery-key", "passphrase-and-key"}:
            if options.new_recovery_key_path is None:
                raise ValueError("New recovery mode requires --new-recovery-key.")
            new_key = generate_root_key()
        revision_value = metadata.get("revision")
        revision = revision_value + 1 if isinstance(revision_value, int) and revision_value > 0 else 2
        vault_id = metadata.get("vault_id")
        if not isinstance(vault_id, str) or not vault_id:
            vault_id = str(uuid.uuid4())
        plaintext = dict(unlocked.plaintext)
        plaintext["vault_id"] = vault_id
        plaintext["revision"] = revision
        encrypted = encrypt_vault(
            VaultWriteInput(
                root_key=unlocked.root_key,
                plaintext=plaintext,
                recovery_mode=options.new_recovery_mode,
                passphrase=options.new_passphrase,
                recovery_key=new_key,
                bundle_id=str(metadata.get("bundle_id") or "legacy-source"),
                protected_bundle_id=str(metadata.get("protected_bundle_id") or "legacy-protected"),
                engagement_id=str(metadata.get("engagement_id") or "legacy-engagement"),
                policy_version=str(metadata.get("policy_version") or "2026-03"),
                token_scope=str(metadata.get("token_scope") or "engagement"),
                bundle_id_scheme=(str(metadata["bundle_id_scheme"]) if metadata.get("bundle_id_scheme") else None),
                profile_id=(str(metadata["profile_id"]) if metadata.get("profile_id") else None),
                profile_version=(str(metadata["profile_version"]) if metadata.get("profile_version") else None),
                vault_id=vault_id,
                revision=revision,
                previous_vault_sha256=source.sha256,
                scope_boundary_id=boundary,
            ),
        )
        targets = [options.output_vault_path]
        if options.new_recovery_key_path is not None:
            targets.append(options.new_recovery_key_path)
        coordinator = ArtifactTransactionCoordinator(
            tuple(targets),
            overwrite=options.overwrite or options.in_place,
        )
        coordinator.validate_destinations()
        writer = PrivateArtifactWriter()
        artifacts = []
        with coordinator:
            try:
                vault_artifact = writer.prepare(
                    options.output_vault_path,
                    (json.dumps(encrypted, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                    overwrite=options.overwrite or options.in_place,
                    artifact="identity_vault",
                    transaction_id=coordinator.transaction_id,
                )
                artifacts.append(vault_artifact)
                if options.new_recovery_key_path is not None and new_key is not None:
                    artifacts.append(
                        writer.prepare(
                            options.new_recovery_key_path,
                            base64.b64encode(new_key) + b"\n",
                            overwrite=options.overwrite,
                            artifact="recovery_key",
                            transaction_id=coordinator.transaction_id,
                        ),
                    )
                verified_key = new_key if options.new_recovery_mode != "passphrase" else None
                verified = unlock_vault(encrypted, passphrase=options.new_passphrase, recovery_key=verified_key)
                if verified.root_key != unlocked.root_key or verified.plaintext != plaintext:
                    raise ValueError("Rekeyed vault verification failed.")
                ArtifactTransaction(tuple(artifacts)).commit()
            except BaseException:
                for artifact in artifacts:
                    artifact.cleanup()
                raise
        return VaultRekeyResult(options.output_vault_path, options.new_recovery_key_path)

    def _read_key(self, path: Path | None) -> bytes | None:
        if path is None:
            return None
        try:
            return base64.b64decode(path.read_text(encoding="utf-8").strip(), validate=True)
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValueError("Recovery key could not be read.") from exc
