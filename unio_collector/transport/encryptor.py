"""Streaming recipient encryption for transferable evidence archives."""

from __future__ import annotations

# ruff: noqa: EM101,TRY003
import hashlib
import os
import secrets
import tempfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from zipfile import ZipFile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from unio_collector.transport.archive import transport_member
from unio_collector.transport.constants import (
    CHUNK_BYTES,
    CIPHERTEXT_MEMBER,
    CONTENT_KEY_BYTES,
    KEY_WRAP_LABEL,
    MANIFEST_MEMBER,
    MAX_PAYLOAD_BYTES,
    NONCE_BYTES,
)
from unio_collector.transport.envelope import (
    TransportEnvelope,
    validate_recipient_key_id,
)
from unio_collector.transport.public_key import load_public_key

if TYPE_CHECKING:
    from collections.abc import Callable


class TransportPackageEncryptor:
    """Wrap an evidence-bundle ZIP for one recipient without changing it."""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        """Create an encryptor with an injectable UTC clock."""
        self._clock = clock or (lambda: datetime.now(UTC))

    def encrypt(
        self,
        *,
        bundle_path: Path,
        output_path: Path,
        recipient_public_key_path: Path,
        recipient_key_id: str,
        overwrite: bool = False,
    ) -> TransportEnvelope:
        """Encrypt one evidence archive into an atomically published package."""
        self._validate_paths(bundle_path, output_path, overwrite=overwrite)
        validate_recipient_key_id(recipient_key_id)
        public_key = load_public_key(recipient_public_key_path)
        content_key = secrets.token_bytes(CONTENT_KEY_BYTES)
        nonce = secrets.token_bytes(NONCE_BYTES)
        wrapped_key = public_key.encrypt(
            content_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=KEY_WRAP_LABEL,
            ),
        )
        created_at = self._clock().astimezone(UTC).isoformat().replace("+00:00", "Z")
        envelope = TransportEnvelope.create(
            recipient_key_id=recipient_key_id,
            created_at=created_at,
            payload_size=bundle_path.stat().st_size,
            nonce=nonce,
            wrapped_content_key=wrapped_key,
        )
        temporary = self._temporary_path(output_path)
        try:
            envelope = self._write_package(
                bundle_path=bundle_path,
                output_path=temporary,
                content_key=content_key,
                envelope=envelope,
            )
            if output_path.exists() and not overwrite:
                raise FileExistsError("Encrypted transport output already exists.")
            temporary.replace(output_path)
        finally:
            temporary.unlink(missing_ok=True)
        return envelope

    def _write_package(
        self,
        *,
        bundle_path: Path,
        output_path: Path,
        content_key: bytes,
        envelope: TransportEnvelope,
    ) -> TransportEnvelope:
        encryptor = Cipher(
            algorithms.AES(content_key),
            modes.GCM(envelope.decode_nonce()),
        ).encryptor()
        encryptor.authenticate_additional_data(envelope.authenticated_metadata())
        ciphertext_digest = hashlib.sha256()
        with ZipFile(output_path, "w") as archive:
            with (
                bundle_path.open("rb") as source,
                archive.open(
                    transport_member(CIPHERTEXT_MEMBER),
                    "w",
                ) as target,
            ):
                while chunk := source.read(CHUNK_BYTES):
                    encrypted = encryptor.update(chunk)
                    ciphertext_digest.update(encrypted)
                    target.write(encrypted)
                final = encryptor.finalize()
                ciphertext_digest.update(final)
                target.write(final)
            completed = replace(
                envelope,
                authentication_tag=_encode(encryptor.tag),
                ciphertext_sha256=ciphertext_digest.hexdigest(),
            )
            archive.writestr(
                transport_member(MANIFEST_MEMBER),
                completed.canonical_bytes(),
            )
        return completed

    def _validate_paths(
        self,
        bundle_path: Path,
        output_path: Path,
        *,
        overwrite: bool,
    ) -> None:
        if not bundle_path.is_file() or bundle_path.is_symlink():
            raise ValueError("Evidence bundle input must be a regular file.")
        if not 1 <= bundle_path.stat().st_size <= MAX_PAYLOAD_BYTES:
            raise ValueError("Evidence bundle input size is outside the transport limit.")
        if not output_path.parent.is_dir():
            raise ValueError("Encrypted transport output directory does not exist.")
        if bundle_path.resolve() == output_path.resolve():
            raise ValueError("Encrypted transport output must differ from the source bundle.")
        if output_path.exists() and (output_path.is_dir() or output_path.is_symlink()):
            raise ValueError("Encrypted transport output path is unsafe.")
        if output_path.exists() and not overwrite:
            raise FileExistsError("Encrypted transport output already exists.")

    def _temporary_path(self, output_path: Path) -> Path:
        handle, name = tempfile.mkstemp(
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            dir=output_path.parent,
        )
        os.close(handle)
        return Path(name)


def _encode(value: bytes) -> str:
    import base64  # noqa: PLC0415

    return base64.b64encode(value).decode("ascii")


__all__ = ["TransportPackageEncryptor"]
