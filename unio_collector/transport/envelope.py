"""Typed transport-envelope metadata and canonical serialization."""

from __future__ import annotations

# ruff: noqa: EM101,EM102,TRY003
import base64
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from unio_collector.transport.constants import (
    CIPHERTEXT_MEMBER,
    ENCRYPTION_ALGORITHM,
    KEY_WRAP_ALGORITHM,
    MAX_PAYLOAD_BYTES,
    NONCE_BYTES,
    PAYLOAD_TYPE,
    TAG_BYTES,
    TRANSPORT_SCHEMA_VERSION,
)

_FIELDS = frozenset(
    {
        "schema_version",
        "encryption_algorithm",
        "key_wrap_algorithm",
        "recipient_key_id",
        "created_at",
        "payload_type",
        "payload_size",
        "ciphertext_member",
        "nonce",
        "authentication_tag",
        "wrapped_content_key",
        "ciphertext_sha256",
    },
)
_UNAUTHENTICATED_FIELDS = frozenset(("authentication_tag", "ciphertext_sha256"))
SHA256_HEX_LENGTH = 64
RECIPIENT_KEY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


@dataclass(frozen=True)
class TransportEnvelope:
    """Versioned metadata for one encrypted evidence archive."""

    schema_version: str
    encryption_algorithm: str
    key_wrap_algorithm: str
    recipient_key_id: str
    created_at: str
    payload_type: str
    payload_size: int
    ciphertext_member: str
    nonce: str
    authentication_tag: str
    wrapped_content_key: str
    ciphertext_sha256: str

    @classmethod
    def create(
        cls,
        *,
        recipient_key_id: str,
        created_at: str,
        payload_size: int,
        nonce: bytes,
        wrapped_content_key: bytes,
        authentication_tag: bytes = b"",
        ciphertext_sha256: str = "",
    ) -> TransportEnvelope:
        """Create protocol metadata from validated encryption inputs."""
        return cls(
            schema_version=TRANSPORT_SCHEMA_VERSION,
            encryption_algorithm=ENCRYPTION_ALGORITHM,
            key_wrap_algorithm=KEY_WRAP_ALGORITHM,
            recipient_key_id=recipient_key_id,
            created_at=created_at,
            payload_type=PAYLOAD_TYPE,
            payload_size=payload_size,
            ciphertext_member=CIPHERTEXT_MEMBER,
            nonce=_b64(nonce),
            authentication_tag=_b64(authentication_tag),
            wrapped_content_key=_b64(wrapped_content_key),
            ciphertext_sha256=ciphertext_sha256,
        )

    @classmethod
    def from_bytes(cls, value: bytes) -> TransportEnvelope:
        """Parse and strictly validate canonical envelope JSON."""
        try:
            payload = json.loads(value.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Transport envelope manifest is malformed.") from exc
        if not isinstance(payload, dict) or set(payload) != _FIELDS:
            raise ValueError("Transport envelope manifest has missing or unexpected fields.")
        envelope = cls(**payload)
        envelope.validate()
        return envelope

    def validate(self) -> None:
        """Fail closed on unsupported or malformed metadata."""
        self._validate_protocol()
        self._validate_routing()
        self._validate_crypto_fields()

    def _validate_protocol(self) -> None:
        if self.schema_version != TRANSPORT_SCHEMA_VERSION:
            raise ValueError("Transport envelope schema version is unsupported.")
        if self.encryption_algorithm != ENCRYPTION_ALGORITHM:
            raise ValueError("Transport encryption algorithm is unsupported.")
        if self.key_wrap_algorithm != KEY_WRAP_ALGORITHM:
            raise ValueError("Transport key-wrap algorithm is unsupported.")

    def _validate_routing(self) -> None:
        validate_recipient_key_id(self.recipient_key_id)
        if not isinstance(self.created_at, str):
            raise ValueError("Transport creation timestamp is invalid.")
        try:
            parsed = datetime.fromisoformat(self.created_at)
        except ValueError as exc:
            raise ValueError("Transport creation timestamp is invalid.") from exc
        if parsed.tzinfo is None:
            raise ValueError("Transport creation timestamp must include a timezone.")
        if self.payload_type != PAYLOAD_TYPE:
            raise ValueError("Transport payload type is unsupported.")
        if type(self.payload_size) is not int or not 1 <= self.payload_size <= MAX_PAYLOAD_BYTES:
            raise ValueError("Transport payload size is invalid.")
        if self.ciphertext_member != CIPHERTEXT_MEMBER:
            raise ValueError("Transport ciphertext member is invalid.")

    def _validate_crypto_fields(self) -> None:
        self.decode_nonce()
        self.decode_tag()
        self.decode_wrapped_key()
        value = self.ciphertext_sha256
        if not isinstance(value, str) or len(value) != SHA256_HEX_LENGTH:
            raise ValueError("Transport ciphertext_sha256 is invalid.")
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError("Transport ciphertext_sha256 is invalid.") from exc

    def canonical_bytes(self) -> bytes:
        """Return deterministic JSON bytes for the outer manifest."""
        return _canonical(asdict(self)) + b"\n"

    def authenticated_metadata(self) -> bytes:
        """Return deterministic AEAD associated data."""
        payload = {key: value for key, value in asdict(self).items() if key not in _UNAUTHENTICATED_FIELDS}
        return _canonical(payload)

    def decode_nonce(self) -> bytes:
        """Decode the fixed-width GCM nonce."""
        return _decode(self.nonce, "nonce", length=NONCE_BYTES)

    def decode_tag(self) -> bytes:
        """Decode the fixed-width GCM authentication tag."""
        return _decode(self.authentication_tag, "authentication tag", length=TAG_BYTES)

    def decode_wrapped_key(self) -> bytes:  # noqa: D102
        return _decode(self.wrapped_content_key, "wrapped content key")


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: object, field: str, *, length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"Transport {field} must contain base64 text.")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"Transport {field} contains invalid base64.") from exc
    if not decoded or (length is not None and len(decoded) != length):
        raise ValueError(f"Transport {field} has an invalid length.")
    return decoded


def validate_recipient_key_id(value: object) -> str:
    """Validate a bounded log-safe recipient key identifier."""
    if not isinstance(value, str) or RECIPIENT_KEY_ID_RE.fullmatch(value) is None:
        raise ValueError("Transport recipient key id is invalid.")
    return value


__all__ = ["TransportEnvelope", "validate_recipient_key_id"]
