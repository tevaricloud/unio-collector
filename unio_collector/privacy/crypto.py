from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,EM102,TRY003
import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from unio_collector.collector.protocol import DEFAULT_PROTOCOL, EvidenceProtocol
from unio_collector.privacy import argon2id
from unio_collector.privacy.argon2id import Argon2idParameters

ROOT_KEY_BYTES = 32
NONCE_BYTES = 12
ARGON2_SALT_BYTES = 16
ARGON2_MEMORY_KIB = argon2id.ARGON2_MEMORY_KIB
ARGON2_TIME_COST = argon2id.ARGON2_TIME_COST
ARGON2_PARALLELISM = argon2id.ARGON2_PARALLELISM
ARGON2_HASH_LENGTH = argon2id.ARGON2_HASH_LENGTH


@dataclass(frozen=True)
class WrappedRootKey:
    """Encrypted root key metadata for vault recovery."""

    mode: str
    salt: str | None
    nonce: str
    ciphertext: str
    argon2id: dict[str, int] | None = None

    def convert_to_dict(self) -> dict[str, Any]:
        """Return serializable wrapping metadata."""
        return {
            "mode": self.mode,
            "salt": self.salt,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "argon2id": self.argon2id,
        }


def generate_root_key() -> bytes:
    """Generate a cryptographically random 256-bit client root key."""
    return secrets.token_bytes(ROOT_KEY_BYTES)


def derive_subkey(root_key: bytes, purpose: str, *, length: int = 32, protocol: EvidenceProtocol = DEFAULT_PROTOCOL) -> bytes:
    """Derive a purpose-specific subkey with HKDF-SHA-256."""
    return HKDF(
        algorithm=SHA256(),
        length=length,
        salt=None,
        info=protocol.privacy_context(purpose),
    ).derive(root_key)


def root_key_fingerprint(root_key: bytes) -> str:
    """Return a non-secret root-key fingerprint for metadata binding."""
    return hashlib.sha256(root_key).hexdigest()[:24]


def scope_fingerprint(root_key: bytes, token_scope: str, scope_boundary_id: str, *, protocol: EvidenceProtocol = DEFAULT_PROTOCOL) -> str:
    """Return a keyed, non-reversible fingerprint for a token boundary."""
    key = derive_subkey(root_key, "scope-fingerprint", protocol=protocol)
    payload = f"{token_scope}\0{scope_boundary_id}".encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()[:24]


def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt bytes with AES-GCM and a random nonce."""
    nonce = secrets.token_bytes(NONCE_BYTES)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt AES-GCM ciphertext."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def derive_passphrase_kek(
    passphrase: str,
    salt: bytes,
    *,
    parameters: Argon2idParameters | None = None,
) -> bytes:
    """Derive a key-encryption key with Argon2id."""
    resolved = parameters or Argon2idParameters()
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=resolved.time_cost,
        memory_cost=resolved.memory_cost_kib,
        parallelism=resolved.parallelism,
        hash_len=resolved.hash_length,
        type=Type.ID,
    )


def combine_keks(*values: bytes, protocol: EvidenceProtocol = DEFAULT_PROTOCOL) -> bytes:
    """Combine passphrase and key-file material with HKDF-SHA-256."""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=protocol.privacy_context("combined-root-key-kek"),
    ).derive(b"".join(values))


def wrap_root_key(
    root_key: bytes,
    *,
    mode: str,
    passphrase: str | None = None,
    recovery_key: bytes | None = None,
    aad: bytes,
    argon2id_parameters: Argon2idParameters | None = None,
) -> WrappedRootKey:
    """Wrap the random root key using passphrase and/or key-file material."""
    salt: bytes | None = None
    parameters = argon2id_parameters or Argon2idParameters()
    if mode == "passphrase":
        if not passphrase:
            raise ValueError("Passphrase recovery mode requires a passphrase.")
        salt = secrets.token_bytes(ARGON2_SALT_BYTES)
        kek = derive_passphrase_kek(passphrase, salt, parameters=parameters)
    elif mode == "recovery-key":
        if recovery_key is None:
            raise ValueError("Recovery-key mode requires recovery key material.")
        kek = recovery_key
    elif mode == "passphrase-and-key":
        if not passphrase or recovery_key is None:
            raise ValueError(
                "Passphrase-and-key mode requires a passphrase and recovery key material.",
            )
        salt = secrets.token_bytes(ARGON2_SALT_BYTES)
        kek = combine_keks(
            derive_passphrase_kek(passphrase, salt, parameters=parameters),
            recovery_key,
        )
    else:
        raise ValueError(f"Unsupported recovery mode: {mode}")
    nonce, ciphertext = aesgcm_encrypt(kek, root_key, aad)
    return WrappedRootKey(
        mode=mode,
        salt=base64.b64encode(salt).decode("ascii") if salt is not None else None,
        nonce=base64.b64encode(nonce).decode("ascii"),
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
        argon2id=(parameters.convert_to_dict() if salt is not None else None),
    )


def unwrap_root_key(
    payload: dict[str, object],
    *,
    passphrase: str | None = None,
    recovery_key: bytes | None = None,
    aad: bytes,
    protocol: EvidenceProtocol = DEFAULT_PROTOCOL,
) -> bytes:
    """Unwrap a vault root key using passphrase and/or key-file material."""
    mode = str(payload.get("mode") or "")
    salt_text = payload.get("salt")
    nonce = decode_vault_bytes(payload.get("nonce"), length=NONCE_BYTES)
    ciphertext = decode_vault_bytes(payload.get("ciphertext"), length=ROOT_KEY_BYTES + 16)
    parameters = Argon2idParameters.from_payload(payload.get("argon2id"))
    if mode == "passphrase":
        if not passphrase or not isinstance(salt_text, str):
            raise ValueError("Passphrase recovery mode requires a passphrase.")
        kek = derive_passphrase_kek(
            passphrase,
            decode_vault_bytes(salt_text, length=ARGON2_SALT_BYTES),
            parameters=parameters,
        )
    elif mode == "recovery-key":
        if recovery_key is None:
            raise ValueError("Recovery-key mode requires recovery key material.")
        kek = recovery_key
    elif mode == "passphrase-and-key":
        if not passphrase or recovery_key is None or not isinstance(salt_text, str):
            raise ValueError(
                "Passphrase-and-key mode requires a passphrase and recovery key material.",
            )
        kek = combine_keks(
            derive_passphrase_kek(
                passphrase,
                decode_vault_bytes(salt_text, length=ARGON2_SALT_BYTES),
                parameters=parameters,
            ),
            recovery_key,
            protocol=protocol,
        )
    else:
        raise ValueError(f"Unsupported recovery mode: {mode}")
    return aesgcm_decrypt(kek, nonce, ciphertext, aad)


def decode_vault_bytes(value: object, *, length: int | None = None) -> bytes:
    """Decode an explicit base64 envelope field without coercion."""
    if not isinstance(value, str):
        raise ValueError("Vault encryption field must contain base64 text.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Vault encryption field contains invalid base64.") from exc
    if not decoded or (length is not None and len(decoded) != length):
        raise ValueError("Vault encryption field has an invalid length.")
    return decoded


def b64(value: bytes) -> str:
    """Return base64 text."""
    return base64.b64encode(value).decode("ascii")
