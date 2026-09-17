from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,TRY003
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from unio_collector.collector.bundle.encoding import load_json_object
from unio_collector.collector.protocol import DEFAULT_PROTOCOL, EvidenceProtocol
from unio_collector.privacy.admission.vault import VaultSource
from unio_collector.privacy.constants import (
    LEGACY_VAULT_FORMAT_VERSION,
    PRIVACY_POLICY_VERSION,
    SUPPORTED_TOKEN_SCOPES,
    TOKEN_FORMAT_VERSION,
    VAULT_FORMAT_VERSION,
    VAULT_PLAINTEXT_SCHEMA_VERSION,
)
from unio_collector.privacy.crypto import (
    NONCE_BYTES,
    Argon2idParameters,
    aesgcm_decrypt,
    aesgcm_encrypt,
    b64,
    decode_vault_bytes,
    derive_subkey,
    root_key_fingerprint,
    scope_fingerprint,
    unwrap_root_key,
    wrap_root_key,
)
from unio_collector.privacy.unlocked_vault import UnlockedVault

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class VaultWriteInput:
    """Inputs needed to encrypt a private identity vault."""

    root_key: bytes
    plaintext: dict[str, object]
    recovery_mode: str
    passphrase: str | None
    recovery_key: bytes | None
    bundle_id: str
    protected_bundle_id: str
    engagement_id: str
    policy_version: str
    token_scope: str
    argon2id_parameters: Argon2idParameters | None = None
    bundle_id_scheme: str | None = None
    profile_id: str | None = None
    profile_version: str | None = None
    provider: str = "aws"
    vault_id: str | None = None
    revision: int = 1
    previous_vault_sha256: str | None = None
    scope_boundary_id: str | None = None


def build_vault_aad(payload: dict[str, object]) -> bytes:
    """Build deterministic AEAD associated data from non-secret metadata."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8",
    )


def encrypt_vault(data: VaultWriteInput) -> dict[str, Any]:
    """Return encrypted vault file content."""
    metadata: dict[str, object] = {
        "format": VAULT_FORMAT_VERSION if data.vault_id is not None else LEGACY_VAULT_FORMAT_VERSION,
        "bundle_id": data.bundle_id,
        "protected_bundle_id": data.protected_bundle_id,
        "engagement_id": data.engagement_id,
        "policy_version": data.policy_version,
        "token_scope": data.token_scope,
        "root_key_fingerprint": root_key_fingerprint(data.root_key),
        "warning": (
            "This vault file contains encrypted ciphertext and non-secret "
            "metadata only. Decrypted vault plaintext contains sensitive "
            "identity mappings and must remain client-side."
        ),
    }
    if data.vault_id is not None:
        metadata.update(
            {
                "provider": data.provider,
                "vault_id": data.vault_id,
                "revision": data.revision,
                "previous_vault_sha256": data.previous_vault_sha256,
                "token_format_version": TOKEN_FORMAT_VERSION,
                "scope_type": data.token_scope,
                "scope_fingerprint": scope_fingerprint(
                    data.root_key,
                    data.token_scope,
                    data.scope_boundary_id or data.engagement_id,
                ),
            },
        )
    if data.bundle_id_scheme is not None:
        metadata["bundle_id_scheme"] = data.bundle_id_scheme
    if data.profile_id is not None:
        metadata["profile_id"] = data.profile_id
    if data.profile_version is not None:
        metadata["profile_version"] = data.profile_version
    aad = build_vault_aad(metadata)
    wrapped = wrap_root_key(
        data.root_key,
        mode=data.recovery_mode,
        passphrase=data.passphrase,
        recovery_key=data.recovery_key,
        aad=aad,
        argon2id_parameters=data.argon2id_parameters,
    )
    vault_key = derive_subkey(data.root_key, "vault-aead")
    nonce, ciphertext = aesgcm_encrypt(
        vault_key,
        json.dumps(data.plaintext, sort_keys=True).encode("utf-8"),
        aad,
    )
    return {
        "metadata": metadata,
        "wrapped_root_key": wrapped.convert_to_dict(),
        "vault_ciphertext": {
            "algorithm": "AES-256-GCM",
            "nonce": b64(nonce),
            "ciphertext": b64(ciphertext),
        },
    }


def decrypt_vault(
    payload: dict[str, object],
    *,
    passphrase: str | None = None,
    recovery_key: bytes | None = None,
) -> dict[str, object]:
    """Decrypt a private identity vault for local tests and future restoration."""
    return unlock_vault(
        payload,
        passphrase=passphrase,
        recovery_key=recovery_key,
    ).plaintext


def unlock_vault(
    payload: dict[str, object],
    *,
    passphrase: str | None = None,
    recovery_key: bytes | None = None,
) -> UnlockedVault:
    """Decrypt a vault and return authenticated metadata plus its root key."""
    metadata = payload.get("metadata")
    wrapped = payload.get("wrapped_root_key")
    ciphertext_payload = payload.get("vault_ciphertext")
    if not isinstance(metadata, dict):
        raise ValueError("Vault metadata is missing or invalid.")
    if not isinstance(wrapped, dict):
        raise ValueError("Wrapped root key metadata is missing or invalid.")
    if not isinstance(ciphertext_payload, dict):
        raise ValueError("Vault ciphertext metadata is missing or invalid.")
    try:
        protocol = EvidenceProtocol.from_identifier(metadata.get("format"), ("vault-v1", "vault-v2"))
    except ValueError as exc:
        raise ValueError("Vault format is unsupported.") from exc
    protocol.validate_privacy(metadata, vault=True)
    if ciphertext_payload.get("algorithm") != "AES-256-GCM":
        raise ValueError("Vault encryption algorithm is unsupported.")
    if "revision" in metadata and (type(metadata["revision"]) is not int or metadata["revision"] < 1):
        raise ValueError("Vault revision must be a positive integer.")
    if "vault_id" in metadata and (not isinstance(metadata["vault_id"], str) or not metadata["vault_id"].strip()):
        raise ValueError("Vault identity must be a non-empty string.")
    nonce = decode_vault_bytes(ciphertext_payload.get("nonce"), length=NONCE_BYTES)
    ciphertext = decode_vault_bytes(ciphertext_payload.get("ciphertext"))
    aad = build_vault_aad(metadata)
    root_key = unwrap_root_key(
        wrapped,
        passphrase=passphrase,
        recovery_key=recovery_key,
        aad=aad,
        protocol=protocol,
    )
    vault_key = derive_subkey(root_key, "vault-aead", protocol=protocol)
    plaintext = aesgcm_decrypt(vault_key, nonce, ciphertext, aad)
    result = load_json_object(plaintext.decode("utf-8"))
    _validate_unlocked_metadata(metadata, result, root_key, protocol)
    validated_export_bindings(result)
    return UnlockedVault(
        payload=payload,
        metadata=metadata,
        plaintext=result,
        root_key=root_key,
    )


def _validate_unlocked_metadata(metadata: dict[str, object], result: dict[str, object], root_key: bytes, protocol: EvidenceProtocol = DEFAULT_PROTOCOL) -> None:
    if "schema_version" in result and (
        not isinstance(result["schema_version"], str) or result["schema_version"] not in {PRIVACY_POLICY_VERSION, VAULT_PLAINTEXT_SCHEMA_VERSION}
    ):
        raise ValueError("Vault plaintext schema version is unsupported.")
    if metadata.get("root_key_fingerprint") != root_key_fingerprint(root_key):
        raise ValueError("Vault root-key fingerprint is invalid.")
    for field in ("vault_id", "revision"):
        if field in result and (type(result[field]) is not type(metadata.get(field)) or result[field] != metadata.get(field)):
            raise ValueError("Vault plaintext lineage contradicts authenticated metadata.")
    _validate_scope_fingerprint(metadata, result, root_key, protocol)


def _validate_scope_fingerprint(
    metadata: dict[str, object], plaintext: dict[str, object], root_key: bytes, protocol: EvidenceProtocol = DEFAULT_PROTOCOL
) -> None:
    if "scope_fingerprint" not in metadata:
        return
    token_scope = metadata.get("token_scope")
    boundary = plaintext.get("scope_boundary_id", metadata.get("engagement_id"))
    if not isinstance(token_scope, str) or token_scope not in SUPPORTED_TOKEN_SCOPES or not isinstance(boundary, str) or not boundary:
        raise ValueError("Vault scope metadata is invalid.")
    if metadata["scope_fingerprint"] != scope_fingerprint(root_key, token_scope, boundary, protocol=protocol):
        raise ValueError("Vault scope fingerprint is invalid.")


def validated_export_bindings(plaintext: dict[str, object]) -> tuple[dict[str, object], ...]:
    """Admit present encrypted export identities while retaining absent legacy bindings."""
    if "export_bindings" not in plaintext:
        return ()
    values = plaintext["export_bindings"]
    if not isinstance(values, list):
        raise ValueError("Vault export bindings must be a list.")
    identities: set[str] = set()
    bindings: list[dict[str, object]] = []
    for value in values:
        identity = value.get("protected_bundle_id") if isinstance(value, dict) else None
        if not isinstance(value, dict) or not isinstance(identity, str) or not identity.strip() or identity in identities:
            raise ValueError("Vault export bindings contain invalid or duplicate identities.")
        for key in ("source_bundle_id", "privacy_policy_version", "profile_id", "profile_version", "engagement_id"):
            if key in value and (not isinstance(value[key], str) or not value[key].strip()):
                raise ValueError("Vault export binding metadata is invalid.")
        identities.add(identity)
        bindings.append(value)
    return tuple(bindings)


def read_vault_recovery_mode(path: Path) -> str:
    """Read the non-secret recovery mode needed for CLI input resolution."""
    try:
        payload = VaultSource.read(path).payload
    except ValueError as exc:
        raise ValueError("Encrypted vault could not be read as JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError("Encrypted vault must be a JSON object.")
    wrapped = payload.get("wrapped_root_key")
    if not isinstance(wrapped, dict):
        raise ValueError("Wrapped root key metadata is missing or invalid.")
    mode = wrapped.get("mode")
    if mode not in ("passphrase", "recovery-key", "passphrase-and-key"):
        raise ValueError("Vault recovery mode is missing or unsupported.")
    return str(mode)
