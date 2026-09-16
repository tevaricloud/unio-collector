from __future__ import annotations  # noqa: D100

# ruff: noqa: EM102
# ruff: noqa: EM101,TRY003
import json
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

from unio_collector.privacy.constants import PRIVACY_POLICY_FILE, PRIVACY_PREVIEW_FILE

if TYPE_CHECKING:
    from pathlib import Path


def verify_export_binding(
    *,
    archive_path: Path,
    vault_path: Path,
    external_preview: dict[str, object] | None,
) -> None:
    """Verify exact identity bindings across staged export artifacts."""
    with ZipFile(archive_path, "r") as archive:
        manifest = _read_object(archive.read("manifest.json"), "manifest")
        policy = _read_object(archive.read(PRIVACY_POLICY_FILE), "privacy policy")
        preview = _read_object(archive.read(PRIVACY_PREVIEW_FILE), "privacy preview")
    vault = _read_object(vault_path.read_bytes(), "identity vault")
    privacy = _require_object(manifest.get("privacy_protection"), "manifest privacy_protection")
    profile = _require_object(policy.get("profile"), "privacy policy profile")
    preview_profile = _require_object(preview.get("profile"), "privacy preview profile")
    vault_metadata = _require_object(vault.get("metadata"), "identity vault metadata")
    mappings = (
        ("protected_bundle_id", privacy, "protected_bundle_id", policy, "protected_bundle_id"),
        ("protected_bundle_id", privacy, "protected_bundle_id", preview, "protected_bundle_id"),
        ("protected_bundle_id", privacy, "protected_bundle_id", vault_metadata, "protected_bundle_id"),
        ("source_bundle_id", privacy, "source_bundle_id", policy, "bundle_id"),
        ("source_bundle_id", privacy, "source_bundle_id", preview, "source_bundle_id"),
        ("source_bundle_id", privacy, "source_bundle_id", vault_metadata, "bundle_id"),
        ("source_bundle_id_scheme", privacy, "source_bundle_id_scheme", policy, "bundle_id_scheme"),
        ("source_bundle_id_scheme", privacy, "source_bundle_id_scheme", preview, "source_bundle_id_scheme"),
        ("source_bundle_id_scheme", privacy, "source_bundle_id_scheme", vault_metadata, "bundle_id_scheme"),
        ("engagement_id", privacy, "engagement_id", policy, "engagement_id"),
        ("engagement_id", privacy, "engagement_id", preview, "engagement_id"),
        ("engagement_id", privacy, "engagement_id", vault_metadata, "engagement_id"),
        ("token_scope", privacy, "token_scope", policy, "token_scope"),
        ("token_scope", privacy, "token_scope", preview, "token_scope"),
        ("token_scope", privacy, "token_scope", vault_metadata, "token_scope"),
        ("privacy_policy_version", privacy, "privacy_policy_version", policy, "policy_version"),
        ("privacy_policy_version", privacy, "privacy_policy_version", preview, "privacy_policy_version"),
        ("privacy_policy_version", privacy, "privacy_policy_version", vault_metadata, "policy_version"),
        ("profile_id", privacy, "profile_id", profile, "profile_id"),
        ("profile_id", privacy, "profile_id", preview_profile, "profile_id"),
        ("profile_id", privacy, "profile_id", vault_metadata, "profile_id"),
        ("profile_version", privacy, "profile_version", profile, "version"),
        ("profile_version", privacy, "profile_version", preview_profile, "version"),
        ("profile_version", privacy, "profile_version", vault_metadata, "profile_version"),
    )
    for label, left, left_key, right, right_key in mappings:
        left_value = _require_string(left, left_key, label)
        right_value = _require_string(right, right_key, label)
        if left_value != right_value:
            raise ValueError(f"Protected export {label} binding does not match.")
    if "vault_id" in privacy:
        for key in ("vault_id", "root_key_fingerprint", "scope_fingerprint"):
            expected = _require_string(privacy, key, key)
            for payload in (policy, preview, vault_metadata):
                if _require_string(payload, key, key) != expected:
                    raise ValueError(f"Protected export {key} binding does not match.")
        revision = privacy.get("vault_revision")
        if type(revision) is not int or revision < 1:
            raise ValueError("Protected export vault revision binding is invalid.")
        revisions = (policy.get("vault_revision"), preview.get("vault_revision"), vault_metadata.get("revision"))
        if any(type(value) is not int or value != revision for value in revisions):
            raise ValueError("Protected export vault revision binding does not match.")
    if external_preview is not None and external_preview != preview:
        raise ValueError("External privacy preview does not match the protected bundle preview.")


def _read_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Staged {label} is invalid JSON.") from exc
    return _require_object(payload, label)


def _require_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Staged {label} must be an object.")
    return value


def _require_string(payload: dict[str, Any], field: str, label: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Protected export {label} binding is missing or invalid.")
    return value
