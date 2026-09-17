from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,TRY003
import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

if TYPE_CHECKING:
    from pathlib import Path

SOURCE_BUNDLE_IDENTITY_SCHEME = "unio-source-bundle-content-sha256-v1"
LEGACY_SOURCE_BUNDLE_IDENTITY_SCHEME = "legacy-path-uuid5-v1"
_MANIFEST_IDENTITY_FIELDS = (
    "bundle_schema_version",
    "bundle_purpose",
    "collector_version",
    "collection_mode",
    "generated_at",
    "evidence_generated_at",
)


@dataclass(frozen=True)
class SourceBundleIdentity:
    """Stable identity derived from validated source bundle content."""

    value: str
    scheme: str = SOURCE_BUNDLE_IDENTITY_SCHEME


def derive_source_bundle_identity(bundle_path: Path) -> SourceBundleIdentity:
    """Derive an identity from validated checksums and manifest fields."""
    with ZipFile(bundle_path, "r") as archive:
        checksums = _read_object(archive.read("checksums.json"), "checksums.json")
        manifest = _read_object(archive.read("manifest.json"), "manifest.json")
    checksum_map = checksums.get("checksums")
    algorithm = checksums.get("algorithm")
    if algorithm != "sha256" or not isinstance(checksum_map, dict) or not checksum_map:
        raise ValueError("Validated bundle checksums cannot be used for source identity.")
    material = {
        "identity_scheme": SOURCE_BUNDLE_IDENTITY_SCHEME,
        "checksums": {
            "algorithm": algorithm,
            "checksums": dict(sorted(checksum_map.items())),
        },
        "manifest": {key: manifest.get(key) for key in _MANIFEST_IDENTITY_FIELDS},
    }
    canonical = json.dumps(
        material,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return SourceBundleIdentity(value=f"sha256:{hashlib.sha256(canonical).hexdigest()}")


def resolve_source_bundle_identity_scheme(metadata: dict[str, Any]) -> str:
    """Resolve additive identity metadata with legacy fallback."""
    value = metadata.get("bundle_id_scheme")
    if isinstance(value, str) and value.strip():
        return value
    return LEGACY_SOURCE_BUNDLE_IDENTITY_SCHEME


def _read_object(data: bytes, name: str) -> dict[str, Any]:
    payload = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        message = f"{name} must contain a JSON object."
        raise ValueError(message)
    return payload
