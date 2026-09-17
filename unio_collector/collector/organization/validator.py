from __future__ import annotations

# ruff: noqa: BLE001,C901,D100,D102,EM101,TRY003,TRY300,TRY301
import base64
import json
import tempfile
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from unio_collector.collector.bundle.checksums import build_sha256
from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.collector.organization.constants import (
    ORGANIZATION_ENVELOPE_SCHEMA_VERSION,
    ORGANIZATION_REQUIRED_FILES,
)
from unio_collector.collector.organization.manifest import OrganizationEnvelopeManifest
from unio_collector.collector.organization.validation_result import OrganizationEnvelopeValidationResult


class OrganizationEnvelopeValidator:
    """Validate envelope structure, integrity, children, and optional signature."""

    def validate(
        self,
        path: Path,
        *,
        trusted_public_key: Path | None = None,
        require_signed: bool = False,
    ) -> OrganizationEnvelopeValidationResult:
        errors: list[str] = []
        warnings: list[str] = []
        signed = False
        verified = False
        schema_version: str | None = None
        try:
            with ZipFile(path) as archive:
                names = archive.namelist()
                if len(names) != len(set(names)):
                    errors.append("Organization envelope contains duplicate member paths.")
                for name in names:
                    posix = PurePosixPath(name)
                    if "\\" in name or name.startswith("/") or ".." in posix.parts:
                        errors.append(f"Invalid organization envelope member path: {name}")
                missing = sorted(ORGANIZATION_REQUIRED_FILES - set(names))
                if missing:
                    errors.append("Organization envelope is missing required files: " + ", ".join(missing))
                if errors:
                    return self._result(errors, warnings)
                manifest_raw = self._json(archive, "organization-manifest.json", errors)
                checksums_raw = self._json(archive, "checksums.json", errors)
                signature = self._json(archive, "signature.json", errors)
                if errors:
                    return self._result(errors, warnings)
                try:
                    manifest = OrganizationEnvelopeManifest.model_validate(manifest_raw)
                    manifest.validate_account_references()
                    schema_version = manifest.schema_version
                except Exception as exc:
                    errors.append(f"Invalid organization manifest: {exc}")
                    return self._result(errors, warnings)
                if schema_version != ORGANIZATION_ENVELOPE_SCHEMA_VERSION:
                    errors.append(f"Unsupported organization envelope schema: {schema_version}")
                declared_children = {account.bundle_path for account in manifest.accounts if account.status in {"completed", "degraded"}}
                actual_children = {name for name in names if name.startswith("accounts/")}
                if declared_children != actual_children:
                    errors.append("Organization envelope child members do not match its successful account references.")
                checksum_map = checksums_raw.get("checksums") if isinstance(checksums_raw, dict) else None
                if not isinstance(checksum_map, dict) or checksums_raw.get("algorithm") != "sha256":
                    errors.append("checksums.json must contain a sha256 checksum mapping.")
                    checksum_map = {}
                expected_members = set(names) - {"checksums.json", "signature.json"}
                if set(checksum_map) != expected_members:
                    errors.append("checksums.json does not cover the exact envelope payload members.")
                for name, digest in checksum_map.items():
                    if name in names and build_sha256(archive.read(name)) != digest:
                        errors.append(f"Organization envelope checksum mismatch: {name}")
                for account in manifest.accounts:
                    if account.status not in {"completed", "degraded"}:
                        continue
                    if account.bundle_path not in names:
                        errors.append(f"Successful account has no child bundle: {account.account_reference}")
                        continue
                    child_bytes = archive.read(account.bundle_path)
                    if build_sha256(child_bytes) != account.bundle_sha256:
                        errors.append(f"Child bundle manifest checksum mismatch: {account.account_reference}")
                        continue
                    with tempfile.TemporaryDirectory(
                        prefix="unio-collector-organization-child-",
                    ) as temporary:
                        child_path = Path(temporary) / "evidence-bundle.zip"
                        child_path.write_bytes(child_bytes)
                        child_result = EvidenceBundleValidator().validate(child_path)
                        child_manifest = self._child_manifest(child_path, errors)
                    if not child_result.passed:
                        errors.append(f"Invalid child bundle for {account.account_reference}: " + "; ".join(child_result.errors))
                    if account.bundle_purpose is not None and child_manifest.get("bundle_purpose") != account.bundle_purpose:
                        errors.append(f"Child bundle purpose mismatch for {account.account_reference}.")
                    if account.bundle_schema_version is not None and child_manifest.get("bundle_schema_version") != account.bundle_schema_version:
                        errors.append(f"Child bundle schema mismatch for {account.account_reference}.")
                status = signature.get("status") if isinstance(signature, dict) else None
                signed = status == "signed"
                if status not in {"signed", "unsigned"}:
                    errors.append("signature.json status must be signed or unsigned.")
                if signature.get("metadata_version") != schema_version:
                    errors.append("signature.json metadata_version does not match the envelope schema.")
                if signature.get("digest_algorithm") != "sha256":
                    errors.append("signature.json digest_algorithm must be sha256.")
                if signature.get("signed_payload") != "checksums.json":
                    errors.append("signature.json signed_payload must be checksums.json.")
                if status == "unsigned" and any(
                    signature.get(key) is not None
                    for key in (
                        "signature_algorithm",
                        "key_id",
                        "created_at",
                        "signature",
                    )
                ):
                    errors.append("Unsigned organization envelopes must not contain signature material.")
                if require_signed and not signed:
                    errors.append("A signed organization envelope is required.")
                if signed:
                    if signature.get("signature_algorithm") != "Ed25519":
                        errors.append("Signed organization envelopes must use Ed25519.")
                    if not signature.get("key_id") or not signature.get("created_at") or not signature.get("signature"):
                        errors.append("Signed organization envelopes require key ID, creation time, and signature.")
                    elif trusted_public_key is None:
                        if require_signed:
                            errors.append("Trusted public key is required to verify the organization envelope.")
                        else:
                            warnings.append("Organization envelope is signed but no trusted public key was supplied.")
                    else:
                        verified = self._verify(trusted_public_key, archive.read("checksums.json"), signature, errors)
                elif trusted_public_key is not None:
                    warnings.append("Trusted public key was supplied for an unsigned organization envelope.")
        except (BadZipFile, OSError) as exc:
            errors.append(f"Unable to read organization envelope: {exc}")
        return OrganizationEnvelopeValidationResult(
            valid=not errors,
            schema_version=schema_version,
            signed=signed,
            signature_verified=verified,
            errors=tuple(errors),
            warnings=tuple(warnings),
        )

    def _json(self, archive: ZipFile, name: str, errors: list[str]) -> dict[str, object]:
        try:
            payload = json.loads(archive.read(name).decode("utf-8"))
            if not isinstance(payload, dict):
                errors.append(f"Invalid {name}: top-level value must be an object.")
                return {}
            return payload
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as exc:
            errors.append(f"Invalid {name}: {exc}")
            return {}

    def _child_manifest(
        self,
        path: Path,
        errors: list[str],
    ) -> dict[str, object]:
        try:
            with ZipFile(path) as archive:
                payload = json.loads(archive.read("manifest.json"))
            if isinstance(payload, dict):
                return payload
        except (BadZipFile, KeyError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            errors.append(f"Unable to read child bundle manifest: {exc}")
        return {}

    def _verify(self, path: Path, payload: bytes, signature: dict[str, object], errors: list[str]) -> bool:
        try:
            key = serialization.load_pem_public_key(path.read_bytes())
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("Trusted organization envelope key must be Ed25519.")
            encoded = signature.get("signature")
            if not isinstance(encoded, str):
                raise ValueError("Signed organization envelope has no signature value.")
            key.verify(base64.b64decode(encoded, validate=True), payload)
            return True
        except (OSError, ValueError, InvalidSignature) as exc:
            errors.append(f"Organization envelope signature verification failed: {exc}")
            return False

    def _result(self, errors: list[str], warnings: list[str]) -> OrganizationEnvelopeValidationResult:
        return OrganizationEnvelopeValidationResult(valid=False, errors=tuple(errors), warnings=tuple(warnings))
