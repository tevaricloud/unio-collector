from __future__ import annotations

# ruff: noqa: D100,D102,EM101,EM102,TC001,TC003,TRY003
import base64
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unio_collector.collector.bundle.archive_writer import write_bundle_archive
from unio_collector.collector.bundle.checksums import build_sha256
from unio_collector.collector.bundle.encoding import dump_json, dump_jsonl, validate_internal_path
from unio_collector.collector.organization.manifest import OrganizationEnvelopeManifest
from unio_collector.collector.signature import build_unsigned_signature_metadata


class OrganizationEnvelopeWriter:
    """Write a deterministic organization envelope around authoritative child bundles."""

    def write(
        self,
        *,
        path: Path,
        manifest: OrganizationEnvelopeManifest,
        request_payload: dict[str, object],
        scope_payload: dict[str, object],
        coverage_payload: dict[str, object],
        run_summary_payload: dict[str, object],
        role_audit_records: list[dict[str, object]],
        child_bundles: dict[str, Path],
        signing_key: Path | None = None,
        signing_key_id: str | None = None,
    ) -> Path:
        manifest.validate_account_references()
        expected = {item.account_reference: item for item in manifest.accounts if item.status in {"completed", "degraded"}}
        if set(child_bundles) != set(expected):
            raise ValueError("Successful envelope accounts must have exactly one child bundle.")
        files: dict[str, bytes] = {
            "organization-manifest.json": dump_json(manifest.model_dump(mode="json")),
            "organization-request.json": dump_json(request_payload),
            "organization-scope.json": dump_json(scope_payload),
            "organization-coverage.json": dump_json(coverage_payload),
            "organization-run-summary.json": dump_json(run_summary_payload),
            "role-assumption-audit.jsonl": dump_jsonl(role_audit_records),
        }
        for reference, bundle_path in sorted(child_bundles.items()):
            data = bundle_path.read_bytes()
            item = expected[reference]
            if build_sha256(data) != item.bundle_sha256:
                raise ValueError(f"Child bundle checksum mismatch before envelope write: {reference}")
            internal_path = f"accounts/{reference}/evidence-bundle.zip"
            if internal_path != item.bundle_path:
                raise ValueError(f"Child bundle manifest path mismatch: {reference}")
            files[internal_path] = data
        checksums = {name: build_sha256(data) for name, data in sorted(files.items())}
        files["checksums.json"] = dump_json({"algorithm": "sha256", "checksums": checksums})
        files["signature.json"] = dump_json(
            self._signature(files["checksums.json"], manifest.schema_version, signing_key, signing_key_id),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        write_bundle_archive(path, files, validate_path=validate_internal_path)
        return path

    def _signature(
        self,
        payload: bytes,
        schema_version: str,
        private_key_path: Path | None,
        key_id: str | None,
    ) -> dict[str, object]:
        if private_key_path is None:
            return build_unsigned_signature_metadata(metadata_version=schema_version)
        if not key_id or not key_id.strip():
            raise ValueError("Organization envelope signing requires a non-empty key ID.")
        loaded = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("Organization envelope signing key must be Ed25519.")
        return {
            "metadata_version": schema_version,
            "status": "signed",
            "digest_algorithm": "sha256",
            "signed_payload": "checksums.json",
            "signature_algorithm": "Ed25519",
            "key_id": key_id.strip(),
            "created_at": datetime.now(UTC).isoformat(),
            "signature": base64.b64encode(loaded.sign(payload)).decode("ascii"),
            "reason": "Organization envelope checksum manifest signed by an operator-provided key.",
        }
