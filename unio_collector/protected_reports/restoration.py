from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,TRY003
import base64
import copy
import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from unio_collector.collector.bundle.encoding import load_json_object
from unio_collector.privacy.admission.vault import VaultSource
from unio_collector.privacy.artifact_transaction import ArtifactTransaction
from unio_collector.privacy.private_artifact_writer import PrivateArtifactWriter
from unio_collector.privacy.security_warning import SecurityWarning, warning_messages
from unio_collector.privacy.transaction_coordinator import ArtifactTransactionCoordinator
from unio_collector.privacy.vault import decrypt_vault
from unio_collector.protected_reports.canonical_renderers import CanonicalProtectedArtifactRenderer
from unio_collector.protected_reports.constants import PROTECTED_REPORT_PACKAGE_V2_SCHEMA_VERSION
from unio_collector.protected_reports.renderer import ProtectedReportRenderer
from unio_collector.protected_reports.restoration_completion import (
    build_restoration_completion,
    encode_restoration_completion,
)
from unio_collector.protected_reports.restore.options import ProtectedReportRestoreOptions
from unio_collector.protected_reports.restore.result import ProtectedReportRestoreResult
from unio_collector.protected_reports.restored_tree_verifier import RestoredTreeVerifier
from unio_collector.protected_reports.validation import ProtectedReportPackageValidator
from unio_collector.protected_reports.vault_binding_validator import VaultPackageBindingValidator
from unio_collector.protected_reports.verification_options import ProtectedReportVerificationOptions
from unio_collector.protected_reports.verifier import ProtectedReportPackageVerifier

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from unio_collector.privacy.prepared_artifact import PreparedArtifact

TOKEN_REFERENCE_RE = re.compile(
    r"\b(?:ACCOUNT|RESOURCE|ROLE|IPV4|IPV6|CIDR|DNS|EMAIL|BUCKET|ARN|TAG)-[A-Z2-7]{16}\b",
)

__all__ = [
    "ProtectedReportRenderer",
    "ProtectedReportRestoreOptions",
    "ProtectedReportRestoreResult",
    "ProtectedReportRestorer",
]


class ProtectedReportRestorer:
    """Restore protected report packages locally without report-pipeline imports."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        """Create a restorer with an injectable completion-marker clock."""
        self._clock = clock or (lambda: datetime.now(UTC))

    def restore(
        self,
        options: ProtectedReportRestoreOptions,
    ) -> ProtectedReportRestoreResult:
        """Restore typed token references using a client-held encrypted vault."""
        package = self._load_package(options.package_path)
        self._validate_package(package)
        self._verify_package(package, options)
        vault_payload = self._load_vault(options.vault_path)
        VaultPackageBindingValidator().validate_metadata(package, vault_payload)
        plaintext = decrypt_vault(
            vault_payload,
            passphrase=options.passphrase,
            recovery_key=self._read_recovery_key(options.recovery_key_path),
        )
        VaultPackageBindingValidator().validate_export_binding(package, plaintext)
        token_map = self._build_token_map(plaintext)
        restored = self._restore_package(package, token_map)
        audit = self._build_audit(
            package=package,
            restored=restored,
            token_map=token_map,
        )
        paths, warning_details = self._write_outputs(
            restored,
            package=package,
            audit=audit,
            options=options,
        )
        return ProtectedReportRestoreResult(
            output_dir=options.output_dir,
            restored_json_path=paths["json"],
            markdown_path=paths["markdown"],
            html_path=paths["html"],
            audit_path=paths["audit"],
            completion_path=paths["completion"],
            audit=audit,
            warnings=warning_messages(warning_details),
            warning_details=warning_details,
            artifact_paths=tuple(path for role, path in paths.items() if role not in {"audit", "completion"}),
        )

    def _load_package(self, path: Path) -> dict[str, Any]:
        return load_json_object(path.read_text(encoding="utf-8"))

    def _load_vault(self, path: Path) -> dict[str, object]:
        return VaultSource.read(path).payload

    def _validate_package(self, package: dict[str, Any]) -> None:
        result = ProtectedReportPackageValidator().validate(package)
        if not result.passed:
            raise ValueError(
                "Protected report package validation failed: " + "; ".join(result.errors),
            )

    def _verify_package(
        self,
        package: dict[str, Any],
        options: ProtectedReportRestoreOptions,
    ) -> None:
        signature = package.get("signature")
        if not isinstance(signature, dict):
            raise ValueError("Protected report package signature metadata is missing.")
        if signature.get("status") == "unsigned":
            if options.allow_unsigned:
                return
            raise ValueError(
                "Protected report package is unsigned. Provide a signed package or pass --allow-unsigned for local testing.",
            )
        if options.tevari_public_key_path is None:
            raise ValueError(
                "Signed protected report packages require --tevari-public-key.",
            )
        verified = ProtectedReportPackageVerifier().verify(
            package,
            ProtectedReportVerificationOptions(
                public_key_path=options.tevari_public_key_path,
                expected_key_id=options.expected_key_id,
            ),
        )
        if not verified:
            raise ValueError("Protected report package signature verification failed.")

    def _read_recovery_key(self, path: Path | None) -> bytes | None:
        if path is None:
            return None
        return base64.b64decode(path.read_text(encoding="utf-8").strip(), validate=True)

    def _build_token_map(self, plaintext: dict[str, object]) -> dict[str, str]:
        entries = plaintext.get("entries")
        if not isinstance(entries, list):
            raise ValueError("Vault plaintext is missing token entries.")
        token_map: dict[str, str] = {}
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError("Vault token entry must be an object.")
            token = item.get("token")
            canonical_value = item.get("canonical_value")
            observed_values = item.get("observed_values", [])
            if not isinstance(token, str) or TOKEN_REFERENCE_RE.fullmatch(token) is None or not isinstance(canonical_value, str):
                raise ValueError("Vault token mapping is invalid.")
            if token in token_map:
                raise ValueError("Vault token mappings contain duplicate identities.")
            if not isinstance(observed_values, list) or any(not isinstance(value, str) for value in observed_values):
                raise ValueError("Vault observed token values are invalid.")
            restored = canonical_value
            if isinstance(observed_values, list):
                first_observed = next(
                    (value for value in observed_values if isinstance(value, str)),
                    None,
                )
                if first_observed:
                    restored = first_observed
            token_map[token] = restored
        if not token_map:
            raise ValueError("Vault plaintext contains no token mappings.")
        return token_map

    def _restore_package(
        self,
        package: dict[str, Any],
        token_map: dict[str, str],
    ) -> dict[str, Any]:
        restored_count = self._count_restorable_references(package, token_map)
        restored = self._restore_value(
            copy.deepcopy(package),
            token_map,
            path="$",
        )
        if isinstance(restored, dict):
            source_signature = package.get("signature")
            restored["restoration"] = {
                "status": "restored_locally",
                "local_restore_report_command_available": True,
                "restored_token_reference_count": restored_count,
                "restoration_strategy": "path_aware_structural_fields",
            }
            restored["signature"] = {
                "status": "restored_local_copy",
                "source_package_signature_status": (source_signature.get("status") if isinstance(source_signature, dict) else "unknown"),
                "note": (
                    "The source protected package signature was verified before "
                    "restoration when a Tevari public key was supplied. This "
                    "restored local JSON is not signed by Tevari."
                ),
            }
            return restored
        raise ValueError("Restored package must be a JSON object.")

    def _restore_value(
        self,
        value: object,
        token_map: dict[str, str],
        *,
        path: str,
    ) -> object:
        if isinstance(value, dict):
            return {
                key: self._restore_value(
                    item,
                    token_map,
                    path=f"{path}.{key}",
                )
                for key, item in value.items()
                if key != "token_references"
            }
        if isinstance(value, list):
            return [self._restore_value(item, token_map, path=f"{path}[]") for item in value]
        if isinstance(value, str):
            if not self._path_allows_restoration(path):
                return value
            if any(token not in token_map for token in TOKEN_REFERENCE_RE.findall(value)):
                raise ValueError("Protected report package contains unresolved restorable tokens.")
            return TOKEN_REFERENCE_RE.sub(
                lambda match: token_map.get(match.group(0), match.group(0)),
                value,
            )
        return value

    def _count_restorable_references(
        self,
        package: dict[str, Any],
        token_map: dict[str, str],
    ) -> int:
        return self._count_value_references(package, token_map, path="$")

    def _count_value_references(
        self,
        value: object,
        token_map: dict[str, str],
        *,
        path: str,
    ) -> int:
        if isinstance(value, dict):
            return sum(self._count_value_references(child, token_map, path=f"{path}.{key}") for key, child in value.items() if key != "token_references")
        if isinstance(value, list):
            return sum(self._count_value_references(child, token_map, path=f"{path}[]") for child in value)
        if isinstance(value, str) and self._path_allows_restoration(path):
            return sum(1 for token in TOKEN_REFERENCE_RE.findall(value) if token in token_map)
        return 0

    def _path_allows_restoration(self, path: str) -> bool:
        if path == "$.source.account_reference":
            return True
        allowed_prefixes = (
            "$.findings[].summary",
            "$.findings[].resource_references.",
            "$.findings[].evidence.",
            "$.findings[].review.",
            "$.render_model.",
            "$.render_contracts[].model.",
        )
        return any(path.startswith(prefix) for prefix in allowed_prefixes)

    def _build_audit(
        self,
        *,
        package: dict[str, Any],
        restored: dict[str, Any],
        token_map: dict[str, str],
    ) -> dict[str, object]:
        findings = restored.get("findings")
        signature = package.get("signature")
        return {
            "status": "restored",
            "package_schema_version": package.get("package_schema_version"),
            "signature_status": (signature.get("status") if isinstance(signature, dict) else "unknown"),
            "finding_count": len(findings) if isinstance(findings, list) else 0,
            "vault_token_count": len(token_map),
            "restored_token_reference_count": self._count_restorable_references(
                package,
                token_map,
            ),
            "contains_restored_values": False,
            "note": ("Audit output intentionally omits restored identifiers and vault plaintext."),
        }

    def _write_outputs(
        self,
        restored: dict[str, Any],
        *,
        package: dict[str, Any],
        audit: dict[str, object],
        options: ProtectedReportRestoreOptions,
    ) -> tuple[dict[str, Path], tuple[SecurityWarning, ...]]:
        is_v2 = package.get("package_schema_version") == PROTECTED_REPORT_PACKAGE_V2_SCHEMA_VERSION
        if is_v2 and TOKEN_REFERENCE_RE.search(json.dumps(restored.get("render_contracts"), sort_keys=True)):
            raise ValueError("Protected report package contains unresolved render-contract tokens.")
        rendered_by_relative_path = (
            CanonicalProtectedArtifactRenderer().render(restored)
            if is_v2
            else {
                "restored-report.json": (json.dumps(restored, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                "restored-report.md": ProtectedReportRenderer().render_markdown(restored).encode("utf-8"),
                "restored-report.html": ProtectedReportRenderer().render_html(restored).encode("utf-8"),
            }
        )
        if is_v2:
            RestoredTreeVerifier(TOKEN_REFERENCE_RE).verify_artifacts(rendered_by_relative_path, package)
        paths = {
            "json": options.output_dir / "restored-report.json",
            "markdown": options.output_dir / "restored-report.md",
            "html": options.output_dir / "restored-report.html",
            "audit": options.output_dir / "restoration-audit.json",
            "completion": options.output_dir / "restoration-complete.json",
        }
        for relative_path in rendered_by_relative_path:
            if relative_path not in {"restored-report.json", "restored-report.md", "restored-report.html"}:
                paths.setdefault(relative_path, options.output_dir.joinpath(*relative_path.split("/")))
        RestoredTreeVerifier(TOKEN_REFERENCE_RE).validate_output_tree(
            options.output_dir,
            tuple(paths.values()),
        )
        coordinator = ArtifactTransactionCoordinator(
            tuple(paths.values()),
            overwrite=options.overwrite,
        )
        coordinator.validate_destinations()
        writer = PrivateArtifactWriter()
        artifacts: list[PreparedArtifact] = []
        warning_details: list[SecurityWarning] = list(options.warning_details)
        with coordinator:
            try:
                for relative_path, content in rendered_by_relative_path.items():
                    role = {
                        "restored-report.json": "json",
                        "restored-report.md": "markdown",
                        "restored-report.html": "html",
                    }.get(relative_path, relative_path)
                    artifact_role = {
                        "restored-report.json": "restored_json",
                        "restored-report.md": "restored_markdown",
                        "restored-report.html": "restored_html",
                        "data/findings.csv": "restored_csv",
                        "workbooks/findings.xlsx": "restored_xlsx",
                        "diagrams/resources.mmd": "restored_mermaid",
                        "report-index.json": "restored_report_index",
                    }.get(relative_path, "restored_artifact")
                    artifact = writer.prepare(
                        paths[role],
                        content,
                        overwrite=options.overwrite,
                        artifact=artifact_role,
                        transaction_id=coordinator.transaction_id,
                    )
                    artifacts.append(artifact)
                    warning_details.extend(artifact.warning_details)
                warning_details = list(self._deduplicate_warnings(warning_details))
                audit_artifact, completion_artifact, stable_warnings = self._stage_completion_artifacts(
                    writer=writer,
                    paths=paths,
                    package=package,
                    audit=audit,
                    output_artifacts=tuple(artifacts),
                    warning_details=tuple(warning_details),
                    options=options,
                    transaction_id=coordinator.transaction_id,
                )
                warning_details = list(stable_warnings)
                artifacts.extend((audit_artifact, completion_artifact))
                ArtifactTransaction(tuple(artifacts)).commit()
            except BaseException:
                for artifact in artifacts:
                    artifact.cleanup()
                raise
        return paths, tuple(warning_details)

    def _stage_completion_artifacts(
        self,
        *,
        writer: PrivateArtifactWriter,
        paths: dict[str, Path],
        package: dict[str, Any],
        audit: dict[str, object],
        output_artifacts: tuple[PreparedArtifact, ...],
        warning_details: tuple[SecurityWarning, ...],
        options: ProtectedReportRestoreOptions,
        transaction_id: str,
    ) -> tuple[PreparedArtifact, PreparedArtifact, tuple[SecurityWarning, ...]]:
        current_warnings = warning_details
        for _attempt in range(3):
            self._add_audit_warnings(audit, list(current_warnings))
            audit_artifact = writer.prepare(
                paths["audit"],
                (json.dumps(audit, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                overwrite=options.overwrite,
                artifact="restoration_audit",
                transaction_id=transaction_id,
            )
            with_audit = self._deduplicate_warnings([*current_warnings, *audit_artifact.warning_details])
            if with_audit != current_warnings:
                audit_artifact.cleanup()
                current_warnings = with_audit
                continue
            marker_payload = build_restoration_completion(
                package=package,
                artifacts=(*output_artifacts, audit_artifact),
                warning_details=current_warnings,
                created_at=self._clock(),
            )
            try:
                completion_artifact = writer.prepare(
                    paths["completion"],
                    encode_restoration_completion(marker_payload),
                    overwrite=options.overwrite,
                    artifact="restoration_completion",
                    transaction_id=transaction_id,
                )
            except BaseException:
                audit_artifact.cleanup()
                raise
            with_completion = self._deduplicate_warnings(
                [*current_warnings, *completion_artifact.warning_details],
            )
            if with_completion == current_warnings:
                return audit_artifact, completion_artifact, current_warnings
            audit_artifact.cleanup()
            completion_artifact.cleanup()
            current_warnings = with_completion
        raise RuntimeError("Restoration permission warnings did not stabilize.")

    def _add_audit_warnings(
        self,
        audit: dict[str, object],
        warnings: list[SecurityWarning],
    ) -> None:
        audit["warnings"] = list(warning_messages(tuple(warnings)))
        audit["warning_details"] = [warning.convert_to_dict() for warning in warnings]

    def _deduplicate_warnings(
        self,
        warnings: list[SecurityWarning],
    ) -> tuple[SecurityWarning, ...]:
        return tuple(
            {
                (
                    warning.code,
                    warning.category,
                    warning.artifact,
                    warning.message,
                ): warning
                for warning in warnings
            }.values(),
        )
