"""Deterministic byte identity for pristine standalone source exports."""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any, cast

from tools.collector_repository.artifacts import PublicAssistantArtifactPolicy
from tools.collector_repository.naming import TRANSFORMATION_VERSION, PublicNamingValidator
from tools.collector_repository.paths import regular_file, relative_path, repository_files, require

if TYPE_CHECKING:
    from pathlib import Path

MANIFEST_NAME = "export-manifest.json"
PROVENANCE_NAME = "export-provenance.json"
IDENTITY_NAMES = frozenset({MANIFEST_NAME, PROVENANCE_NAME})
SCHEMA_VERSION = "2026-09-collector-repository-v2"
CATEGORIES = ("collector_source", "repository_metadata", "tests", "other_assets")
LICENCE_NAME = "Tevari Cloud Unio Collector Source-Available License"
LICENCE_VERSION = "1.0"
LICENCE_SHA256 = "f8c4a34dda929a36c2688f06a80384a855f609d9dabc077aa6cb698d6f578f2d"


def canonical_json(value: object) -> bytes:
    """Encode deterministic UTF-8 JSON, without timestamps."""
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def sha256(content: bytes) -> str:
    """Hash actual bytes without decoding or normalisation."""
    return hashlib.sha256(content).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    """Read an object, rejecting duplicate JSON keys."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key.")
            result[key] = value
        return result

    value = json.loads(path.read_bytes(), object_pairs_hook=unique)
    require(isinstance(value, dict), "Expected a JSON object.")
    return cast("dict[str, Any]", value)


class RepositoryIdentity:
    """Write and independently verify an export's exact byte inventory."""

    def write(self, root: Path, categories: dict[str, str], provenance: dict[str, object]) -> dict[str, object]:
        """Bind payload and provenance without circular self-hashes."""
        require(not IDENTITY_NAMES.intersection(categories), "Reserved identity path in payload.")
        require(set(repository_files(root)) == set(categories), "Payload differs from the approved repository file set.")
        records = [self._record(root, name, categories[name]) for name in sorted(categories)]
        counts = {category: sum(item["category"] == category for item in records) for category in CATEGORIES}
        counts["repository_metadata"] += len(IDENTITY_NAMES)
        tree_digest = sha256(canonical_json(records))
        manifest = {"schema_version": SCHEMA_VERSION, "tree_digest": tree_digest, "files": records}
        manifest_bytes = canonical_json(manifest)
        identity = {
            **provenance,
            "schema_version": SCHEMA_VERSION,
            "generation_tool_version": SCHEMA_VERSION,
            "tree_digest": tree_digest,
            "manifest_sha256": sha256(manifest_bytes),
            "counts": counts,
            "file_count": len(records) + len(IDENTITY_NAMES),
        }
        (root / MANIFEST_NAME).write_bytes(manifest_bytes)
        (root / PROVENANCE_NAME).write_bytes(canonical_json(identity))
        return self.verify(root)

    def verify(self, root: Path) -> dict[str, object]:
        """Reject missing, unexpected, changed or ambiguous export files."""
        from tools.collector_repository.comments import PublicCommentPolicy  # noqa: PLC0415

        PublicAssistantArtifactPolicy().validate(root)
        PublicNamingValidator().validate(root)
        PublicCommentPolicy().validate(root)
        manifest = read_json(regular_file(root, MANIFEST_NAME))
        provenance = read_json(regular_file(root, PROVENANCE_NAME))
        require(set(manifest) == {"schema_version", "tree_digest", "files"}, "Unexpected manifest fields.")
        require(manifest["schema_version"] == SCHEMA_VERSION, "Unsupported manifest schema.")
        self._provenance(provenance)
        records = manifest["files"]
        require(isinstance(records, list), "Invalid manifest records.")
        paths: list[str] = []
        counts = dict.fromkeys(CATEGORIES, 0)
        for record in records:
            require(isinstance(record, dict) and set(record) == {"path", "category", "size", "sha256"}, "Invalid manifest file record.")
            name = record["path"]
            require(isinstance(name, str) and name not in IDENTITY_NAMES, "Invalid payload path.")
            relative_path(name)
            require(record["category"] in CATEGORIES, "Invalid file category.")
            require(type(record["size"]) is int and record["size"] >= 0, "Invalid file size.")
            require(record == self._record(root, name, record["category"]), f"Export bytes differ from manifest: {name}.")
            paths.append(name)
            counts[record["category"]] += 1
        require(paths == sorted(set(paths)), "Manifest paths must be unique and sorted.")
        require("LICENSE" in paths, "Missing approved LICENSE in manifest.")
        require(sha256(regular_file(root, "LICENSE").read_bytes()) == LICENCE_SHA256, "Altered approved LICENSE.")
        require(set(repository_files(root)) == {*paths, *IDENTITY_NAMES}, "Missing or unexpected repository files.")
        digest = sha256(canonical_json(records))
        require(manifest["tree_digest"] == provenance["tree_digest"] == digest, "Export tree digest mismatch.")
        require(provenance["manifest_sha256"] == sha256((root / MANIFEST_NAME).read_bytes()), "Manifest identity mismatch.")
        counts["repository_metadata"] += len(IDENTITY_NAMES)
        require(provenance["counts"] == counts and provenance["file_count"] == len(paths) + len(IDENTITY_NAMES), "Export counts mismatch.")
        return dict(provenance)

    def _record(self, root: Path, name: str, category: str) -> dict[str, object]:
        require(category in CATEGORIES, "Unknown payload category.")
        content = regular_file(root, name).read_bytes()
        return {"path": name, "category": category, "size": len(content), "sha256": sha256(content)}

    def _provenance(self, value: dict[str, Any]) -> None:
        expected = {
            "schema_version",
            "generation_tool_version",
            "source_repository",
            "source_sha",
            "source_git_tree",
            "source_state_clean",
            "publication_ready",
            "policy_schema_version",
            "policy_sha256",
            "envelope_policy_version",
            "envelope_policy_sha256",
            "package_plan_version",
            "publication_transformation_version",
            "publication_transformation_sha256",
            "source_byte_identity",
            "licence_status",
            "licence_name",
            "licence_version",
            "tree_digest",
            "manifest_sha256",
            "counts",
            "file_count",
        }
        require(set(value) in (expected, expected | {"sensitive_data_validation"}), "Unexpected provenance fields.")
        if "sensitive_data_validation" in value:
            from tools.collector_repository.secrets import CONFIG_SHA256, GITLEAKS_VERSION  # noqa: PLC0415

            require(
                value["sensitive_data_validation"]
                == {
                    "project_disclosure": "clean",
                    "gitleaks": "clean",
                    "gitleaks_version": GITLEAKS_VERSION,
                    "gitleaks_config_sha256": CONFIG_SHA256,
                },
                "Invalid sensitive-data publication attestation.",
            )
        require(value["schema_version"] == value["generation_tool_version"] == SCHEMA_VERSION, "Unsupported provenance schema.")
        require(value["source_repository"] == "tevari-cloud/unio-private-source", "Unknown source repository identity.")
        require(value["source_state_clean"] is True and value["publication_ready"] is True, "Export provenance is not publication-ready.")
        require(
            value["publication_transformation_version"] == TRANSFORMATION_VERSION and value["source_byte_identity"] is False,
            "Unsupported publication transformation identity.",
        )
        for key in ("source_sha", "source_git_tree"):
            require(isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{40}", value[key]) is not None, "Invalid Git identity.")
        for key in ("policy_sha256", "envelope_policy_sha256", "publication_transformation_sha256", "tree_digest", "manifest_sha256"):
            require(isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{64}", value[key]) is not None, "Invalid provenance digest.")
        require(value["licence_status"] == "approved", "Export licence is not user-approved.")
        require(value["licence_name"] == LICENCE_NAME and value["licence_version"] == LICENCE_VERSION, "Invalid approved licence metadata.")
        for key in ("policy_schema_version", "envelope_policy_version", "package_plan_version"):
            require(isinstance(value[key], str) and bool(value[key]), "Missing provenance schema version.")
