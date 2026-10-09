"""Recognize fixed bundle protocol paths without exempting customer paths or values."""

from __future__ import annotations

import re
from typing import Any

from unio_collector.collector.bundle.schema import OPTIONAL_BUNDLE_FILES, PROTECTED_PRIVACY_FILES, REQUIRED_BUNDLE_FILES, SERVICE_EVIDENCE_FILES

FIXED_BUNDLE_PATHS = frozenset((*REQUIRED_BUNDLE_FILES, *OPTIONAL_BUNDLE_FILES, *PROTECTED_PRIVACY_FILES))
PROTOCOL_MEMBERS = frozenset({"bundle-schema.json", "manifest.json", "checksums.json", *SERVICE_EVIDENCE_FILES})
SHA256 = re.compile(r"[0-9a-f]{64}")


def mask_protocol_references(member: str, document: dict[str, Any]) -> None:
    """Only fixed file references and exact producer service labels are public literals."""
    list_fields = (
        ("required_files", "optional_files", "service_evidence_files")
        if member == "bundle-schema.json"
        else ("evidence_files",)
        if member == "manifest.json"
        else ()
    )
    for field in list_fields:
        value = document.get(field)
        if isinstance(value, list):
            document[field] = ["" if isinstance(v, str) and v in FIXED_BUNDLE_PATHS else v for v in value]
    if member in {"manifest.json", "checksums.json"}:
        checksums = document.get("checksums")
        if isinstance(checksums, dict):
            document["checksums"] = [
                ["" if key in FIXED_BUNDLE_PATHS and isinstance(value, str) and SHA256.fullmatch(value) else key, value] for key, value in checksums.items()
            ]
    if member in SERVICE_EVIDENCE_FILES and document.get("service") == member.removeprefix("evidence/").removesuffix(".json"):
        document["service"] = ""
