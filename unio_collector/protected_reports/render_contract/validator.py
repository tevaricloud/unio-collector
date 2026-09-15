from __future__ import annotations  # noqa: D100

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any

from unio_collector.protected_reports.constants import (
    PROTECTED_RENDER_DIAGRAM_VERSION,
    PROTECTED_RENDER_REPORT_VERSION,
    PROTECTED_RENDER_TABLE_VERSION,
)

_SUPPORTED_CONTRACTS = {
    PROTECTED_RENDER_REPORT_VERSION,
    PROTECTED_RENDER_TABLE_VERSION,
    PROTECTED_RENDER_DIAGRAM_VERSION,
}
_SUPPORTED_KINDS = {"json", "markdown", "html", "csv", "xlsx", "report_index", "mermaid"}
_CONTRACT_KIND_PAIRS = {
    PROTECTED_RENDER_REPORT_VERSION: {"json", "markdown", "html", "report_index"},
    PROTECTED_RENDER_TABLE_VERSION: {"csv", "xlsx"},
    PROTECTED_RENDER_DIAGRAM_VERSION: {"mermaid"},
}
_RESERVED_WINDOWS_NAMES = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.IGNORECASE)
_FORBIDDEN_MODEL_KEYS = {"__class__", "callable", "module", "pickle", "python_type", "template_instance", "writer_state"}
_FIRST_PRINTABLE_CHARACTER = 32


class ProtectedRenderContractValidator:
    """Validate package-v2 render contracts independently of report writers."""

    def validate(self, payload: dict[str, Any]) -> list[str]:  # noqa: C901
        """Return safe validation errors for render contracts and paths."""
        errors: list[str] = []
        contracts = payload.get("render_contracts")
        artifacts = payload.get("artifact_manifest")
        if not isinstance(contracts, list):
            return ["render_contracts must be a list."]
        if not isinstance(artifacts, list):
            return ["artifact_manifest must be a list."]
        contract_ids: set[str] = set()
        contracts_by_id: dict[str, dict[str, Any]] = {}
        for contract in contracts:
            if not isinstance(contract, dict):
                errors.append("render contract must be an object.")
                continue
            contract_id = contract.get("contract_id")
            version = contract.get("contract_schema_version")
            model = contract.get("model")
            if not isinstance(contract_id, str) or not contract_id or contract_id in contract_ids:
                errors.append("render contract id is missing or duplicated.")
                continue
            contract_ids.add(contract_id)
            contracts_by_id[contract_id] = contract
            if not isinstance(version, str) or version not in _SUPPORTED_CONTRACTS:
                errors.append("render contract schema version is unsupported.")
            if not isinstance(model, dict):
                errors.append("render contract model must be an object.")
                continue
            try:
                encoded = json.dumps(model, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            except (TypeError, ValueError, UnicodeError, RecursionError):
                errors.append("render contract model must contain finite JSON values.")
                continue
            if contract.get("model_sha256") != hashlib.sha256(encoded).hexdigest():
                errors.append("render contract model hash does not match.")
            self._validate_model(model, errors)
        seen_paths: set[str] = set()
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                errors.append("artifact manifest entry must be an object.")
                continue
            path = artifact.get("path")
            if not isinstance(path, str) or not self._safe_path(path):
                errors.append("artifact path is unsafe or invalid.")
            elif path.casefold() in seen_paths:
                errors.append("artifact paths collide case-insensitively.")
            else:
                seen_paths.add(path.casefold())
            artifact_kind = artifact.get("artifact_kind")
            if not isinstance(artifact_kind, str) or artifact_kind not in _SUPPORTED_KINDS:
                errors.append("artifact kind is unsupported.")
            contract_id = artifact.get("render_contract_id")
            if not isinstance(contract_id, str) or contract_id not in contract_ids:
                errors.append("artifact references an unknown render contract.")
                continue
            contract = contracts_by_id[str(contract_id)]
            version = contract.get("contract_schema_version")
            if artifact.get("render_contract_schema_version") != version:
                errors.append("artifact render-contract version does not match.")
            if artifact.get("model_sha256") != contract.get("model_sha256"):
                errors.append("artifact render-contract model hash does not match.")
            if not isinstance(artifact_kind, str) or artifact_kind not in _CONTRACT_KIND_PAIRS.get(str(version), set()):
                errors.append("artifact kind is incompatible with its render contract.")
        return errors

    def _safe_path(self, value: str) -> bool:
        if not value or any(ord(char) < _FIRST_PRINTABLE_CHARACTER or char in '\\:<>"|?*\x7f' for char in value) or value.startswith("/"):
            return False
        path = PurePosixPath(value)
        if not path.parts or any(part in {"", ".", ".."} or part.endswith((".", " ")) or _RESERVED_WINDOWS_NAMES.match(part) for part in path.parts):
            return False
        return str(path) == value

    def _validate_model(self, value: object, errors: list[str]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    errors.append("render contract model keys must be strings.")
                if str(key).casefold() in _FORBIDDEN_MODEL_KEYS:
                    errors.append("render contract contains forbidden writer-internal state.")
                self._validate_model(child, errors)
        elif isinstance(value, list):
            for child in value:
                self._validate_model(child, errors)
        elif not isinstance(value, str | int | float | bool | type(None)):
            errors.append("render contract contains a non-JSON value.")
