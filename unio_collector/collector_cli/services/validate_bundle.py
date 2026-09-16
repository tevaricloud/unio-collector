from __future__ import annotations  # noqa: D100

import json
from pathlib import Path
from typing import Any
from zipfile import ZipFile

from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.collector.summary import build_bundle_collection_summary


class CollectorValidateBundleService:
    """Validate evidence bundles using collector-safe components."""

    def __init__(self, console: Any) -> None:  # noqa: ANN401
        """Store the output console."""
        self.console = console

    def run(self, args: object) -> int:
        """Validate an evidence bundle path."""
        bundle_path = Path(str(getattr(args, "bundle", "")))
        result = EvidenceBundleValidator().validate(bundle_path)
        if not result.passed:
            self.console.print("Evidence bundle validation failed.")
            for error in result.errors:
                self.console.print(f"- {error}")
            return 1
        with ZipFile(bundle_path, "r") as archive:
            manifest = self._read_json(archive, "manifest.json")
            collection_summary = self._read_json(
                archive,
                "collection-summary.json",
            )
            analysis_contract = self._read_json(
                archive,
                "analysis-contract.json",
            )
            strict_analysis_readiness = self._read_json(
                archive,
                "analysis-readiness.json",
            )
            signature_metadata = self._read_json(archive, "signature.json")
        summary = build_bundle_collection_summary(
            manifest,
            collection_summary=collection_summary,
            analysis_contract=analysis_contract,
            strict_analysis_readiness=strict_analysis_readiness,
            signature_metadata=signature_metadata,
        )
        self.console.print("Evidence bundle validation passed.")
        self.console.print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    def _read_json(self, archive: ZipFile, name: str) -> dict[str, Any]:
        if name == "analysis-readiness.json" and name not in archive.namelist():
            return {}
        return json.loads(archive.read(name).decode("utf-8"))


__all__ = ["CollectorValidateBundleService"]
