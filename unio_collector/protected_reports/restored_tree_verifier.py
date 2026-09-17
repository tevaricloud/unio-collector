from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,TRY003
import json
from io import BytesIO
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

if TYPE_CHECKING:
    from pathlib import Path
    from re import Pattern


class RestoredTreeVerifier:
    """Validate canonical artifacts and their private output tree."""

    def __init__(self, token_pattern: Pattern[str]) -> None:
        """Create a verifier for the protected token format."""
        self._token_pattern = token_pattern

    def verify_artifacts(self, rendered: dict[str, bytes], package: dict[str, Any]) -> None:
        """Verify the rendered set, textual token closure, and report index."""
        manifest = package.get("artifact_manifest")
        if not isinstance(manifest, list):
            raise ValueError("Restored artifact inventory must be a list.")
        expected = self._manifest_paths(manifest)
        if set(rendered) != expected:
            raise ValueError("Restored artifact set does not match the protected manifest.")
        workbook_paths = {item["path"] for item in manifest if item.get("artifact_kind") == "xlsx"}
        for path, content in rendered.items():
            if path in workbook_paths:
                with ZipFile(BytesIO(content)) as workbook:
                    texts = [workbook.read(name).decode("utf-8") for name in workbook.namelist() if name.endswith((".xml", ".rels"))]
            else:
                texts = [content.decode("utf-8")]
            if any(self._token_pattern.search(text) for text in texts):
                raise ValueError("Restored textual output contains unresolved token references.")
        if "report-index.json" not in rendered:
            raise ValueError("Restored report index is missing.")
        index = json.loads(rendered["report-index.json"].decode("utf-8"))
        indexed = index.get("artifacts") if isinstance(index, dict) else None
        linked = self._manifest_paths(indexed)
        if linked != expected:
            raise ValueError("Restored report index does not match the generated artifact tree.")

    def _manifest_paths(self, entries: object) -> set[str]:
        if not isinstance(entries, list) or not entries:
            raise ValueError("Restored artifact inventory must be a non-empty list.")
        paths: set[str] = set()
        for item in entries:
            path = item.get("path") if isinstance(item, dict) else None
            if not isinstance(path, str) or not path or path in paths:
                raise ValueError("Restored artifact inventory contains invalid or duplicate paths.")
            paths.add(path)
        return paths

    def validate_output_tree(self, output_dir: Path, targets: tuple[Path, ...]) -> None:
        """Reject path escape through links, junctions, or reparse points."""
        if self._is_link_or_reparse_point(output_dir):
            raise ValueError("Restoration output directory must not be a link or reparse point.")
        resolved_root = output_dir.resolve(strict=False)
        lexical_root = output_dir.absolute()
        for target in targets:
            lexical_target = target.absolute()
            if (
                lexical_target == lexical_root
                or not lexical_target.is_relative_to(lexical_root)
                or not target.resolve(strict=False).is_relative_to(resolved_root)
            ):
                raise ValueError("Restoration output path escapes the selected directory.")
            current = lexical_target
            while True:
                if self._is_link_or_reparse_point(current):
                    raise ValueError("Restoration output path contains a link or reparse point.")
                if current == lexical_root:
                    break
                if current == current.parent:
                    raise ValueError("Restoration output path escapes the selected directory.")
                current = current.parent

    def _is_link_or_reparse_point(self, path: Path) -> bool:
        if not path.exists() and not path.is_symlink():
            return False
        is_junction = getattr(path, "is_junction", None)
        return path.is_symlink() or (callable(is_junction) and bool(is_junction()))
