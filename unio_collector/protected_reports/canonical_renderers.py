from __future__ import annotations  # noqa: D100

# ruff: noqa: EM101,TRY003
import csv
import io
import json
from typing import Any

from unio_collector.protected_reports.renderer import ProtectedReportRenderer
from unio_collector.protected_reports.xlsx_renderer import CanonicalProtectedXlsxRenderer


class CanonicalProtectedArtifactRenderer:
    """Regenerate allowlisted report artifacts from stable render contracts."""

    def render(self, package: dict[str, Any]) -> dict[str, bytes]:
        """Return package-v2 artifacts keyed by safe POSIX relative path."""
        contracts = package.get("render_contracts")
        artifacts = package.get("artifact_manifest")
        if not isinstance(contracts, list) or not isinstance(artifacts, list):
            raise ValueError("Protected render contracts are missing.")
        models = {
            str(item["contract_id"]): item["model"]
            for item in contracts
            if isinstance(item, dict) and isinstance(item.get("contract_id"), str) and isinstance(item.get("model"), dict)
        }
        result: dict[str, bytes] = {}
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise ValueError("Protected artifact manifest entry is invalid.")
            path = str(artifact.get("path") or "")
            kind = str(artifact.get("artifact_kind") or "")
            model = models.get(str(artifact.get("render_contract_id") or ""))
            if model is None:
                raise ValueError("Protected artifact references an unavailable render contract.")
            result[path] = self._render_artifact(kind, model, package, artifacts)
        return result

    def _render_artifact(
        self,
        kind: str,
        model: dict[str, Any],
        package: dict[str, Any],
        artifacts: list[object],
    ) -> bytes:
        if kind == "json":
            restored_json = dict(model)
            restored_json["signature"] = package.get("signature")
            restored_json["restoration"] = package.get("restoration")
            return self._json(restored_json)
        if kind in {"markdown", "html"}:
            render_package = dict(package)
            render_package.update(model)
            renderer = ProtectedReportRenderer()
            text = renderer.render_markdown(render_package) if kind == "markdown" else renderer.render_html(render_package)
            return text.encode("utf-8")
        if kind == "csv":
            return self._csv(model)
        if kind == "xlsx":
            return self._xlsx(model)
        if kind == "mermaid":
            return self._mermaid(model).encode("utf-8")
        if kind == "report_index":
            items = [
                {
                    "path": item.get("path"),
                    "artifact_kind": item.get("artifact_kind"),
                    "media_type": item.get("media_type"),
                }
                for item in artifacts
                if isinstance(item, dict)
            ]
            return self._json({"schema_version": "2026-08-restored-report-index-v1", "artifacts": items})
        raise ValueError("Protected artifact renderer is unsupported.")

    def _json(self, value: object) -> bytes:
        return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")

    def _csv(self, model: dict[str, Any]) -> bytes:
        columns = self._string_row(model.get("columns"))
        rows = model.get("rows")
        if not isinstance(rows, list):
            raise ValueError("Protected table rows are invalid.")
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(self._safe_spreadsheet_row(columns))
        for row in rows:
            writer.writerow(self._safe_spreadsheet_row(self._string_row(row)))
        return output.getvalue().encode("utf-8")

    def _xlsx(self, model: dict[str, Any]) -> bytes:
        columns = tuple(self._string_row(model.get("columns")))
        raw_rows = model.get("rows")
        if not isinstance(raw_rows, list):
            raise ValueError("Protected workbook rows are invalid.")
        rows = (columns, *(tuple(self._safe_spreadsheet_row(self._string_row(row))) for row in raw_rows))
        return CanonicalProtectedXlsxRenderer().render(rows)

    def _mermaid(self, model: dict[str, Any]) -> str:
        if model.get("diagram_type") != "flowchart" or model.get("direction") not in {"TD", "LR"}:
            raise ValueError("Protected Mermaid contract is invalid.")
        lines = [f"flowchart {model['direction']}"]
        nodes = model.get("nodes")
        edges = model.get("edges")
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise ValueError("Protected Mermaid graph is invalid.")
        node_ids: set[str] = set()
        for node in nodes:
            if not isinstance(node, dict):
                raise ValueError("Protected Mermaid node is invalid.")
            node_id = str(node.get("id") or "")
            if not node_id.isalnum() or node_id in node_ids:
                raise ValueError("Protected Mermaid node id is invalid.")
            node_ids.add(node_id)
            label = self._mermaid_text(f"{node.get('label') or ''}: {node.get('reference') or ''}")
            lines.append(f'  {node_id}["{label}"]')
        for edge in edges:
            if not isinstance(edge, dict) or edge.get("source") not in node_ids or edge.get("target") not in node_ids:
                raise ValueError("Protected Mermaid edge is invalid.")
            lines.append(f"  {edge['source']} --> {edge['target']}")
        return "\n".join(lines) + "\n"

    def _string_row(self, value: object) -> list[str]:
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError("Protected table row must contain strings only.")
        return list(value)

    def _safe_spreadsheet_row(self, row: list[str]) -> list[str]:
        return [f"'{value}" if value.startswith(("=", "+", "-", "@")) else value for value in row]

    def _mermaid_text(self, value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', "'").replace("\r", " ").replace("\n", " ")
