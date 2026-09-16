# ruff: noqa: D100, E501
from __future__ import annotations

from html import escape
from typing import Any

from unio_collector.core.html_theme import render_html_theme_tokens
from unio_collector.core.print_action import render_print_action


class ProtectedReportRenderer:
    """Render restored protected report packages without internal report imports."""

    def render_markdown(self, package: dict[str, Any]) -> str:
        """Render a local Markdown report from restored structured findings."""
        lines = [
            "# Restored Unio Report",
            "",
            f"Package schema: {self._markdown_text(package.get('package_schema_version'))}",
            f"Account reference: {self._markdown_text(self._source_value(package, 'account_reference'))}",
            f"Provider: {self._markdown_text(self._source_value(package, 'provider'))}",
            f"Findings: {self._markdown_text(self._summary_value(package, 'finding_count'))}",
            f"Total cost: {self._markdown_text(self._summary_value(package, 'total_cost'))} {self._markdown_text(self._summary_value(package, 'currency'))}",
            "",
            *self._render_savings_markdown(package),
            "## Findings",
            "",
        ]
        findings = package.get("findings")
        if not isinstance(findings, list) or not findings:
            lines.append("No findings recorded.")
            return "\n".join(lines) + "\n"
        for index, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                continue
            lines.extend(self._render_markdown_finding(index, finding))
        return "\n".join(lines) + "\n"

    def render_html(self, package: dict[str, Any]) -> str:
        """Render a local HTML report from restored structured findings."""
        findings = package.get("findings")
        finding_items = ""
        if isinstance(findings, list):
            finding_items = "\n".join(self._render_html_finding(index, finding) for index, finding in enumerate(findings, start=1) if isinstance(finding, dict))
        if not finding_items:
            finding_items = "<p>No findings recorded.</p>"
        return "\n".join(
            [
                "<!doctype html>",
                '<html lang="en">',
                "<head>",
                '  <meta charset="utf-8">',
                '  <meta name="viewport" content="width=device-width, initial-scale=1">',
                "  <title>Restored Unio Report</title>",
                "  <style>",
                self._render_css(),
                "  </style>",
                "</head>",
                "<body>",
                '  <a class="skip-link" href="#main-content">Skip to main content</a>',
                '  <div class="report-shell">',
                '  <header class="report-header">',
                '    <div class="report-brand-rail" aria-hidden="true"></div>',
                '    <div class="report-hero-content">',
                '      <p class="report-brand-lockup"><span>Tevari Cloud</span><strong>Unio</strong></p>',
                '      <p class="report-pack-label">Protected report restoration</p>',
                "      <h1>Restored Unio Report</h1>",
                '      <aside class="report-metadata-band" aria-label="Report metadata">',
                f"        <span><strong>Package schema:</strong> {escape(str(package.get('package_schema_version') or 'unknown'))}</span>",
                f"        <span><strong>Account reference:</strong> {escape(str(self._source_value(package, 'account_reference')))}</span>",
                f"        <span><strong>Provider:</strong> {escape(str(self._source_value(package, 'provider')))}</span>",
                f"        <span><strong>Findings:</strong> {escape(str(self._summary_value(package, 'finding_count')))}</span>",
                "      </aside>",
                "    </div>",
                "  </header>",
                f"  {render_print_action()}",
                '  <main id="main-content">',
                self._render_savings_html(package),
                "  <h2>Findings</h2>",
                finding_items,
                "  </main>",
                "  </div>",
                "</body>",
                "</html>",
                "",
            ],
        )

    def _render_css(self) -> str:
        return (
            render_html_theme_tokens()
            + """
*{box-sizing:border-box}
body{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.6;margin:0;background:var(--color-bg-page);color:var(--color-text-primary)}
.skip-link{position:absolute;left:-999px;top:8px;background:var(--color-text-strong);color:var(--color-cta-primary-text);padding:8px 12px;border-radius:6px;z-index:10}.skip-link:focus{left:8px}
.report-shell{max-width:1040px;margin:0 auto;padding:28px}
.report-header{display:grid;grid-template-columns:10px minmax(0,1fr);overflow:hidden;background:var(--color-surface-hero);border:1px solid var(--color-border-soft);border-radius:16px;margin-bottom:24px}
.report-brand-rail{background:linear-gradient(180deg,var(--color-brand-teal),var(--color-brand-cyan))}
.report-hero-content{padding:28px 30px}
.report-brand-lockup{display:flex;align-items:center;gap:10px;color:var(--color-brand-teal);font-size:13px;font-weight:650;letter-spacing:.04em;margin:0 0 20px;text-transform:uppercase}.report-brand-lockup strong{border-left:1px solid var(--color-brand-cyan-soft);color:var(--color-text-strong);font-size:15px;letter-spacing:.12em;padding-left:10px}
.report-pack-label{color:var(--color-text-muted);font-size:13px;font-weight:650;letter-spacing:.04em;margin:0 0 5px;text-transform:uppercase}
h1{color:var(--color-text-strong);font-size:clamp(30px,4vw,44px);letter-spacing:-.025em;line-height:1.12;margin:0 0 18px}
.report-metadata-band{display:flex;flex-wrap:wrap;gap:8px}.report-metadata-band span{border:1px solid var(--color-border-soft);background:var(--color-surface-primary);border-radius:999px;padding:6px 10px;font-size:12px;color:var(--color-text-secondary)}
.report-actions{display:flex;justify-content:flex-end;margin:0 0 18px}.print-action{appearance:none;background:var(--color-cta-primary);border:1px solid var(--color-cta-primary);border-radius:8px;color:var(--color-cta-primary-text);cursor:pointer;font:inherit;font-weight:700;padding:9px 14px}.print-action:hover{background:var(--color-cta-hover)}.print-action:focus-visible{outline:3px solid var(--color-cta-primary);outline-offset:2px}
h2,h3,h4{color:var(--color-text-strong);line-height:1.25}a:focus-visible{outline:3px solid var(--color-cta-primary);outline-offset:2px}
article{background:var(--color-surface-primary);border:1px solid var(--color-border-soft);border-left:5px solid var(--color-brand-teal);border-radius:12px;padding:18px 20px;margin:16px 0}
table{border-collapse:separate;border-spacing:0;width:100%;margin:.75rem 0;font-size:13px}th,td{border-right:1px solid var(--color-border-soft);border-bottom:1px solid var(--color-border-soft);padding:8px 10px;text-align:left;vertical-align:top}th:first-child,td:first-child{border-left:1px solid var(--color-border-soft)}tr:first-child th,tr:first-child td{border-top:1px solid var(--color-border-soft)}th{background:var(--color-bg-section);color:var(--color-text-strong);width:34%}
code{background:var(--color-bg-section);color:var(--color-text-strong);padding:2px 5px;border-radius:4px}
@media(max-width:720px){body{overflow-x:hidden}.report-shell{max-width:100%;padding:14px}.report-hero-content{min-width:0;padding:22px 18px}.report-metadata-band span{width:100%}article{padding:16px 14px}table{display:block;max-width:100%;overflow-x:auto}th,td{overflow-wrap:anywhere}}
@media print{body{background:var(--color-surface-primary)}.skip-link,.report-actions,.print-action{display:none!important}.report-shell{max-width:none;padding:0}.report-header{border-radius:0}article,tr{break-inside:avoid;page-break-inside:avoid}h1,h2,h3,h4{break-after:avoid;page-break-after:avoid}thead{display:table-header-group}tfoot{display:table-footer-group}table{page-break-inside:auto}}
"""
        ).strip()

    def _render_savings_markdown(self, package: dict[str, Any]) -> list[str]:
        metric = self._savings_metric(package)
        if not metric:
            return []
        baseline = metric.get("baseline")
        baseline_payload = baseline if isinstance(baseline, dict) else {}
        period = baseline_payload.get("period")
        period_payload = period if isinstance(period, dict) else {}
        percentage = self._percentage_or_explanation(metric)
        return [
            "## Known Savings And Completed-Month AWS Spend",
            "",
            f"Percentage or status: {self._markdown_text(percentage)}",
            f"Completed-month period: {self._markdown_text(self._period_text(period_payload))}",
            f"Completed-month spend: {self._markdown_text(self._baseline_amount_text(baseline_payload))}",
            f"Evidence source: {self._markdown_text(self._baseline_source_text(baseline_payload))}",
            *[f"Limitation: {self._markdown_text(item)}" for item in self._limitations(metric)],
            "",
        ]

    def _render_savings_html(self, package: dict[str, Any]) -> str:
        metric = self._savings_metric(package)
        if not metric:
            return ""
        baseline = metric.get("baseline")
        baseline_payload = baseline if isinstance(baseline, dict) else {}
        period = baseline_payload.get("period")
        period_payload = period if isinstance(period, dict) else {}
        limitations = self._limitations(metric)
        limitations_html = ""
        if limitations:
            limitations_html = "<h3>Limitations</h3><ul>" + "".join(f"<li>{escape(item)}</li>" for item in limitations) + "</ul>"
        rows = (
            ("Percentage or status", self._percentage_or_explanation(metric)),
            ("Completed-month period", self._period_text(period_payload)),
            ("Completed-month spend", self._baseline_amount_text(baseline_payload)),
            ("Evidence source", self._baseline_source_text(baseline_payload)),
        )
        rendered_rows = "".join(f"<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>" for label, value in rows)
        return (
            '<section class="savings-percentage">'
            "<h2>Known Savings And Completed-Month AWS Spend</h2>"
            f"<table><tbody>{rendered_rows}</tbody></table>{limitations_html}"
            "</section>"
        )

    def _savings_metric(self, package: dict[str, Any]) -> dict[str, Any]:
        summary = package.get("summary")
        if not isinstance(summary, dict):
            return {}
        metric = summary.get("known_savings_spend_percentage")
        return dict(metric) if isinstance(metric, dict) else {}

    def _percentage_or_explanation(self, metric: dict[str, Any]) -> str:
        if metric.get("status") == "calculated" and metric.get("percentage") is not None:
            return f"{metric['percentage']}%"
        return str(metric.get("explanation") or "Not calculated")

    def _period_text(self, period: dict[str, Any]) -> str:
        start = period.get("start_date")
        end = period.get("end_date_exclusive")
        return f"{start} to {end} (exclusive end)" if start and end else "not available"

    def _baseline_amount_text(self, baseline: dict[str, Any]) -> str:
        amount = baseline.get("amount")
        currency = baseline.get("currency")
        return f"{amount} {currency}" if amount is not None and currency else "not available"

    def _baseline_source_text(self, baseline: dict[str, Any]) -> str:
        source = baseline.get("source")
        details = ", ".join(str(item) for item in (baseline.get("api_operation"), baseline.get("metric")) if item)
        if not source:
            return "not available"
        return f"{source} ({details})" if details else str(source)

    def _limitations(self, metric: dict[str, Any]) -> list[str]:
        limitations = metric.get("limitations")
        if not isinstance(limitations, list):
            return []
        return [str(item) for item in limitations]

    def _render_markdown_finding(
        self,
        index: int,
        finding: dict[str, Any],
    ) -> list[str]:
        lines = [
            f"### {index}. {self._markdown_text(finding.get('summary'))}",
            "",
            f"- Service: {self._markdown_text(finding.get('service'))}",
            f"- Region: {self._markdown_text(finding.get('region'))}",
            f"- Severity: {self._markdown_text(finding.get('severity'))}",
            f"- Risk: {self._markdown_text(finding.get('risk_level'))}",
            f"- Estimated monthly saving: {self._markdown_text(finding.get('estimated_monthly_saving'))}",
        ]
        resource_references = finding.get("resource_references")
        if isinstance(resource_references, dict) and resource_references:
            lines.extend(["", "Resource references:"])
            lines.extend(f"- {self._markdown_text(key)}: {self._markdown_text(value)}" for key, value in sorted(resource_references.items()))
        evidence = finding.get("evidence")
        if isinstance(evidence, dict):
            lines.extend(self._markdown_list("Facts", evidence.get("facts")))
            lines.extend(
                self._markdown_list(
                    "Direct evidence",
                    evidence.get("direct_evidence"),
                ),
            )
        review = finding.get("review")
        if isinstance(review, dict):
            lines.extend(
                self._markdown_list(
                    "Suggested actions",
                    review.get("suggested_actions"),
                ),
            )
            lines.extend(self._markdown_list("Safe checks", review.get("safe_checks")))
        lines.append("")
        return lines

    def _render_html_finding(
        self,
        index: int,
        finding: dict[str, Any],
    ) -> str:
        rows = [
            ("Service", finding.get("service")),
            ("Region", finding.get("region")),
            ("Severity", finding.get("severity")),
            ("Risk", finding.get("risk_level")),
            ("Estimated monthly saving", finding.get("estimated_monthly_saving")),
        ]
        resource_references = finding.get("resource_references")
        if isinstance(resource_references, dict):
            rows.extend((f"Resource {key}", value) for key, value in sorted(resource_references.items()))
        rendered_rows = "\n".join(f"      <tr><th>{escape(str(label))}</th><td>{escape(str(value or 'not recorded'))}</td></tr>" for label, value in rows)
        body = [
            f"  <article><h3>{index}. {escape(str(finding.get('summary') or 'Finding'))}</h3>",
            "    <table>",
            rendered_rows,
            "    </table>",
        ]
        evidence = finding.get("evidence")
        if isinstance(evidence, dict):
            body.append(self._html_list("Facts", evidence.get("facts")))
            body.append(self._html_list("Direct evidence", evidence.get("direct_evidence")))
        review = finding.get("review")
        if isinstance(review, dict):
            body.append(
                self._html_list(
                    "Suggested actions",
                    review.get("suggested_actions"),
                ),
            )
            body.append(self._html_list("Safe checks", review.get("safe_checks")))
        body.append("  </article>")
        return "\n".join(body)

    def _markdown_list(self, title: str, values: object) -> list[str]:
        if not isinstance(values, list) or not values:
            return []
        return [
            "",
            f"{title}:",
            *[f"- {self._markdown_text(value)}" for value in values],
        ]

    def _html_list(self, title: str, values: object) -> str:
        if not isinstance(values, list) or not values:
            return ""
        items = "".join(f"<li>{escape(str(value))}</li>" for value in values)
        return f"    <h4>{escape(title)}</h4><ul>{items}</ul>"

    def _summary_value(self, package: dict[str, Any], key: str) -> object:
        summary = package.get("summary")
        if isinstance(summary, dict):
            return summary.get(key, "not recorded")
        return "not recorded"

    def _source_value(self, package: dict[str, Any], key: str) -> object:
        source = package.get("source")
        if isinstance(source, dict):
            return source.get(key, "not recorded")
        return "not recorded"

    def _markdown_text(self, value: object) -> str:
        text = str(value if value is not None else "not recorded")
        text = text.replace("\\", "\\\\")
        text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        for character in ("`", "[", "]", "(", ")", "|", "#", "*", "_", "!", "+", "-", "."):
            text = text.replace(character, f"\\{character}")
        return text
