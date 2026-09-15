from __future__ import annotations  # noqa: D100


def render_print_action() -> str:
    """Return the self-contained browser print control shared by HTML reports."""
    return (
        '<aside class="report-actions" aria-label="Report actions">'
        '<button class="print-action" type="button" onclick="window.print()" '
        'aria-label="Print or save this report as a PDF">'
        "Print / Save as PDF"
        "</button>"
        "</aside>"
    )


__all__ = ["render_print_action"]
