from __future__ import annotations  # noqa: D100

import io
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


class CanonicalProtectedXlsxRenderer:
    """Render one text-only XLSX worksheet without report-layer imports."""

    def render(self, rows: tuple[tuple[str, ...], ...]) -> bytes:
        """Return a deterministic minimal XLSX archive."""
        output = io.BytesIO()
        members = (
            ("[Content_Types].xml", self._content_types()),
            ("_rels/.rels", self._root_relationships()),
            ("xl/workbook.xml", self._workbook()),
            ("xl/_rels/workbook.xml.rels", self._workbook_relationships()),
            ("xl/styles.xml", self._styles()),
            ("xl/worksheets/sheet1.xml", self._worksheet(rows)),
        )
        with ZipFile(output, "w", compression=ZIP_DEFLATED) as workbook:
            for name, text in members:
                member = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                member.compress_type = ZIP_DEFLATED
                member.create_system = 3
                member.external_attr = 0o600 << 16
                workbook.writestr(member, text)
        return output.getvalue()

    def _content_types(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            "</Types>"
        )

    def _root_relationships(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            "</Relationships>"
        )

    def _workbook(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Findings" sheetId="1" r:id="rId1"/></sheets>'
            "</workbook>"
        )

    def _workbook_relationships(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            "</Relationships>"
        )

    def _styles(self) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<fonts count="2"><font><sz val="11"/></font><font><b/><sz val="11"/></font></fonts>'
            '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>'
            '<borders count="1"><border/></borders>'
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
            '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
            "</styleSheet>"
        )

    def _worksheet(self, rows: tuple[tuple[str, ...], ...]) -> str:
        rendered_rows = "".join(self._row(row, index) for index, row in enumerate(rows, start=1))
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" state="frozen"/></sheetView></sheetViews>'
            f"<sheetData>{rendered_rows}</sheetData></worksheet>"
        )

    def _row(self, row: tuple[str, ...], row_number: int) -> str:
        cells = "".join(
            f'<c r="{self._column(column)}{row_number}"{self._style(row_number)} t="inlineStr"><is><t>{escape(value)}</t></is></c>'
            for column, value in enumerate(row, start=1)
        )
        return f'<row r="{row_number}">{cells}</row>'

    def _style(self, row_number: int) -> str:
        return ' s="1"' if row_number == 1 else ""

    def _column(self, number: int) -> str:
        name = ""
        while number:
            number, remainder = divmod(number - 1, 26)
            name = f"{chr(65 + remainder)}{name}"
        return name
