from __future__ import annotations  # noqa: D100

import base64
import csv
import hashlib
import io
import tempfile
from pathlib import Path
from zipfile import ZipFile


class CollectorWheelCanonicalizer:
    """Finalize generated metadata with platform-independent bytes and RECORD."""

    def canonicalize(self, wheel: Path) -> None:
        """Canonicalize only generated UTF-8 METADATA, preserving all other members."""
        with ZipFile(wheel) as source:
            metadata_names = [name for name in source.namelist() if name.endswith(".dist-info/METADATA")]
            if len(metadata_names) != 1:
                msg = "Collector wheel must contain exactly one METADATA member."
                raise ValueError(msg)
            metadata_name = metadata_names[0]
            record_name = metadata_name.removesuffix("METADATA") + "RECORD"
            original = source.read(metadata_name)
            original.decode("utf-8", errors="strict")
            metadata = original.replace(b"\r\n", b"\n")
            if metadata == original:
                return
            rows = list(csv.reader(io.StringIO(source.read(record_name).decode("utf-8"))))
            if sum(row[0] == metadata_name for row in rows) != 1:
                msg = "Collector wheel RECORD must identify METADATA exactly once."
                raise ValueError(msg)
            digest = base64.urlsafe_b64encode(hashlib.sha256(metadata).digest()).rstrip(b"=").decode("ascii")
            record = io.StringIO(newline="")
            writer = csv.writer(record, lineterminator="\n")
            for row in rows:
                writer.writerow([metadata_name, "sha256=" + digest, str(len(metadata))] if row[0] == metadata_name else row)
            replacements = {metadata_name: metadata, record_name: record.getvalue().encode("utf-8")}

            with tempfile.TemporaryDirectory(prefix="unio-wheel-metadata-") as raw:
                finalized = Path(raw) / wheel.name
                with ZipFile(finalized, "w") as target:
                    target.comment = source.comment
                    for member in source.infolist():
                        target.writestr(member, replacements.get(member.filename, source.read(member)))
                content = finalized.read_bytes()
        wheel.write_bytes(content)
