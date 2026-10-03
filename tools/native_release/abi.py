"""Fail closed on native ELF requirements newer than Ubuntu 22.04."""

from __future__ import annotations

# ruff: noqa: EM101, EM102, S603, TRY003
import json
import re
import shutil
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class LinuxBaselineValidator:
    """Inventory GLIBC requirements before accepting a Linux payload."""

    def validate(self, payload: Path, evidence: Path) -> dict[str, object]:
        """Require every ELF dependency to fit the production GLIBC 2.35 baseline."""
        records: list[dict[str, object]] = []
        result: dict[str, object] = {"baseline": "2.35", "files": records, "status": "failed"}
        try:
            readelf = shutil.which("readelf")
            if readelf is None:
                raise FileNotFoundError("Linux ABI validation requires readelf.")
            for path in sorted(payload.rglob("*")):
                if not path.is_file():
                    continue
                with path.open("rb") as stream:
                    if stream.read(4) != b"\x7fELF":
                        continue
                completed = subprocess.run((readelf, "--version-info", "--wide", str(path)), check=True, capture_output=True, text=True)
                names = sorted(set(re.findall(r"\bGLIBC_[A-Za-z0-9_.]+", completed.stdout)))
                records.append({"path": path.relative_to(payload).as_posix(), "requirements": names})
                for name in names:
                    match = re.fullmatch(r"GLIBC_(\d+)\.(\d+)(?:\.(\d+))?", name)
                    if match is None or tuple(int(part or 0) for part in match.groups()) > (2, 35, 0):
                        raise ValueError(f"Linux payload {path.name} requires unsupported {name}; baseline is GLIBC 2.35.")
            if not records:
                raise ValueError("Linux payload contains no ELF files to validate.")
            result["status"] = "passed"
        finally:
            evidence.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result
