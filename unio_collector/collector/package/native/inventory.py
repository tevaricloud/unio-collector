from __future__ import annotations  # noqa: D100

import hashlib
import json
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

NATIVE_PAYLOAD_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class NativePayloadFile:
    """Normalized file identity for reproducibility comparisons."""

    path: str
    sha256: str
    size: int
    executable: bool
    native_binary: bool

    def convert_to_dict(self) -> dict[str, object]:
        """Return JSON-safe data."""
        return {
            "executable": self.executable,
            "native_binary": self.native_binary,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
        }


def build_native_payload_inventory(root: Path) -> dict[str, Any]:
    """Hash a native payload using platform-neutral relative paths."""
    files = tuple(_file_record(root, path) for path in sorted(path for path in root.rglob("*") if path.is_file()))
    full = [record.convert_to_dict() for record in files]
    normalized = [
        {
            **record.convert_to_dict(),
            "sha256": None if record.native_binary else record.sha256,
            "size": None if record.native_binary else record.size,
        }
        for record in files
    ]
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    return {
        "files": full,
        "normalized_payload_sha256": hashlib.sha256(canonical).hexdigest(),
        "schema_version": NATIVE_PAYLOAD_SCHEMA_VERSION,
    }


def write_native_payload_inventory(root: Path, output: Path) -> dict[str, Any]:
    """Write deterministic normalized payload inventory."""
    payload = build_native_payload_inventory(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _file_record(root: Path, path: Path) -> NativePayloadFile:
    relative = path.relative_to(root).as_posix()
    suffix = path.suffix.casefold()
    return NativePayloadFile(
        path=relative,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        size=path.stat().st_size,
        executable=bool(path.stat().st_mode & stat.S_IXUSR),
        native_binary=suffix in {".dll", ".dylib", ".exe", ".pkg", ".pyd", ".pyz", ".so", ".zip"} or suffix.startswith(".so."),
    )


__all__ = ["NativePayloadFile", "build_native_payload_inventory", "write_native_payload_inventory"]
