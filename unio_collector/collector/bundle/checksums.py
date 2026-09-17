from __future__ import annotations  # noqa: D100

import hashlib


def build_sha256(data: bytes) -> str:  # noqa: D103
    return hashlib.sha256(data).hexdigest()


def build_checksums(files: dict[str, bytes]) -> dict[str, str]:  # noqa: D103
    return {path: build_sha256(data) for path, data in sorted(files.items()) if path not in {"checksums.json", "manifest.json"}}
