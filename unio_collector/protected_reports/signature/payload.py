from __future__ import annotations  # noqa: D100

import copy
import json
from typing import Any


def canonical_signed_payload(package: dict[str, Any]) -> bytes:
    """Return the canonical protected report-package payload to sign."""
    payload = copy.deepcopy(package)
    payload.pop("signature", None)
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
