from __future__ import annotations  # noqa: D100

from typing import Literal

RequirementType = Literal[
    "required",
    "optional",
    "conditional",
    "optional_enrichment",
    "unknown",
]
