from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AwsScanCacheKey:  # noqa: D101
    namespace: str
    parts: tuple[str, ...]

    def convert_to_string(self) -> str:  # noqa: D102
        return f"{self.namespace}:{'|'.join(self.parts)}"
