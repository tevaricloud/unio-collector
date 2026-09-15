from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerImplementation:
    """Describes the scanner object used for a run without exposing internals."""

    implementation_type: str
    implementation_class: str
    implementation_module: str

    def convert_to_dict(self) -> dict[str, str]:  # noqa: D102
        return {
            "implementation_type": self.implementation_type,
            "implementation_class": self.implementation_class,
            "implementation_module": self.implementation_module,
        }
