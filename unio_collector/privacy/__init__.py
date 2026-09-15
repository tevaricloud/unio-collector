from __future__ import annotations  # noqa: D104

from typing import TYPE_CHECKING

from unio_collector.privacy.canonicalization import CanonicalValue, canonicalize_value
from unio_collector.privacy.tokens import TokenService, is_protected_token

if TYPE_CHECKING:
    from unio_collector.privacy.bundle import (
        ProtectedBundleInspector,
        ProtectedBundleProtector,
    )

__all__ = [
    "CanonicalValue",
    "ProtectedBundleInspector",
    "ProtectedBundleProtector",
    "TokenService",
    "canonicalize_value",
    "is_protected_token",
]


def __getattr__(name: str) -> object:
    """Load bundle-facing privacy classes lazily to avoid collector cycles."""
    if name in {"ProtectedBundleInspector", "ProtectedBundleProtector"}:
        from unio_collector.privacy.bundle import (  # noqa: PLC0415
            ProtectedBundleInspector,
            ProtectedBundleProtector,
        )

        values = {
            "ProtectedBundleInspector": ProtectedBundleInspector,
            "ProtectedBundleProtector": ProtectedBundleProtector,
        }
        return values[name]
    raise AttributeError(name)
