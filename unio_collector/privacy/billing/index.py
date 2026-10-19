"""Exact field-index adapter for a finite reviewed billing schema graph."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar, overload

if TYPE_CHECKING:
    from collections.abc import Callable
Spec = tuple[str, str, bool]
_T = TypeVar("_T")


class BillingFieldIndex(dict[str, Spec]):
    """Resolve typed recursive schema paths; unknown fields remain absent."""

    def __init__(self, resolve: Callable[[str], tuple[dict[str, Any], str] | None]) -> None:
        """Bind this index to the exact billing schema resolver."""
        super().__init__()
        self._resolve = resolve

    @overload
    def get(self, key: str, /) -> Spec | None: ...
    @overload
    def get(self, key: str, default: Spec, /) -> Spec: ...
    @overload
    def get(self, key: str, default: _T, /) -> Spec | _T: ...
    def get(self, key: str, default: object = None) -> object:
        """Return an exact primitive binding or the caller's unknown-path default."""
        found = self._resolve(key)
        if found is None:
            return default
        node, category = found
        kind = {"structure": "object", "list": "array", "map": "object", "integer": "count", "long": "count", "double": "money", "float": "money"}.get(
            node["kind"], node["kind"]
        )
        return kind, category, False

    def __contains__(self, key: object) -> bool:
        """Only paths resolving through the explicit graph are declared."""
        if not isinstance(key, str) or self._resolve(key) is None:
            return False
        parent = key.rsplit(".", maxsplit=1)[0] if "." in key else ""
        found = self._resolve(parent)
        return found is None or found[0]["kind"] != "map"

    def __getitem__(self, key: str) -> Spec:
        """Raise for undeclared fields, matching the fixed-field contract interface."""
        found = self.get(key)
        if found is None:
            raise KeyError(key)
        return found
