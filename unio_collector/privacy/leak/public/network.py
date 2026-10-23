"""Kind-bound finite SDK literals in the read-only network leak-scan view."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from unio_collector.privacy.network.facts import NESTED_FIELDS, RESOURCE_FIELDS, NetworkFactsPolicy


class NetworkLiteralScanPolicy:
    """Normalize admitted enum leaves without hiding identifiers or arbitrary text."""

    @classmethod
    def view(cls, value: Any, collection_names: frozenset[str]) -> Any:  # noqa: ANN401
        """Require the exact resource kind and complete facts admission first."""
        if not isinstance(value, dict) or value.get("kind") not in collection_names:
            return value
        kind = value["kind"]
        if NetworkFactsPolicy.unknown_paths(value.get("facts"), kind, "facts"):
            return value
        result = deepcopy(value)
        cls._mask(result["facts"], RESOURCE_FIELDS[kind])
        return result

    @classmethod
    def _mask(cls, value: dict[str, Any], fields: dict[str, str]) -> None:
        for key, child in value.items():
            spec = fields[key]
            if child is None:
                continue
            if spec.startswith("enum:") or (spec == "cidr" and child in {"0.0.0.0/0", "::/0"}):
                value[key] = ""
            elif spec.startswith("object:"):
                cls._mask(child, NESTED_FIELDS[spec.removeprefix("object:")])
            elif spec.startswith("list:"):
                for item in child:
                    cls._mask(item, NESTED_FIELDS[spec.removeprefix("list:")])
