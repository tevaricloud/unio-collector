from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


@dataclass(frozen=True)
class AwsInventoryValueHelper:
    """Normalize small AWS inventory values without owning AWS clients."""

    sample_limit: int = 10

    def collect_dict_items(  # noqa: D102
        self,
        pages: list[dict[str, Any]],
        key: str,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for page in pages:
            page_items = page.get(key, [])
            if isinstance(page_items, list):
                items.extend(item for item in page_items if isinstance(item, dict))
        return items

    def collect_response_items(  # noqa: D102
        self,
        response: dict[str, Any],
        key: str,
    ) -> list[dict[str, Any]]:
        items = response.get(key, []) if isinstance(response, dict) else []
        if not isinstance(items, list):
            return []
        return [item for item in items if isinstance(item, dict)]

    def get_named_values(  # noqa: D102
        self,
        items: list[dict[str, Any]],
        key: str,
    ) -> list[str]:
        return [str(item[key]) for item in items if item.get(key)]

    def limit_samples(  # noqa: D102
        self,
        values: Iterable[str],
        *,
        limit: int | None = None,
    ) -> list[str]:
        sample_limit = self.sample_limit if limit is None else limit
        seen: set[str] = set()
        samples: list[str] = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            samples.append(value)
            if len(samples) >= sample_limit:
                break
        return samples

    def get_int(self, value: Any) -> int:  # noqa: ANN401, D102
        if isinstance(value, bool):
            return 0
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return 0

    def get_float(self, value: Any) -> float:  # noqa: ANN401, D102
        if isinstance(value, bool):
            return 0.0
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return 0.0
        return 0.0

    def extend_unique(self, target: list[str], values: Iterable[str]) -> None:  # noqa: D102
        for value in values:
            if value not in target:
                target.append(value)

    def chunk_values(  # noqa: D102
        self,
        values: Sequence[str],
        chunk_size: int,
    ) -> list[list[str]]:
        return [list(values[index : index + chunk_size]) for index in range(0, len(values), chunk_size)]

    def truncate_sample_text(self, value: str, max_length: int = 160) -> str:  # noqa: D102
        normalized = " ".join(value.split())
        if len(normalized) <= max_length:
            return normalized
        return f"{normalized[: max_length - 3]}..."
