"""Render explicit IAM conditions without dropping or coercing restrictions."""

from __future__ import annotations

from typing import NoReturn


class AwsIamConditionRenderer:
    """Reject malformed and conflicting restrictions before policy output."""

    def render(self, conditions: object) -> dict[str, object]:
        """Return the historical deterministic shape for valid conditions."""
        if not isinstance(conditions, (tuple, list)):
            self._fail()
        rendered: dict[str, dict[str, object]] = {}
        for condition in conditions:
            if not isinstance(condition, dict) or set(condition) != {"operator", "key", "values"}:
                self._fail()
            operator = condition["operator"]
            key = condition["key"]
            values = condition["values"]
            if not self._text(operator) or not self._text(key):
                self._fail()
            if not isinstance(values, (tuple, list)) or not values or not all(self._text(value) for value in values):
                self._fail()
            normalized = sorted(values)
            value: object = normalized[0] if len(normalized) == 1 else normalized
            group = rendered.setdefault(operator, {})
            if key in group and group[key] != value:
                self._fail()
            group[key] = value
        return dict(rendered)

    @staticmethod
    def _text(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _fail() -> NoReturn:
        message = "AWS IAM policy condition is malformed or conflicting."
        raise ValueError(message)
