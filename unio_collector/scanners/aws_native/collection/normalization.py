from __future__ import annotations  # noqa: D100

from typing import Any

MAX_NATIVE_RECOMMENDATION_RECORDS = 100


def get_first_list(payload: dict[str, Any], keys: tuple[str, ...]) -> list[Any]:  # noqa: D103
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def first_text(payload: dict[str, Any], *keys: str) -> str | None:  # noqa: D103
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def first_dict(payload: dict[str, Any], *keys: str) -> dict[str, Any]:  # noqa: D103
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list) and value and isinstance(value[0], dict):
            return value[0]
        if isinstance(value, dict):
            return value
    return {}


def get_dict(value: Any) -> dict[str, Any]:  # noqa: ANN401, D103
    return value if isinstance(value, dict) else {}


def extract_estimated_savings(payload: dict[str, Any]) -> dict[str, str | None]:  # noqa: D103
    candidates = (
        payload.get("estimatedMonthlySavings"),
        payload.get("savingsOpportunity", {}),
        payload.get("estimatedSavings"),
        payload.get("estimatedMonthlySavingsValue"),
    )
    for candidate in candidates:
        if isinstance(candidate, dict):
            nested = candidate.get("estimatedMonthlySavings")
            if isinstance(nested, dict):
                amount = first_text(nested, "value", "amount")
                currency = first_text(
                    nested,
                    "currency",
                    "currencyCode",
                ) or first_text(candidate, "currency", "currencyCode")
                if amount:
                    return {"amount": amount, "currency": currency}
            amount = first_text(
                candidate,
                "value",
                "amount",
                "estimatedMonthlySavings",
                "estimatedSavings",
            )
            currency = first_text(candidate, "currency", "currencyCode")
            if amount:
                return {"amount": amount, "currency": currency}
        elif candidate not in (None, ""):
            return {"amount": str(candidate), "currency": None}
    return {"amount": None, "currency": None}


def compact_dict(payload: dict[str, Any]) -> dict[str, Any]:  # noqa: D103
    compact: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            compact[key] = value
        elif isinstance(value, dict):
            compact[key] = {
                child_key: child_value for child_key, child_value in value.items() if isinstance(child_value, (str, int, float, bool)) or child_value is None
            }
        elif isinstance(value, list):
            compact[key] = f"{len(value)} item(s)"
    return compact


def deduplicate_strings(values: list[str]) -> list[str]:  # noqa: D103
    return list(dict.fromkeys(value for value in values if value))
