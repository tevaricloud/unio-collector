"""Load and validate the versioned environment vocabulary."""

from __future__ import annotations

# ruff: noqa: EM101,EM102,TRY003
import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from unio_collector.environment.types import CLASSIFIER_VERSION, EnvironmentSubtype

CANONICAL_SUBTYPES: tuple[EnvironmentSubtype, ...] = (
    "production",
    "development",
    "staging",
    "test",
    "non-production",
)
_SEPARATOR_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class EnvironmentVocabulary:
    """Validated aliases and explicit environment-style keys."""

    aliases: dict[str, EnvironmentSubtype]
    explicit_keys: frozenset[str]
    custom_aliases: frozenset[str] = frozenset()
    classifier_version: str = CLASSIFIER_VERSION


def normalize_term(value: str) -> str:
    """Normalize punctuation and separators without substring matching."""
    return "-".join(part for part in _SEPARATOR_RE.split(value.strip().casefold()) if part)


def load_environment_vocabulary(
    alias_file: str | Path | None = None,
) -> EnvironmentVocabulary:
    """Load built-ins and an optional additive customer alias mapping."""
    resource = files("unio_collector").joinpath("data/environment-classification.yaml")
    payload = yaml.safe_load(resource.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Built-in environment vocabulary must contain a mapping.")
    if payload.get("classifier_version") != CLASSIFIER_VERSION:
        raise ValueError("Environment vocabulary classifier version is inconsistent with the runtime contract.")
    aliases = _parse_categories(payload.get("categories"), source="built-in environment vocabulary")
    keys = payload.get("explicit_environment_keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("Built-in environment vocabulary must define explicit_environment_keys.")
    explicit_keys = frozenset(normalize_term(str(value)) for value in keys)
    custom_aliases: set[str] = set()
    if alias_file is not None:
        custom_payload = _load_customer_file(Path(alias_file))
        categories = custom_payload.get("categories", custom_payload)
        custom = _parse_categories(categories, source="customer environment alias file")
        for alias, subtype in custom.items():
            existing = aliases.get(alias)
            if existing is not None:
                relation = "contradicts" if existing != subtype else "duplicates"
                raise ValueError(f"Customer environment alias {alias!r} {relation} the built-in vocabulary.")
            aliases[alias] = subtype
            custom_aliases.add(alias)
    return EnvironmentVocabulary(
        aliases=aliases,
        explicit_keys=explicit_keys,
        custom_aliases=frozenset(custom_aliases),
    )


def _load_customer_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"Environment alias file does not exist: {path}")
    if path.suffix.casefold() not in {".yaml", ".yml"}:
        raise ValueError(f"Environment alias file must use YAML (.yaml or .yml): {path}")
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"Environment alias file is not valid YAML: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Environment alias file must contain a category-to-aliases mapping.")
    unknown = set(payload) - {"schema_version", "categories", *CANONICAL_SUBTYPES}
    if unknown:
        raise ValueError(f"Environment alias file contains unsupported keys: {', '.join(sorted(unknown))}.")
    if "schema_version" in payload and payload["schema_version"] != 1:
        raise ValueError("Environment alias file schema_version must be 1.")
    return payload


def _parse_categories(value: object, *, source: str) -> dict[str, EnvironmentSubtype]:
    if not isinstance(value, dict) or not value:
        raise ValueError(f"{source} must contain a non-empty category mapping.")
    aliases: dict[str, EnvironmentSubtype] = {}
    for raw_subtype, raw_aliases in value.items():
        subtype = str(raw_subtype)
        if subtype not in CANONICAL_SUBTYPES:
            raise ValueError(f"{source} contains unsupported category {subtype!r}.")
        if not isinstance(raw_aliases, list) or not raw_aliases:
            raise ValueError(f"Environment category {subtype!r} must contain a non-empty alias list.")
        for raw_alias in raw_aliases:
            if not isinstance(raw_alias, str) or not normalize_term(raw_alias):
                raise ValueError(f"Environment category {subtype!r} contains an invalid alias.")
            alias = normalize_term(raw_alias)
            if alias in aliases:
                raise ValueError(f"Environment alias {alias!r} is duplicated or contradictory in {source}.")
            aliases[alias] = subtype  # type: ignore[assignment]
    return aliases
