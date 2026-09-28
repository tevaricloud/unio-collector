"""Deterministic environment-context classifier."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from unio_collector.environment.models import EnvironmentResult
from unio_collector.environment.runtime import current_environment_alias_file
from unio_collector.environment.signal import EnvironmentSignal
from unio_collector.environment.vocabulary import EnvironmentVocabulary, load_environment_vocabulary, normalize_term

_WORD_RE = re.compile(r"[a-z0-9]+")
_STRENGTH_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
_IDENTITY_FIELDS = ("account_label", "resource_name", "name", "resource_id", "arn")
_TAG_FIELDS = ("tags", "target_tags", "current_tags", "associated_tags")


class EnvironmentClassifier:
    """Classify arbitrary normalized evidence without retaining matched text."""

    def __init__(
        self,
        *,
        alias_file: str | None = None,
        vocabulary: EnvironmentVocabulary | None = None,
    ) -> None:
        """Load the shared vocabulary plus optional invocation-local aliases."""
        selected = alias_file if alias_file is not None else current_environment_alias_file()
        self.vocabulary = vocabulary or load_environment_vocabulary(selected)

    def classify(self, record: Mapping[str, Any], *, account_label: str = "") -> EnvironmentResult:
        """Return a canonical result from all available identifying metadata."""
        preclassified = self._preclassified(record)
        if preclassified is not None:
            return preclassified
        signals: list[EnvironmentSignal] = []
        for mapping in self._mappings(record):
            for tag_field in _TAG_FIELDS:
                signals.extend(self._tag_signals(mapping.get(tag_field)))
            for key, value in mapping.items():
                normalized_key = normalize_term(str(key))
                if normalized_key in self.vocabulary.explicit_keys and value not in (None, ""):
                    signals.extend(self._signals(str(value), strength="high", source="explicit_metadata"))
        identities = [("account_label", account_label), *((field, record.get(field)) for field in _IDENTITY_FIELDS)]
        for _field, value in identities:
            if value not in (None, ""):
                signals.extend(self._signals(str(value), strength="low", source="identity"))
        return self._result(self._deduplicate(signals))

    def classify_tags(
        self,
        tags: Mapping[str, Any] | Iterable[Mapping[str, Any]],
        *,
        resource_name: str | None = None,
    ) -> EnvironmentResult:
        """Classify cleanup-style tag input and an optional resource name."""
        record: dict[str, Any] = {"tags": tags}
        if resource_name:
            record["resource_name"] = resource_name
        return self.classify(record)

    def _tag_signals(self, value: object) -> list[EnvironmentSignal]:
        signals: list[EnvironmentSignal] = []
        if isinstance(value, Mapping):
            items = value.items()
        elif isinstance(value, list):
            items = ((item.get("Key", item.get("key", "")), item.get("Value", item.get("value", ""))) for item in value if isinstance(item, Mapping))
        else:
            return signals
        for key, item_value in items:
            explicit = normalize_term(str(key)) in self.vocabulary.explicit_keys
            strength = "high" if explicit else "medium"
            signals.extend(self._signals(str(item_value), strength=strength, source="tag"))
            if not explicit:
                signals.extend(self._signals(str(key), strength="medium", source="tag"))
        return signals

    def _signals(self, value: str, *, strength: str, source: str) -> list[EnvironmentSignal]:
        normalized = normalize_term(value)
        words = _WORD_RE.findall(normalized)
        candidates = {normalized, *words}
        for start in range(len(words)):
            for end in range(start + 2, min(len(words), start + 3) + 1):
                candidates.add("-".join(words[start:end]))
        matched: dict[str, str] = {}
        for alias in sorted(candidates, key=len, reverse=True):
            subtype = self.vocabulary.aliases.get(alias)
            if subtype is not None:
                matched[alias] = subtype

        for alias in tuple(matched):
            if "-" not in alias:
                continue
            for component in alias.split("-"):
                matched.pop(component, None)
        return [
            EnvironmentSignal(
                classification=("production" if subtype == "production" else "non-production"),
                subtype=subtype,  # type: ignore[arg-type]
                evidence_strength=strength,  # type: ignore[arg-type]
                source=source,
                custom_alias=alias in self.vocabulary.custom_aliases,
            )
            for alias, subtype in sorted(matched.items())
        ]

    def _result(self, signals: tuple[EnvironmentSignal, ...]) -> EnvironmentResult:
        classifications = {signal.classification for signal in signals}
        strength = max(signals, key=lambda item: _STRENGTH_ORDER[item.evidence_strength]).evidence_strength if signals else "unknown"
        if classifications == {"production", "non-production"}:
            return EnvironmentResult("conflicting", None, strength, signals)
        if not signals:
            return EnvironmentResult("unknown", None, "unknown")
        classification = signals[0].classification
        subtypes = {signal.subtype for signal in signals}
        subtype = next(iter(subtypes)) if len(subtypes) == 1 else ("non-production" if classification == "non-production" else None)
        return EnvironmentResult(classification, subtype, strength, signals)  # type: ignore[arg-type]

    def _preclassified(self, record: Mapping[str, Any]) -> EnvironmentResult | None:
        value = record.get("environment_context")
        if not isinstance(value, Mapping):
            return None
        if value.get("classifier_version") != self.vocabulary.classifier_version:
            return None
        classification = value.get("classification")
        strength = value.get("evidence_strength", "unknown")
        subtype = value.get("canonical_subtype")
        if classification not in {"production", "non-production", "unknown", "conflicting"}:
            return None
        if strength not in _STRENGTH_ORDER:
            strength = "unknown"
        if subtype not in {"production", "development", "staging", "test", "non-production"}:
            subtype = None
        return EnvironmentResult(classification, subtype, strength)  # type: ignore[arg-type]

    def _mappings(self, record: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        mappings: list[Mapping[str, Any]] = []
        pending = [record]
        seen: set[int] = set()
        while pending:
            mapping = pending.pop()
            identity = id(mapping)
            if identity in seen:
                continue
            seen.add(identity)
            mappings.append(mapping)
            for key in ("metadata", "source_signals", "relationships"):
                value = mapping.get(key)
                if isinstance(value, Mapping):
                    pending.append(value)
                elif isinstance(value, list):
                    pending.extend(item for item in value if isinstance(item, Mapping))
        return mappings

    def _deduplicate(self, signals: list[EnvironmentSignal]) -> tuple[EnvironmentSignal, ...]:
        return tuple(dict.fromkeys(signals))
