"""Privacy-safe environment result projection."""

from __future__ import annotations

# ruff: noqa: EM101,TRY003
from typing import TYPE_CHECKING, Any, Literal, cast

from unio_collector.environment.classifier import EnvironmentClassifier
from unio_collector.environment.vocabulary import CLASSIFIER_VERSION

if TYPE_CHECKING:
    from collections.abc import Mapping

EnvironmentSemantics = Literal["detailed", "coarse", "omit"]
SAFE_SERIALIZED_ENVIRONMENT_VALUES = frozenset(
    {
        CLASSIFIER_VERSION,
        "production",
        "non-production",
        "unknown",
        "conflicting",
        "development",
        "staging",
        "test",
        "high",
        "medium",
        "low",
    },
)


def build_environment_context(
    record: Mapping[str, Any],
    *,
    classifier: EnvironmentClassifier,
    semantics: EnvironmentSemantics = "detailed",
) -> dict[str, str] | None:
    """Build a sanitized transferable classification for a record-like mapping."""
    if semantics == "omit" or not _is_record_like(record):
        return None
    result = classifier.classify(record)
    if result.classification == "unknown" and "environment_context" not in record:
        return None
    context = {
        "classifier_version": CLASSIFIER_VERSION,
        "classification": result.classification,
        "evidence_strength": result.evidence_strength,
    }
    if semantics == "detailed" and result.subtype is not None:
        context["canonical_subtype"] = result.subtype
    return context


def annotate_environment_records(
    records: list[dict[str, Any]],
    *,
    classifier: EnvironmentClassifier | None = None,
) -> list[dict[str, Any]]:
    """Attach safe canonical context to top-level normalized evidence records."""
    active = classifier or EnvironmentClassifier()
    annotated: list[dict[str, Any]] = []
    for record in records:
        context = build_environment_context(record, classifier=active)
        annotated.append({**record, **({"environment_context": context} if context is not None else {})})
    return annotated


def resolve_environment_semantics(profile_id: str, requested: str | None = None) -> EnvironmentSemantics:
    """Resolve privacy-profile defaults and reject unsafe strict detail."""
    if requested not in {None, "detailed", "coarse", "omit"}:
        raise ValueError("Environment semantics must be detailed, coarse, or omit.")
    if profile_id == "strict":
        if requested == "detailed":
            raise ValueError("Strict privacy profile cannot include detailed environment subtypes; use coarse or omit.")
        return "omit" if requested == "omit" else "coarse"
    return "detailed" if requested is None else cast("EnvironmentSemantics", requested)


def _is_record_like(record: Mapping[str, Any]) -> bool:
    return bool(
        set(record)
        & {
            "tags",
            "target_tags",
            "current_tags",
            "associated_tags",
            "resource_name",
            "resource_id",
            "arn",
        }
    )
