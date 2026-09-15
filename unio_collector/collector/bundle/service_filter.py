from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.collector.minimisation import (
    EvidenceMinimisationOptions,
    normalize_service_name,
)


def is_excluded_service(
    service: object,
    *,
    minimisation: EvidenceMinimisationOptions,
) -> bool:
    """Return whether service evidence is excluded by minimisation options."""
    normalized = normalize_service_name(service or "")
    service_terms = {
        normalized,
        normalized.removeprefix("aws-"),
        normalized.removeprefix("amazon-"),
    }
    service_aliases = {
        "amazon-simple-storage-service": "s3",
        "simple-storage-service": "s3",
        "aws-identity-and-access-management": "iam",
        "identity-and-access-management": "iam",
        "aws-cost-explorer": "cost-explorer",
        "cost-explorer": "ce",
    }
    alias = service_aliases.get(normalized)
    if alias:
        service_terms.add(alias)
    if service_terms.intersection(set(minimisation.exclude_services)):
        return True
    if "s3" in minimisation.exclude_services and "s3" in service_terms:
        return True
    if "iam" in minimisation.exclude_services and ("iam" in service_terms or "identity-and-access-management" in service_terms):
        return True
    return bool(
        minimisation.no_cost_data and service_terms.intersection({"ce", "cost-explorer", "aws-cost-explorer"}),
    )


def filter_evidence_records(
    records: list[dict[str, Any]],
    minimisation: EvidenceMinimisationOptions,
) -> list[dict[str, Any]]:
    """Retain whole supplied records for services allowed by export options."""
    return [record for record in records if not is_excluded_service(record.get("service"), minimisation=minimisation)]
