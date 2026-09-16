from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.privacy.protected_bundle import privacy_protection_metadata


def build_bundle_collection_summary(  # noqa: D103
    manifest: dict[str, Any],
    *,
    collection_summary: dict[str, Any] | None = None,
    analysis_contract: dict[str, Any] | None = None,
    strict_analysis_readiness: dict[str, Any] | None = None,
    signature_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "bundle_schema_version": manifest.get("bundle_schema_version"),
        "collector_version": manifest.get("collector_version"),
        "generated_at": manifest.get("generated_at"),
        "account_id": manifest.get("account_id"),
        "regions": manifest.get("regions", []),
        "services_collected": manifest.get("services_collected", []),
        "services_unavailable": manifest.get("services_unavailable", []),
        "permission_limitation_count": _permission_limitation_count(
            manifest,
            collection_summary,
        ),
        "limitation_count": _limitation_count(collection_summary),
        "limitation_counts": _limitation_counts(collection_summary),
        "stable_limitation_counts": _stable_limitation_counts(collection_summary),
        "privacy_protection": privacy_protection_metadata(manifest),
    }
    if analysis_contract is not None:
        summary["analysis_contract"] = _summarise_analysis_contract(
            analysis_contract,
        )
    if collection_summary is not None:
        summary["scanner_analysis_boundary_summary"] = _summarise_analysis_boundary(collection_summary)
    if strict_analysis_readiness is not None:
        summary["strict_analysis_readiness"] = _summarise_analysis_readiness(
            strict_analysis_readiness,
        )
    if signature_metadata is not None:
        summary["signature"] = _summarise_signature_metadata(signature_metadata)
    return summary


def _limitation_count(collection_summary: dict[str, Any] | None) -> int:
    if not collection_summary:
        return 0
    value = collection_summary.get("limitation_count")
    return value if isinstance(value, int) and value >= 0 else 0


def _permission_limitation_count(
    manifest: dict[str, Any],
    collection_summary: dict[str, Any] | None,
) -> int:
    limitation_count = _limitation_count(collection_summary)
    if collection_summary is not None:
        return limitation_count
    limitations = manifest.get("permission_limitations", [])
    return len(limitations) if isinstance(limitations, list) else 0


def _limitation_counts(collection_summary: dict[str, Any] | None) -> dict[str, int]:
    if not collection_summary:
        return {}
    raw = collection_summary.get("limitation_counts")
    if not isinstance(raw, dict):
        return {}
    return {str(key): int(value) for key, value in raw.items() if isinstance(value, int) and value >= 0}


def _stable_limitation_counts(
    collection_summary: dict[str, Any] | None,
) -> dict[str, int]:
    if not collection_summary:
        return {}
    raw = collection_summary.get("stable_limitation_counts")
    if not isinstance(raw, dict):
        return {}
    return {str(key): int(value) for key, value in raw.items() if isinstance(value, int) and value >= 0}


def _summarise_analysis_contract(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "contract_type": contract.get("contract_type"),
        "analyzer_entrypoint": contract.get("analyzer_entrypoint"),
        "active_analysis_source": contract.get("active_analysis_source"),
        "deterministic_report_parity": contract.get(
            "deterministic_report_parity",
        ),
        "requires_aws_for_analysis": contract.get("requires_aws_for_analysis"),
        "requires_credentials_for_analysis": contract.get(
            "requires_credentials_for_analysis",
        ),
        "contains_completed_report_bundle": contract.get(
            "contains_completed_report_bundle",
        ),
        "strict_evidence_only_analysis_supported": contract.get(
            "strict_evidence_only_analysis_supported",
        ),
        "strict_evidence_only_support_scope": contract.get(
            "strict_evidence_only_support_scope",
        ),
        "strict_evidence_only_ready_scanner_count": contract.get(
            "strict_evidence_only_ready_scanner_count",
        ),
        "result_bundle_only_scanner_count": contract.get(
            "result_bundle_only_scanner_count",
        ),
        "strict_evidence_only_report_rebuild_supported": contract.get(
            "strict_evidence_only_report_rebuild_supported",
        ),
    }


def _summarise_signature_metadata(
    signature_metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "status": signature_metadata.get("status"),
        "metadata_version": signature_metadata.get("metadata_version"),
        "digest_algorithm": signature_metadata.get("digest_algorithm"),
        "signed_payload": signature_metadata.get("signed_payload"),
        "signature_algorithm": signature_metadata.get("signature_algorithm"),
        "key_id": signature_metadata.get("key_id"),
        "created_at": signature_metadata.get("created_at"),
    }


def _summarise_analysis_readiness(readiness: dict[str, Any]) -> dict[str, Any]:
    return {
        "active_analysis_source": readiness.get("active_analysis_source"),
        "strict_scanner_analyzer_replay_supported": readiness.get(
            "strict_scanner_analyzer_replay_supported",
        ),
        "strict_scanner_analyzer_replay_scope": readiness.get(
            "strict_scanner_analyzer_replay_scope",
        ),
        "full_report_rebuild_from_scanner_evidence_supported": readiness.get(
            "full_report_rebuild_from_scanner_evidence_supported",
        ),
        "scanner_evidence_payloads_serialized": readiness.get(
            "scanner_evidence_payloads_serialized",
        ),
        "scanner_evidence_payload_file": readiness.get(
            "scanner_evidence_payload_file",
        ),
        "scanner_evidence_payload_count": readiness.get(
            "scanner_evidence_payload_count",
        ),
        "missing_scanner_evidence_payload_count": len(
            readiness.get("missing_scanner_evidence_payload_ids", []) if isinstance(readiness.get("missing_scanner_evidence_payload_ids"), list) else [],
        ),
        "required_for_full_report_rebuild": readiness.get(
            "required_for_full_report_rebuild",
            [],
        ),
        "scanner_count": readiness.get("scanner_count"),
        "strict_evidence_only_ready_count": readiness.get(
            "strict_evidence_only_ready_count",
        ),
        "result_bundle_only_count": readiness.get("result_bundle_only_count"),
    }


def _summarise_analysis_boundary(
    collection_summary: dict[str, Any],
) -> dict[str, Any]:
    value = collection_summary.get("scanner_analysis_boundary_summary")
    if not isinstance(value, dict):
        return {}
    return {
        "scanner_count": value.get("scanner_count"),
        "by_analysis_boundary": value.get("by_analysis_boundary", {}),
        "strict_evidence_only_ready_count": value.get(
            "strict_evidence_only_ready_count",
        ),
        "result_bundle_only_count": value.get("result_bundle_only_count"),
        "deferred_scanner_count": len(
            value.get("deferred_scanner_ids", []) if isinstance(value.get("deferred_scanner_ids"), list) else [],
        ),
    }
