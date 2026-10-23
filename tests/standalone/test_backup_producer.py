"""Actual populated Backup DTO union and configuration callbacks through offline protection."""

from __future__ import annotations

import copy
import json
from dataclasses import fields
from typing import TYPE_CHECKING, Any

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_backup.fixture import VARIANTS, backup_producer_observation
from unio_collector.aws.backup.plan import BackupPlanRecord
from unio_collector.aws.backup.recovery_point import BackupRecoveryPointRecord
from unio_collector.aws.backup.rule import BackupRuleRecord
from unio_collector.aws.backup.selection import BackupSelectionRecord
from unio_collector.aws.backup.vault import BackupVaultRecord
from unio_collector.privacy.backup.fields import PLAN, POINT, RULE, SELECTION, VAULT
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"
EXPECTED_RECORD_COUNT = 4
EXPECTED_NESTED_COUNT = 2
YOUNG_POINT_DAYS = 10
AGE_POLICY_DAYS = 90


@pytest.mark.parametrize(
    ("dto", "expected"),
    [(BackupPlanRecord, PLAN), (BackupRecoveryPointRecord, POINT), (BackupRuleRecord, RULE), (BackupSelectionRecord, SELECTION), (BackupVaultRecord, VAULT)],
)
def test_backup_contract_tracks_actual_dtos(dto: type[Any], expected: frozenset[str]) -> None:
    """Independent explicit contracts must cover every actual emitted DTO field."""
    assert {field.name for field in fields(dto)} == expected


@pytest.mark.parametrize("variant", VARIANTS)
def test_actual_backup_source_shapes(variant: str) -> None:
    """Actual SDK calls, complete mixed records and failure diagnostics remain observable."""
    observed = backup_producer_observation(variant)
    assert observed["callbacks"]
    assert observed["provider_calls"]
    assert observed["statuses"]
    assert observed["execution"]["implementation_module"].endswith(".scanners.backup")
    assert observed["execution"]["implementation_class"] == "BackupRetentionReviewScanner"
    row = observed["evidence"]
    assert row["scanner_id"] == "backup-retention-review"
    assert row["serialization_status"] == "serialized"
    records = row["payload"]["records"]
    if variant in {"empty", "denied", "unsupported", "failure", "unavailable"}:
        assert records == []
        if variant != "empty":
            assert observed["diagnostic_warnings"]
            assert observed["execution"]["status"] == "completed_with_warnings"
        return
    assert len(records) == EXPECTED_RECORD_COUNT
    plan = next(record for record in records if "backup_plan_id" in record)
    if variant == "summary":
        assert not any(call.startswith("get_backup_selection:") for call in observed["provider_calls"])
        assert all(not selection["resources"] for selection in plan["selections"])
    if variant == "no_tags":
        assert not any(call.startswith("list_tags:") for call in observed["provider_calls"])
        assert all(record["tags_collected"] is False for record in records if "tags_collected" in record)
    if variant in {"partial", "selection_denied", "tag_denied"}:
        assert plan["collection_errors"]
    if variant == "nullable":
        point = next(record for record in records if "recovery_point_arn" in record)
        optional_point_fields = {
            "backup_vault_arn",
            "resource_arn",
            "resource_type",
            "resource_name",
            "status",
            "backup_size_bytes",
            "creation_date",
            "completion_date",
            "calculated_delete_at",
            "calculated_retention_days",
            "age_days",
        }
        assert all(point[field] is None for field in optional_point_fields)
        assert plan["backup_plan_arn"] is None
        assert plan["creation_date"] is None
        assert plan["last_execution_date"] is None
        assert all(not selection["conditions"] and not selection["list_of_tags"] for selection in plan["selections"])
    if variant == "success":
        assert len(plan["rules"]) == len(plan["selections"]) == EXPECTED_NESTED_COUNT
        points = [record for record in records if "recovery_point_arn" in record]
        assert min(record["age_days"] for record in points) == YOUNG_POINT_DAYS
        assert row["payload"]["metadata"]["older_than_days"] == AGE_POLICY_DAYS
        assert set(plan["selections"][1]["conditions"]) == {"StringEquals", "StringNotEquals", "StringLike", "StringNotLike"}


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_backup_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], variant: str, profile: str) -> None:
    """Run actual populated/conditional producers through receipts, independent validation and cleanup."""
    _case(tmp_path, monkeypatch, sdk_base, backup_producer_observation(variant), profile)


@pytest.mark.parametrize(
    "mutation", ["record", "rule", "condition", "condition_null", "condition_type", "borrowed", "number", "date", "tags", "identity", "scope", "note", "parent"]
)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_backup_unknown_and_malformed_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], mutation: str, profile: str) -> None:
    """Reject nested unknowns, malformed values and foreign identities without completed artifacts."""
    observed = backup_producer_observation()
    records = observed["evidence"]["payload"]["records"]
    plan = next(record for record in records if "backup_plan_id" in record)
    point = next(record for record in records if "recovery_point_arn" in record)
    replacements = {
        "record": (point, "unknown_backup_control", None),
        "rule": (plan["rules"][0], "unknown_backup_control", None),
        "condition": (plan["selections"][1]["conditions"]["StringEquals"][0], "unknown_backup_control", None),
        "condition_null": (plan["selections"][1]["conditions"], "StringEquals", None),
        "condition_type": (plan["selections"][1]["list_of_tags"][0], "ConditionType", "untrusted-condition"),
        "borrowed": (point, "tags", {}),
        "number": (point, "backup_size_bytes", True),
        "date": (point, "creation_date", "2026-09"),
        "tags": (plan["tags"], "synthetic-customer-key", None),
        "identity": (observed["evidence"], "provider_id", "untrusted-provider"),
        "scope": (observed["execution"]["coverage_notes"][0], "configured_value", False),
        "note": (observed["execution"]["coverage_notes"][0], "unknown_backup_control", None),
        "parent": (observed["execution"], "scanner_id", "untrusted-wrapper"),
    }
    container, key, replacement = replacements[mutation]
    container[key] = replacement
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("mutation", ["customer", "unknown", "foreign", "provider", "boundary"])
def test_backup_literals_do_not_hide_customer_values(mutation: str) -> None:
    """Actual status literals cannot exempt arbitrary text or untrusted producer identities."""
    operation = transformer("standard")
    source = {"scanner_evidence": [backup_producer_observation()["evidence"]]}
    before = copy.deepcopy(source)
    protected = operation.transform(source, file_name=MEMBER)
    assert not operation.summary.unclassified
    assert source == before
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"COMPLETED"}, generated_tokens=generated).passed
    row = protected["scanner_evidence"][0]
    point = next(record for record in row["payload"]["records"] if "recovery_point_arn" in record)
    if mutation == "customer":
        point["resource_name"] = "COMPLETED"
    elif mutation == "unknown":
        point["unknown_customer"] = "COMPLETED"
    elif mutation == "foreign":
        row["scanner_id"] = "untrusted-wrapper"
    elif mutation == "provider":
        row["provider_id"] = "untrusted-provider"
    else:
        point["resource_name"] += "COMPLETED"
    result = scanner.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"COMPLETED"}, generated_tokens=generated)
    assert any(finding.category == "known_original_value" for finding in result.findings)
