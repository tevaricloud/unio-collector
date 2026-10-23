"""Actual populated DynamoDB producer branches and closed privacy/receipt contracts."""

from __future__ import annotations

import copy
import json
from dataclasses import fields
from typing import TYPE_CHECKING

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_dynamodb.fixture import SCANNER, VARIANTS, dynamodb_producer_observation
from unio_collector.aws.dynamodb.region import DynamoDbRegionRecord
from unio_collector.privacy.dynamodb.fields import FIELDS
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"
TABLES = 2
OBSERVATIONS = 14


def test_dynamo_contract_tracks_actual_dto() -> None:
    """Do not let hand-rewritten response expectations hide new emitted fields."""
    declared = {
        path.removeprefix("records[].")
        for path in FIELDS
        if path.startswith("records[].") and "." not in path.removeprefix("records[].") and "[" not in path.removeprefix("records[].")
    }
    assert declared == {field.name for field in fields(DynamoDbRegionRecord)}


@pytest.mark.parametrize("variant", VARIANTS)
def test_actual_dynamo_source_shapes(variant: str) -> None:
    """Real SDK collectors and framework callbacks retain populated or limited facts."""
    observed = dynamodb_producer_observation(variant)
    assert observed["callbacks"]
    assert any(observed["provider_calls"].values())
    assert observed["statuses"]
    assert observed["evidence"]["serialization_status"] == "serialized"
    assert observed["evidence"]["scanner_id"] == SCANNER
    records = observed["evidence"]["payload"]["records"]
    if variant == "malformed":
        assert records == []
        assert observed["execution"]["status"] == "completed_with_warnings"
        return
    assert records
    record = records[0]
    if variant in {"empty", "denied", "unsupported", "failure", "unavailable"}:
        assert record["table_count"] == 0
        assert bool(record["permission_errors"]) == (variant != "empty")
        return
    assert record["table_count"] == TABLES
    assert observed["execution"]["coverage_notes"]
    if variant == "success":
        assert record["metric_observation_count"] == OBSERVATIONS
        assert record["service_current_cost"] == "17.25"
        assert record["untagged_table_count"] == 0
        assert "resourcegroupstaggingapi:get_resources:UnobservedTags" in record["permission_errors"]
    if variant in {"summary", "metrics_partial"}:
        assert record["metric_observation_count"] == 0
        assert record["average_daily_read_capacity_units"] is None
    if variant in {"nullable", "no_cost"}:
        assert record["service_current_cost"] is None
    if variant == "billing_active":
        assert len(records) == TABLES
        by_region = {row["region"]: row for row in records}
        assert set(by_region) == {"eu-west-2", "eu-central-1"}
        assert by_region["eu-west-2"]["table_detail_collected"] is True
        assert by_region["eu-central-1"]["table_detail_collected"] is False
        assert by_region["eu-central-1"]["table_count"] == TABLES
    if variant == "literal_collision":
        assert "ConsumedReadCapacityUnits" in record["sample_table_names"]
        assert "ConsumedReadCapacityUnits" in record["observed_metric_names"]
        assert record["metric_observation_count"] == OBSERVATIONS


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_dynamo_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], variant: str, profile: str) -> None:
    """Verify actual producers, independent validation, receipt, leak results and preservation."""
    _case(tmp_path, monkeypatch, sdk_base, dynamodb_producer_observation(variant), profile)


@pytest.mark.parametrize("mutation", ["unknown", "sample", "count", "cost", "average", "metric", "null", "provider", "note", "scope", "parent"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_dynamo_unknown_and_malformed_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], mutation: str, profile: str) -> None:
    """Unknown descendants and invalid types cannot produce any completed output artifacts."""
    observed = dynamodb_producer_observation()
    row = observed["evidence"]
    record = row["payload"]["records"][0]
    note = observed["execution"]["coverage_notes"][0]
    mutations = {
        "unknown": (record, "unknown_dynamodb_control", None),
        "sample": (record, "sample_table_names", [{}]),
        "count": (record, "table_count", True),
        "cost": (record, "service_current_cost", {}),
        "average": (record, "average_daily_read_capacity_units", "NaN"),
        "metric": (record, "observed_metric_names", [None]),
        "null": (record, "table_detail_collected", None),
        "provider": (row, "provider_id", "untrusted-provider"),
        "note": (note, "unknown_dynamodb_control", None),
        "scope": (note, "configured_value", False),
        "parent": (observed["execution"], "scanner_id", "untrusted-wrapper"),
    }
    container, key, value = mutations[mutation]
    container[key] = value
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("mutation", ["customer", "unknown", "foreign", "provider", "boundary"])
def test_dynamo_metric_literals_do_not_hide_customer_values(mutation: str) -> None:
    """A finite metric role never exempts customer text or untrusted token boundaries."""
    observed = dynamodb_producer_observation("literal_collision")
    source = {"scanner_evidence": [observed["evidence"]]}
    before = copy.deepcopy(source)
    operation = transformer("standard")
    protected = operation.transform(source, file_name=MEMBER)
    assert not operation.summary.unclassified
    assert source == before
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"ConsumedReadCapacityUnits"}, generated_tokens=generated).passed
    row = protected["scanner_evidence"][0]
    record = row["payload"]["records"][0]
    if mutation == "customer":
        record["sample_table_names"][0] = "ConsumedReadCapacityUnits"
    elif mutation == "unknown":
        record["unknown_customer"] = "ConsumedReadCapacityUnits"
    elif mutation == "foreign":
        row["scanner_id"] = "untrusted-wrapper"
    elif mutation == "provider":
        row["provider_id"] = "untrusted-provider"
    else:
        record["sample_table_names"][0] += "ConsumedReadCapacityUnits"
    findings = scanner.scan_text(
        path=MEMBER, content=json.dumps(protected), known_original_values={"ConsumedReadCapacityUnits"}, generated_tokens=generated
    ).findings
    assert any(finding.category == "known_original_value" for finding in findings)
