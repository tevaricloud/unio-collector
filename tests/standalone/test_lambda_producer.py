"""Actual Lambda inventory, private strings and coarse cyclic-reference preservation."""

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
from tools.collector_serverless.fixture import LAMBDA, VARIANTS, serverless_producer_observation
from unio_collector.aws.lambda_cost.cycle.record import LambdaCostCycleRecord
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.serverless.lambda_cycle.fields import FIELDS

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"


def test_lambda_record_contract_is_complete() -> None:
    """Match every declared producer field, including optional legacy defaults."""
    assert {field.name for field in fields(LambdaCostCycleRecord)} == {
        key.removeprefix("records[].")
        for key in FIELDS
        if key.startswith("records[].") and "." not in key.removeprefix("records[].") and "[]" not in key.removeprefix("records[].")
    }


@pytest.mark.parametrize("variant", [item for item in VARIANTS[LAMBDA] if item != "unavailable"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_lambda_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], variant: str, profile: str) -> None:
    """Real populated, optional, limited and failed SDK branches protect and independently validate."""
    _case(tmp_path, monkeypatch, sdk_base, serverless_producer_observation(LAMBDA, variant), profile)


@pytest.mark.parametrize("mutation", ["unknown", "environment", "destination", "filter", "metric", "nullable", "identity", "conflict"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_lambda_rejection_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], mutation: str, profile: str) -> None:
    """Unknown/malformed and conflicting evidence cannot leave successful-looking artifacts."""
    observed = serverless_producer_observation(LAMBDA)
    row = observed["evidence"]
    record = row["payload"]["records"][0]
    if mutation == "unknown":
        record["event_sources"][0]["unknown_lambda_control"] = None
    elif mutation == "environment":
        record["environment_variables"]["SYNTHETIC"] = None
    elif mutation == "destination":
        record["destination_config"]["unknown_lambda_control"] = None
    elif mutation == "filter":
        record["s3_notifications"][0]["filter_rules"][0]["name"] = "untrusted-filter"
    elif mutation == "metric":
        record["metric_summaries"][0]["statistic"] = "Maximum"
    elif mutation == "nullable":
        record["event_sources"] = None
    elif mutation == "identity":
        row["provider_id"] = "azure"
    else:
        record["environment_bucket_match"] = False
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("mutation", ["customer", "unknown", "foreign", "boundary"])
def test_lambda_scan_keeps_customer_values_visible(mutation: str) -> None:
    """Exact runtime controls never exempt arbitrary values, unknown paths or token suffixes."""
    row = serverless_producer_observation(LAMBDA)["evidence"]
    operation = transformer("standard")
    protected = operation.transform({"scanner_evidence": [row]}, file_name=MEMBER)
    assert not operation.summary.unclassified
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"python3.12"}, generated_tokens=generated).passed
    record = protected["scanner_evidence"][0]["payload"]["records"][0]
    if mutation == "customer":
        record["function_name"] = "python3.12"
    elif mutation == "unknown":
        record["unknown_customer"] = "python3.12"
    elif mutation == "foreign":
        protected["scanner_evidence"][0]["scanner_id"] = "untrusted-wrapper"
    else:
        record["function_name"] += "python3.12"
    result = scanner.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"python3.12"}, generated_tokens=generated)
    assert any(finding.category == "known_original_value" for finding in result.findings)


def test_lambda_preparation_preserves_source_and_legacy_default() -> None:
    """Raw evidence stays unchanged; the additive flag is optional on historical payloads."""
    row = serverless_producer_observation(LAMBDA, "url_environment")["evidence"]
    before = copy.deepcopy(row)
    assert row["payload"]["records"][0]["environment_bucket_match"] is None
    protected = transformer("standard").transform({"scanner_evidence": [row]}, file_name=MEMBER)
    assert protected["scanner_evidence"][0]["payload"]["records"][0]["environment_bucket_match"] is True
    assert row == before
