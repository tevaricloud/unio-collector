"""Actual SQS polling producers, closed metric roles and privacy failure cleanup."""

from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_serverless.fixture import POLLING, VARIANTS, serverless_producer_observation
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("variant", VARIANTS[POLLING])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_polling_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], variant: str, profile: str) -> None:
    """Use populated actual SDK/provider/callback/serialization paths through protection."""
    _case(tmp_path, monkeypatch, sdk_base, serverless_producer_observation(POLLING, variant), profile)


@pytest.mark.parametrize("mutation", ["unknown", "null", "role", "number", "context", "parts", "missing", "identity", "note_unknown", "note_parent"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_polling_rejection_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], mutation: str, profile: str) -> None:
    """Unknown/null/type/aggregate/foreign metadata fail before any completed artifacts."""
    observed = serverless_producer_observation(POLLING, "capped")
    row = observed["evidence"]
    metric = row["payload"]["records"][0]["metric_summaries"][0]
    if mutation == "unknown":
        metric["unknown_serverless_control"] = None
    elif mutation == "null":
        metric["namespace"] = None
    elif mutation == "role":
        metric["statistic"] = "Maximum"
    elif mutation == "number":
        metric["period"] = True
    elif mutation == "context":
        metric["collection_context"] = 1
    elif mutation == "parts":
        metric["observed_average_parts"] = [0, [9], -1]
    elif mutation == "missing":
        del metric["datapoints"]
    elif mutation == "identity":
        row["provider_id"] = "azure"
    elif mutation == "note_unknown":
        observed["execution"]["coverage_notes"][0]["unknown_serverless_control"] = None
    else:
        observed["execution"]["scanner_id"] = "untrusted-wrapper"
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("mutation", ["customer", "unknown", "foreign", "provider", "role", "boundary"])
def test_polling_scan_rejects_plaintext(mutation: str) -> None:
    """Validated metric literals cannot admit arbitrary text or untrusted producers."""
    row = serverless_producer_observation(POLLING)["evidence"]
    operation = transformer("standard")
    protected = operation.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not operation.summary.unclassified
    before = copy.deepcopy(row)
    record = protected["scanner_evidence"][0]
    metric = record["payload"]["records"][0]["metric_summaries"][0]
    literal = metric["namespace"]
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    baseline = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={literal}, generated_tokens=generated
    )
    assert baseline.passed, baseline.findings
    if mutation == "customer":
        metric["limitation"] = literal
    elif mutation == "unknown":
        metric["unknown_customer"] = literal
    elif mutation == "foreign":
        record["scanner_id"] = "untrusted-wrapper"
    elif mutation == "provider":
        record["provider_id"] = "azure"
    elif mutation == "role":
        metric["statistic"] = "Maximum"
    else:
        metric["limitation"] = "RESOURCE-AAAAAAAAAAAAAAAA" + literal
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={literal}, generated_tokens=generated
    )
    assert not result.passed
    assert any(finding.category == "known_original_value" for finding in result.findings)
    assert row == before


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_polling_legacy_metric_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], profile: str) -> None:
    """MetricSummary v0 retains its declared optional defaults; v1 missing-field negatives stay rejected."""
    observed = serverless_producer_observation(POLLING)
    for record in observed["evidence"]["payload"]["records"]:
        for metric in record["metric_summaries"]:
            for key in (
                "limitation",
                "datapoints",
                "collection_evidence_version",
                "collection_context",
                "collection_status",
                "collection_reason",
                "observed_average_parts",
            ):
                metric.pop(key)
    _case(tmp_path, monkeypatch, sdk_base, observed, profile)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_temporal_role_collision(profile: str) -> None:
    """Actual metric/AMI dates normalize only in owned timestamp roles, never customer text."""
    observed = serverless_producer_observation(POLLING)
    operation = transformer(profile)
    protected = operation.transform({"scanner_evidence": [observed["evidence"]]}, file_name="scan-result/scanner-evidence.json")
    assert not operation.summary.unclassified
    literal = "2026-09"
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scanner = ProtectedArchiveLeakScanner()
    baseline = scanner.scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={literal}, generated_tokens=generated
    )
    assert baseline.passed, baseline.findings
    protected["scanner_evidence"][0]["payload"]["records"][0]["resource_name" if POLLING == "extended-support-and-eol-review" else "function_name"] = literal
    rejected = scanner.scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={literal}, generated_tokens=generated
    )
    assert any(finding.category == "known_original_value" for finding in rejected.findings)
