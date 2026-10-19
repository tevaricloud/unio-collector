"""Commitment unknown/type/tuple rejection, plaintext leaks and failure cleanup."""

from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_commitment.fixture import commitment_producer_observation
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    "mutation",
    [
        "unknown",
        "nested",
        "count",
        "money",
        "null",
        "category",
        "legacy",
        "pair",
        "dimension",
        "grouping",
        "provider",
        "timestamp",
        "blank_money",
        "legacy_null",
    ],
)
def test_commitment_rejection_and_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], profile: str, mutation: str) -> None:
    """Validate every raw subtree before strict financial omission and leave no completed artifacts."""
    observed = commitment_producer_observation()
    row = observed["evidence"]
    payload = row["payload"]
    portfolio = payload["portfolio"]
    item = portfolio["inventory"][0]
    metric = portfolio["observed_metrics"][-1]
    changes = {
        "unknown": (portfolio, "unknown_portfolio_field", None),
        "nested": (item["payment"], "unknown_financial_field", None),
        "count": (portfolio["source_outcomes"][0], "record_count", True),
        "money": (item["payment"], "upfront_amount", "NaN"),
        "null": (item["identity"], "source_id", None),
        "category": (metric, "nature", "customer_nature"),
        "legacy": (payload, "reservation_utilization", [{"unknown_legacy_field": None}]),
        "pair": (metric, "dimensions", [["region", "eu-west-2", "extra"]]),
        "dimension": (metric, "dimensions", [["region", {}]]),
        "grouping": (metric, "dimensions", [["_grouping", "customer-grouping"]]),
        "provider": (row, "provider_id", "foreign"),
        "timestamp": (portfolio, "period_start", "2026-01"),
        "blank_money": (item["payment"], "upfront_amount", ""),
        "legacy_null": (payload, "reservation_utilization", None),
    }
    target, key, value = changes[mutation]
    target[key] = value
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["customer", "financial", "unknown", "foreign", "boundary", "dimension_key", "dimension_value"])
def test_commitment_literal_roles_reject_plaintext(profile: str, mutation: str) -> None:
    """Typed controls never exempt identifiers, arbitrary dimension data or financial customer values."""
    original = commitment_producer_observation()["evidence"]
    operation = transformer(profile)
    protected = operation.transform({"scanner_evidence": [original]}, file_name=MEMBER)
    assert not operation.summary.unclassified
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scan = ProtectedArchiveLeakScanner()
    assert scan.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"aws_observed"}, generated_tokens=generated).passed
    changed = copy.deepcopy(protected)
    row = changed["scanner_evidence"][0]
    portfolio = row["payload"]["portfolio"]
    item = portfolio["inventory"][0]
    metric = portfolio["observed_metrics"][-1]
    if mutation == "customer":
        item["identity"]["source_id"] = "aws_observed"
    elif mutation == "financial":
        item["payment"]["upfront_amount"] = "aws_observed"
    elif mutation == "unknown":
        item["unknown_customer_field"] = "aws_observed"
    elif mutation == "foreign":
        row["provider_id"] = "foreign"
        item["identity"]["source_id"] = "aws_observed"
    elif mutation == "boundary":
        item["identity"]["source_id"] += "aws_observed"
    elif mutation == "dimension_key":
        metric["dimensions"] = [["aws_observed", "synthetic-customer"]]
    else:
        metric["dimensions"] = [["region", "aws_observed"]]
    checked = scan.scan_text(path=MEMBER, content=json.dumps(changed), known_original_values={"aws_observed"}, generated_tokens=generated)
    assert not checked.passed
    assert any(finding.category == "known_original_value" for finding in checked.findings)
