"""Actual populated commitment producer, conditional failures and independent protection."""

from __future__ import annotations

from dataclasses import fields
from importlib import import_module
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_commitment.fixture import SCANNER, VARIANTS, commitment_producer_observation
from unio_collector.privacy.commitment.fields import FIELDS, INVENTORY, METRIC
from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS
from unio_collector.scanners.cost_explorer.commitment.collection import CommitmentAndPricingReviewCollector

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline
INVENTORY_COUNT = 2
METRIC_COUNT = 39
GROUPED_METRIC_COUNT = 63
DTO_PATHS = {
    "unio_collector.scanners.cost_explorer.commitment.evidence:CommitmentReviewEvidence": "",
    "unio_collector.commitments.observation:ObservedCommitmentPortfolio": "portfolio",
    "unio_collector.commitments.inventory:CommitmentInventoryItem": INVENTORY,
    "unio_collector.commitments.identity:CommitmentIdentity": INVENTORY + ".identity",
    "unio_collector.commitments.specification:CommitmentSpecification": INVENTORY + ".specification",
    "unio_collector.commitments.term:CommitmentTerm": INVENTORY + ".term",
    "unio_collector.commitments.payment:CommitmentPayment": INVENTORY + ".payment",
    "unio_collector.commitments.observed_metric:ObservedCommitmentMetric": METRIC,
    "unio_collector.commitments.source:CommitmentSourceOutcome": "portfolio.source_outcomes[]",
}


def test_commitment_registered_owner() -> None:
    """Verify the actual wrapper remains its live registered owner."""
    module, name = COLLECTOR_SCANNER_CLASS_PATHS[SCANNER].split(":")
    assert getattr(import_module(module), name) is CommitmentAndPricingReviewCollector


@pytest.mark.parametrize("variant", VARIANTS)
def test_actual_commitment_source(variant: str) -> None:
    """Require real SDK requests, account filters, populated metrics and explicit limitations."""
    original = CommitmentAndPricingReviewCollector.collect
    with patch.object(CommitmentAndPricingReviewCollector, "collect", autospec=True, side_effect=original) as observed:
        result = commitment_producer_observation(variant)
    assert observed.call_count == 1
    assert result["callbacks"]
    assert result["operations"]
    payload = result["evidence"]["payload"]
    portfolio = payload["portfolio"]
    assert payload["savings_plans_utilization"] == payload["reservation_utilization"] == []
    for call in result["operations"]:
        if call["operation"].startswith("get_"):
            assert "123456789012" in str(call["parameters"]["Filter"])
    statuses = {item["status"] for item in portfolio["source_outcomes"]}
    _assert_commitment_outcomes(portfolio, variant, statuses)


def _assert_commitment_outcomes(portfolio: dict, variant: str, statuses: set[str]) -> None:
    """Keep populated, scoped and explicitly unavailable producer outcomes separate."""
    if variant == "empty":
        assert not portfolio["inventory"]
        assert not portfolio["observed_metrics"]
        assert statuses == {"success_empty"}
    elif variant in {"denied", "unavailable", "unsupported", "failure"}:
        assert statuses == {"unavailable"}
        assert all(item["limitation"] for item in portfolio["source_outcomes"])
    else:
        assert portfolio["inventory"]
        if variant == "cross_account":
            assert not portfolio["observed_metrics"]
            assert "account_scope_unproven" in statuses
        else:
            assert portfolio["observed_metrics"]
        if variant == "success":
            assert len(portfolio["inventory"]) == INVENTORY_COUNT
            assert len(portfolio["observed_metrics"]) == METRIC_COUNT
        if variant == "groups":
            assert len(portfolio["observed_metrics"]) == GROUPED_METRIC_COUNT
        if variant == "partial":
            assert "unavailable" in statuses
        if variant == "malformed_numeric":
            assert "malformed" in statuses
            assert any(item["value"] is None and item["limitations"] for item in portfolio["observed_metrics"])


@pytest.mark.parametrize(("identity", "prefix"), DTO_PATHS.items())
def test_complete_commitment_dto_contract(identity: str, prefix: str) -> None:
    """Inspect all independently declared DTO fields, not merely populated sample paths."""
    module, name = identity.split(":")
    base = prefix + "." if prefix else ""
    declared = {
        key.removeprefix(base) for key in FIELDS if key.startswith(base) and key != prefix and not any(char in key.removeprefix(base) for char in ".[]")
    }
    assert declared == {field.name for field in fields(getattr(import_module(module), name))}


@pytest.mark.parametrize("variant", [variant for variant in VARIANTS if variant != "dimension_collision"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_commitment_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], variant: str, profile: str) -> None:
    """Require independent validation, receipt integrity, unchanged inputs and fail-closed money collisions."""
    _case(
        tmp_path, monkeypatch, sdk_base, commitment_producer_observation(variant), profile, invalid=variant == "financial_collision" and profile == "standard"
    )


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_ambiguous_commitment_identifier_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], profile: str) -> None:
    """Do not globally exempt region inside arbitrary generated prose to admit an adversarial ID.

    The real parser accepts this synthetic non-UUID ID. Its exact original also
    appears in retained preview notice, permission diagnostics and callback text.
    The unchanged known-original contract must reject these ambiguous occurrences,
    rather than suppress findings or invent a broad literal exception.
    """
    _case(tmp_path, monkeypatch, sdk_base, commitment_producer_observation("dimension_collision"), profile, invalid=True)
