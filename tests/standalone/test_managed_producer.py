"""Actual managed wrappers retain individual SDK response limitations."""

from __future__ import annotations

import json
from dataclasses import fields
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_managed.cache import SyntheticCacheSession
from tools.collector_managed.ecs import SyntheticEcsSession
from tools.collector_managed.eks import SyntheticEksSession
from tools.collector_managed.fixture import CACHE, ECS, EKS, VARIANTS, managed_producer_observation
from tools.collector_sdk_fixture import WRAPPERS
from unio_collector.aws.ecs.region_record import EcsRegionRecord
from unio_collector.aws.eks.region_record import EksRegionRecord
from unio_collector.aws.elasticache.region_record import ElastiCacheRegionRecord
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.selection import select_producer_contract

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline


@pytest.fixture(autouse=True)
def forbid_live_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """All producer responses are synthetic; SDK construction remains forbidden."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))


@pytest.mark.parametrize("operation", ["describe_clusters", "describe_services"])
@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("ACCESS_DENIED", "AccessDeniedException"),
        ("MISSING", "UnavailableEvidence"),
        ("synthetic-customer-private-reason", "PartialEvidence"),
        (None, "MalformedEvidence"),
    ],
)
def test_actual_ecs_response_failures_are_limitations(monkeypatch: pytest.MonkeyPatch, operation: str, reason: str | None, expected: str) -> None:
    """A successful request containing denied/missing resources cannot look clean."""
    original = getattr(SyntheticEcsSession, operation)

    def response(self: SyntheticEcsSession, **kwargs: object) -> dict[str, Any]:
        result = original(self, **kwargs)
        result["failures"] = [{"arn": "synthetic-customer-resource", "reason": reason, "detail": "synthetic-customer-private-detail"}]
        return result

    monkeypatch.setattr(SyntheticEcsSession, operation, response)
    observed = managed_producer_observation(ECS)
    record = observed["evidence"]["payload"]["records"][0]
    assert operation + ":" + expected in record["permission_errors"]
    assert observed["execution"]["coverage_notes"][0]["permission_error_count"] > 0
    assert all("synthetic-customer-private" not in message for message in record["permission_errors"])


EXPECTED_CACHE_METRICS = 7
CASES = [(sid, variant, billing) for sid, variants in VARIANTS.items() for variant in variants for billing in (True, False)]


def observe(scanner: str, variant: str, *, billing: bool = True) -> dict[str, Any]:
    """Require actual registered invocation, populated supported results and callbacks."""
    wrapper = WRAPPERS[scanner]
    original = wrapper.collect
    with patch.object(wrapper, "collect", autospec=True, side_effect=original) as called:
        observed = managed_producer_observation(scanner, variant, billing=billing)
    assert called.call_count == 1
    assert observed["callbacks"]
    assert observed["provider_calls"]
    assert observed["evidence"]["serialization_status"] == "serialized"
    if variant == "success":
        record = observed["evidence"]["payload"]["records"][0]
        assert record[{ECS: "service_count", EKS: "cluster_count", CACHE: "cache_cluster_count"}[scanner]] > 0
        if scanner == CACHE:
            assert len(record["metrics"]) == EXPECTED_CACHE_METRICS
            assert all(metric["observed_average"] is not None for metric in record["metrics"])
    return observed


@pytest.mark.parametrize(("scanner", "variant", "billing"), CASES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_managed_producer_protection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, variant: str, *, billing: bool, profile: str
) -> None:
    """Protect complete actual evidence, validate independently and verify receipts."""
    _case(tmp_path, monkeypatch, sdk_base, observe(scanner, variant, billing=billing), profile)


@pytest.mark.parametrize(("scanner", "dto"), [(ECS, EcsRegionRecord), (EKS, EksRegionRecord), (CACHE, ElastiCacheRegionRecord)])
def test_complete_managed_record_contract(scanner: str, dto: type) -> None:
    """Compare the static contract to the real populated DTO, not a rewritten shape."""
    row = json.loads(json.dumps(observe(scanner, "success")["evidence"]))
    contract = select_producer_contract(row)
    assert contract is not None
    assert {field.name for field in fields(dto)} == set(row["payload"]["records"][0])
    assert {"records[]." + field.name for field in fields(dto)} <= set(contract.fields)
    assert not contract.unknown_record_paths(row, "scan-result/scanner-evidence.json")


@pytest.mark.parametrize("scanner", [ECS, EKS, CACHE])
@pytest.mark.parametrize(
    "mutation", ["unknown_payload", "unknown_note", "boolean_count", "foreign_note", "literal_note", "null_identifier", "cost_object", "note_null", "prose"]
)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_managed_malformed_and_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, mutation: str, profile: str
) -> None:
    """Reject unknown, malformed and conflicting shapes; protect arbitrary prose."""
    observed = observe(scanner, "success")
    record = observed["evidence"]["payload"]["records"][0]
    note = observed["execution"]["coverage_notes"][0]
    if mutation == "unknown_payload":
        record["unknown_managed_control"] = None
    elif mutation == "unknown_note":
        note["detail_counts"]["unknown_managed_note"] = None
    elif mutation == "boolean_count":
        record[{ECS: "service_count", EKS: "cluster_count", CACHE: "cache_cluster_count"}[scanner]] = True
    elif mutation == "foreign_note":
        note["scanner_id"] = "bedrock-cost-review"
    elif mutation == "literal_note":
        note["resource_label"] = "synthetic-customer-label"
    elif mutation == "null_identifier":
        next(value for key, value in record.items() if key.startswith("sample_") and value)[0] = None
    elif mutation == "cost_object":
        record["service_current_cost"] = {}
    elif mutation == "note_null":
        note["detail_counts"] = None
    else:
        note["summary"] = "synthetic-customer-free-prose"
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=mutation != "prose")


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_cache_identifier_literal_collision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], profile: str) -> None:
    """An actual legal cache name matching a metric interpretation remains protected."""
    original = SyntheticCacheSession.describe_cache_clusters

    def response(self: SyntheticCacheSession, **kwargs: object) -> dict[str, Any]:
        result = original(self, **kwargs)
        result["CacheClusters"][0]["CacheClusterId"] = "observed"
        return result

    monkeypatch.setattr(SyntheticCacheSession, "describe_cache_clusters", response)
    _case(tmp_path, monkeypatch, sdk_base, observe(CACHE, "success"), profile)


@pytest.mark.parametrize("mutation", ["unknown", "context", "status", "parts", "aggregate", "timestamp", "literal", "null_count"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_cache_metric_contract_rejects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], mutation: str, profile: str) -> None:
    """Malformed and inconsistent factual metrics cannot be hidden by strict output."""
    observed = observe(CACHE, "success")
    metric = observed["evidence"]["payload"]["records"][0]["metrics"][0]
    if mutation == "unknown":
        metric["unknown_metric_control"] = None
    elif mutation == "context":
        metric["collection_context"] = True
    elif mutation == "status":
        metric["collection_status"] = "customer-status"
    elif mutation == "parts":
        metric["observed_average_parts"] = [0, [True], 0]
    elif mutation == "aggregate":
        metric["observed_average"] = "9999"
    elif mutation == "timestamp":
        metric["start_time"] = "not-a-date"
    elif mutation == "literal":
        metric["metric_name"] = "customer-metric"
    else:
        observed["evidence"]["payload"]["records"][0]["total_node_count"] = None
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("scanner", [ECS, EKS, CACHE])
@pytest.mark.parametrize("mutation", ["customer", "foreign", "unknown", "literal"])
def test_managed_notes_still_reject_plaintext(scanner: str, mutation: str) -> None:
    """Public callback constants never conceal arbitrary values or foreign owners."""
    result = observe(scanner, "success")["execution"]
    operation = transformer("standard")
    protected = operation.transform({"scanner_results": [result]}, file_name="scan-result/scanner-results.json")
    assert not operation.summary.unclassified
    note = protected["scanner_results"][0]["coverage_notes"][0]
    if mutation == "customer":
        note["summary"] = scanner
    elif mutation == "foreign":
        protected["scanner_results"][0]["scanner_id"] = "untrusted-wrapper"
    elif mutation == "unknown":
        note["unknown_customer"] = scanner
    else:
        note["scope_area"] = scanner
    scan = ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-results.json", content=json.dumps(protected), known_original_values={scanner})
    assert not scan.passed


def test_actual_partial_service_response_retains_denial() -> None:
    """Keep the reproduced one-success/one-denied response limited after collection."""
    observed = observe(ECS, "partial")
    record = observed["evidence"]["payload"]["records"][0]
    assert record["service_count"] == 1
    assert "describe_services:AccessDeniedException" in record["permission_errors"]
    assert observed["execution"]["coverage_notes"][0]["permission_error_count"] > 0


@pytest.mark.parametrize("scanner", [ECS, EKS])
@pytest.mark.parametrize("literal", ["execution_detail", "managed_platform_metadata"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_managed_callback_identifier_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, literal: str, profile: str
) -> None:
    """Actual customer resource names matching finite note controls protect whole."""
    if scanner == ECS:
        original = SyntheticEcsSession.describe_services

        def response(self: SyntheticEcsSession, **kwargs: object) -> dict[str, Any]:
            result = original(self, **kwargs)
            result["services"][0]["serviceName"] = literal
            return result

        monkeypatch.setattr(SyntheticEcsSession, "describe_services", response)
    else:
        monkeypatch.setattr(SyntheticEksSession, "list_clusters", lambda *_a, **_k: {"clusters": [literal]})
    observed = observe(scanner, "success")
    assert literal in json.dumps(observed["evidence"]["payload"])
    _case(tmp_path, monkeypatch, sdk_base, observed, profile)
