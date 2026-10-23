"""Actual Glue/SageMaker producers, complete DTOs and fail-closed protection."""

from __future__ import annotations

import copy
import json
from dataclasses import fields
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_analytics.fixture import GLUE, OPENSEARCH, REDSHIFT, SAGEMAKER, VARIANTS, analytics_producer_observation
from tools.collector_analytics.search import SyntheticSearchSession
from tools.collector_analytics.session import SyntheticAnalyticsSession
from tools.collector_sdk_fixture import WRAPPERS
from unio_collector.aws.glue.region_record import GlueRegionRecord
from unio_collector.aws.opensearch.region_record import OpenSearchRegionRecord
from unio_collector.aws.redshift.region_record import RedshiftRegionRecord
from unio_collector.aws.sagemaker.region_record import SageMakerRegionRecord
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.selection import select_producer_contract

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
EXPECTED_POPULATED_COUNT = 2
CASES = [(scanner, variant, billing) for scanner, variants in VARIANTS.items() for variant in variants for billing in (True, False)]


@pytest.fixture(autouse=True)
def forbid_live_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Actual collection uses in-memory providers; SDK construction is forbidden."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))


def observe(scanner: str, variant: str, *, billing: bool = True) -> dict[str, Any]:
    """Observe the actual wrapper with original return value and callback order."""
    wrapper = WRAPPERS[scanner]
    original = wrapper.collect
    with patch.object(wrapper, "collect", autospec=True, side_effect=original) as called:
        observed = analytics_producer_observation(scanner, variant, billing=billing)
    assert called.call_count == 1
    assert observed["evidence"]["serialization_status"] == "serialized"
    assert observed["callbacks"]
    assert observed["provider_calls"]
    if scanner == GLUE and variant == "malformed":
        assert not observed["evidence"]["payload"]["records"]
        assert observed["statuses"] == ["failed"]
        assert observed["diagnostic_warnings"]
    else:
        assert observed["evidence"]["payload"]["records"]
    if variant == "success":
        record = observed["evidence"]["payload"]["records"][0]
        count = {GLUE: "job_count", SAGEMAKER: "notebook_count", OPENSEARCH: "domain_count", REDSHIFT: "cluster_count"}[scanner]
        assert record[count] == EXPECTED_POPULATED_COUNT
        samples = [value for key, value in record.items() if key.startswith("sample_")]
        assert samples
        assert all(samples)
    return observed


@pytest.mark.parametrize(("scanner", "variant", "billing"), CASES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_analytics_producer_protection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, variant: str, *, billing: bool, profile: str
) -> None:
    """Protect actual callbacks and evidence, validate independently and verify receipt."""
    _case(tmp_path, monkeypatch, sdk_base, observe(scanner, variant, billing=billing), profile)


@pytest.mark.parametrize(
    ("scanner", "record_type"),
    [(GLUE, GlueRegionRecord), (SAGEMAKER, SageMakerRegionRecord), (OPENSEARCH, OpenSearchRegionRecord), (REDSHIFT, RedshiftRegionRecord)],
)
def test_complete_actual_analytics_dto_fields(scanner: str, record_type: type) -> None:
    """Every actual DTO field has an explicit contract, including nullable fields."""
    row = observe(scanner, "success")["evidence"]
    contract = select_producer_contract(row)
    assert contract is not None
    assert {field.name for field in fields(record_type)} == set(row["payload"]["records"][0])
    assert {"records[]." + field.name for field in fields(record_type)} <= set(contract.fields)
    assert not contract.unknown_record_paths(row, "scan-result/scanner-evidence.json")


@pytest.mark.parametrize("scanner", [GLUE, SAGEMAKER, OPENSEARCH, REDSHIFT])
@pytest.mark.parametrize(
    "mutation", ["unknown_payload", "unknown_note", "boolean_count", "foreign_note", "literal_note", "null_identifier", "cost_object", "note_null", "prose"]
)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_analytics_unknown_malformed_and_prose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, mutation: str, profile: str
) -> None:
    """Unknown and malformed values fail before omission; arbitrary prose protects."""
    observed = observe(scanner, "success")
    record = observed["evidence"]["payload"]["records"][0]
    note = observed["execution"]["coverage_notes"][0]
    if mutation == "unknown_payload":
        record["unknown_analytics_control"] = None
    elif mutation == "unknown_note":
        note["detail_counts"]["unknown_analytics_note"] = None
    elif mutation == "boolean_count":
        record[{GLUE: "job_count", SAGEMAKER: "notebook_count", OPENSEARCH: "domain_count", REDSHIFT: "cluster_count"}[scanner]] = True
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


@pytest.mark.parametrize("mutation", ["width", "rows", "counts", "missing", "unknown", "nonfinite"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_glue_numeric_contract_rejection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], mutation: str, profile: str) -> None:
    """Wrong width, malformed, missing, unknown and inconsistent rows reject safely."""
    observed = observe(GLUE, "success")
    numeric = observed["evidence"]["payload"]["records"][0]["job_numeric_evidence"]
    if mutation == "width":
        numeric["field_count"] = 3
    elif mutation == "rows":
        numeric["rows"][0].append(1)
    elif mutation == "counts":
        numeric["omitted_count"] = 1
    elif mutation == "missing":
        del numeric["seen_count"]
    elif mutation == "unknown":
        numeric["unknown_analytics_control"] = None
    else:
        numeric["rows"][0][0] = "nonfinite-number"
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("scanner", [GLUE, SAGEMAKER, OPENSEARCH, REDSHIFT])
@pytest.mark.parametrize(
    ("key", "value"),
    [("provider_id", "azure"), ("evidence_type", "ForeignEvidence"), ("evidence_module", "untrusted.foreign"), ("evidence_schema_version", True)],
)
def test_analytics_identity_rejects(scanner: str, key: str, value: object) -> None:
    """Recognized scanner names never admit conflicting provider/schema identities."""
    row = observe(scanner, "success")["evidence"]
    row[key] = value
    with pytest.raises(ValueError, match="[Ss]chema"):
        select_producer_contract(row)


@pytest.mark.parametrize("scanner", [GLUE, SAGEMAKER, OPENSEARCH, REDSHIFT])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_analytics_source_classification_preserves_input(scanner: str, profile: str) -> None:
    """Both complete actual schemas classify without mutating the input DTO."""
    observed = observe(scanner, "success")
    before = copy.deepcopy(observed)
    operation = transformer(profile)
    operation.transform({"scanner_evidence": [observed["evidence"]]}, file_name="scan-result/scanner-evidence.json")
    operation.transform({"scanner_results": [observed["execution"]]}, file_name="scan-result/scanner-results.json")
    assert not operation.summary.unclassified
    assert observed == before


@pytest.mark.parametrize("scanner", [GLUE, SAGEMAKER, OPENSEARCH, REDSHIFT])
@pytest.mark.parametrize("mutation", ["customer", "foreign", "unknown", "literal"])
def test_analytics_notes_still_reject_plaintext(scanner: str, mutation: str) -> None:
    """Exact public controls cannot hide customer strings or untrusted identities."""
    original = scanner
    result = observe(scanner, "success")["execution"]
    operation = transformer("standard")
    protected = operation.transform({"scanner_results": [result]}, file_name="scan-result/scanner-results.json")
    assert not operation.summary.unclassified
    note = protected["scanner_results"][0]["coverage_notes"][0]
    if mutation == "customer":
        note["summary"] = original
    elif mutation == "foreign":
        protected["scanner_results"][0]["scanner_id"] = "untrusted-wrapper"
    elif mutation == "unknown":
        note["unknown_customer"] = original
    else:
        note["scope_area"] = original
    scan = ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-results.json", content=json.dumps(protected), known_original_values={original})
    assert not scan.passed


@pytest.mark.parametrize("scanner", [GLUE, SAGEMAKER, OPENSEARCH, REDSHIFT])
@pytest.mark.parametrize("literal", ["analytics_ai_metadata", "execution_detail"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_analytics_identifier_collisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, literal: str, profile: str
) -> None:
    """Actual sampled provider names equal to public note controls remain protected."""

    def rename(client: type, operation: str, rows_key: str, name_key: str) -> None:
        original = getattr(client, operation)

        def response(session: object, **kwargs: object) -> dict[str, Any]:
            result = original(session, **kwargs)
            rows = result[rows_key]
            assert len(rows) == EXPECTED_POPULATED_COUNT
            rows[0][name_key] = literal
            return result

        monkeypatch.setattr(client, operation, response)

    if scanner == GLUE:
        rename(SyntheticAnalyticsSession, "get_crawlers", "Crawlers", "Name")
    elif scanner == SAGEMAKER:
        rename(SyntheticAnalyticsSession, "list_notebook_instances", "NotebookInstances", "NotebookInstanceName")
    elif scanner == OPENSEARCH:
        rename(SyntheticSearchSession, "list_domain_names", "DomainNames", "DomainName")
        rename(SyntheticSearchSession, "describe_domains", "DomainStatusList", "DomainName")
    else:
        rename(SyntheticSearchSession, "describe_clusters", "Clusters", "ClusterIdentifier")
    observed = observe(scanner, "success")
    sample_key = {GLUE: "sample_crawler_names", SAGEMAKER: "sample_notebook_names", OPENSEARCH: "sample_domain_names", REDSHIFT: "sample_cluster_identifiers"}[
        scanner
    ]
    assert literal in observed["evidence"]["payload"]["records"][0][sample_key]
    _case(tmp_path, monkeypatch, sdk_base, observed, profile)


@pytest.mark.parametrize("scanner", [GLUE, SAGEMAKER, OPENSEARCH, REDSHIFT])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_analytics_explicit_profile_treatments(scanner: str, profile: str) -> None:
    """Sample identifiers protect whole while strict billing removal is retained."""
    row = observe(scanner, "success")["evidence"]
    operation = transformer(profile)
    protected = operation.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not operation.summary.unclassified
    before = row["payload"]["records"][0]
    after = protected["scanner_evidence"][0]["payload"]["records"][0]
    for key, values in before.items():
        if key.startswith("sample_"):
            assert len(after[key]) == len(values)
            assert all(protected_value != original for protected_value, original in zip(after[key], values, strict=True))

    assert after["service_current_cost"] == (before["service_current_cost"] if profile == "standard" else "")
    if scanner in {GLUE, SAGEMAKER}:
        assert (
            after["top_usage_type_costs"] is None
            if profile == "strict"
            else after["top_usage_type_costs"][0]["usage_type"] != before["top_usage_type_costs"][0]["usage_type"]
        )
    else:
        assert "top_usage_type_costs" not in after


@pytest.mark.parametrize("scanner", [GLUE, SAGEMAKER, OPENSEARCH, REDSHIFT])
@pytest.mark.parametrize("mutation", ["customer", "foreign", "unknown"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_analytics_payloads_still_reject_plaintext(scanner: str, mutation: str, profile: str) -> None:
    """Trusted structural keys never exempt customer strings or foreign payloads."""
    row = observe(scanner, "success")["evidence"]
    operation = transformer(profile)
    protected = operation.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not operation.summary.unclassified
    target = protected["scanner_evidence"][0]
    record = target["payload"]["records"][0]
    marker = "synthetic-customer-leak-marker"
    if mutation == "unknown":
        record["unknown_customer"] = marker
    else:
        next(value for key, value in record.items() if key.startswith("sample_") and value)[0] = marker
        if mutation == "foreign":
            target["provider_id"] = "untrusted-provider"
    scan = ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={marker})
    assert not scan.passed
    assert any(finding.category == "known_original_value" for finding in scan.findings)
