"""Actual cache/deadline callbacks: closed schema, protection and adversarial checks."""

from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import observe as sdk_observe
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_cache_fixture import actual_cache_notes
from tools.collector_managed.fixture import managed_producer_observation
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", tuple(COLLECTOR_SCANNER_CLASS_PATHS))
@pytest.mark.parametrize("kind", ["loaded", "hit", "waited", "deadline"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_common_callbacks_classify(scanner: str, kind: str, profile: str) -> None:
    """Every real collector parent admits only the actual producer's closed shapes."""
    notes = actual_cache_notes(scanner, kind)
    assert len(notes) == (0 if kind == "loaded" else 1)
    value = {"scanner_results": [{"scanner_id": scanner, "coverage_notes": notes}]}
    before = copy.deepcopy(value)
    operation = transformer(profile)
    protected = operation.transform(value, file_name="scan-result/scanner-results.json")
    assert not operation.summary.unclassified
    assert value == before
    encoded = json.dumps(protected)
    if notes:
        assert notes[0]["cache_label"] not in encoded
        assert notes[0]["cache_namespace"] not in encoded
        assert notes[0]["summary"] not in encoded


@pytest.mark.parametrize("scanner", ["athena-query-efficiency-review", "ecs-cost-governance-review"])
@pytest.mark.parametrize("kind", ["hit", "waited", "deadline"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_callback_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, kind: str, profile: str) -> None:
    """Protect actual collector and common callback output, validate and verify receipt."""
    observed = managed_producer_observation(scanner) if scanner.startswith("ecs-") else sdk_observe(scanner, "success")
    observed["execution"]["coverage_notes"].extend(actual_cache_notes(scanner, kind))
    _case(tmp_path, monkeypatch, sdk_base, observed, profile)


@pytest.mark.parametrize("mutation", ["unknown", "null", "pair", "kind", "foreign", "provider"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_common_callback_rejection_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], mutation: str, profile: str) -> None:
    """Unknown/null/malformed/action-conflicting/foreign callbacks fail without artifacts."""
    scanner = "ecs-cost-governance-review"
    observed = managed_producer_observation(scanner)
    note = actual_cache_notes(scanner, "hit")[0]
    if mutation == "unknown":
        note["unknown_cache_control"] = None
    elif mutation == "null":
        note["cache_namespace"] = None
    elif mutation == "pair":
        note["cache_action"] = "waited for"
    elif mutation == "kind":
        note["note_type"] = "untrusted_cache_note"
    elif mutation == "foreign":
        observed["execution"]["scanner_id"] = "untrusted-wrapper"
    else:
        observed["execution"]["provider_id"] = "azure"
    observed["execution"]["coverage_notes"].append(note)
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("mutation", ["customer", "namespace", "unknown", "pair", "foreign", "provider", "boundary"])
def test_common_note_scan_rejects_plaintext(mutation: str) -> None:
    """Finite controls cannot exempt text, malformed notes, foreign roots or token suffixes."""
    scanner = "ecs-cost-governance-review"
    operation = transformer("standard")
    value = {"scanner_results": [{"scanner_id": scanner, "coverage_notes": actual_cache_notes(scanner, "hit")}]}
    protected = operation.transform(value, file_name="scan-result/scanner-results.json")
    assert not operation.summary.unclassified
    row = protected["scanner_results"][0]
    note = row["coverage_notes"][0]
    literal = "cached_evidence_reuse"
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    baseline = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-results.json", content=json.dumps(protected), known_original_values={literal}, generated_tokens=generated
    )
    assert baseline.passed, baseline.findings
    if mutation == "customer":
        note["summary"] = literal
    elif mutation == "namespace":
        note["cache_namespace"] = literal
    elif mutation == "unknown":
        note["unknown_customer"] = literal
    elif mutation == "pair":
        note["cache_action"] = "waited for"
    elif mutation == "foreign":
        row["scanner_id"] = "untrusted-wrapper"
    elif mutation == "provider":
        row["provider_id"] = "azure"
    else:
        note["summary"] = "RESOURCE-AAAAAAAAAAAAAAAA" + literal
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-results.json", content=json.dumps(protected), known_original_values={literal}, generated_tokens=generated
    )
    assert not result.passed
    assert any(finding.category == "known_original_value" for finding in result.findings)
