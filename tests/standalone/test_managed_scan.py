"""Adversarial checks for the reproduced cross-producer metadata collision roles."""

from __future__ import annotations

import copy
import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_managed.fixture import CACHE, managed_producer_observation
from unio_collector.privacy.leak.scan import PROTECTED_TOKEN_RE, ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["customer", "foreign", "unknown", "literal", "aggregate", "token_boundary"])
def test_cache_metric_normalization_does_not_hide_leaks(profile: str, mutation: str) -> None:
    """Finite metric metadata never hides arbitrary values or malformed parents."""
    evidence = json.loads(json.dumps(managed_producer_observation(CACHE)["evidence"]))
    operation = transformer(profile)
    protected = operation.transform({"scanner_evidence": [evidence]}, file_name="scan-result/scanner-evidence.json")
    assert not operation.summary.unclassified
    row = protected["scanner_evidence"][0]
    metric = row["payload"]["records"][0]["metrics"][0]
    literal = "observed"
    if mutation == "customer":
        metric["limitation"] = literal
    elif mutation == "foreign":
        row["scanner_id"] = "untrusted-wrapper"
    elif mutation == "unknown":
        metric["unknown_customer"] = literal
    elif mutation == "literal":
        metric["metric_name"] = literal
    elif mutation == "aggregate":
        metric["observed_average"] = "9999"
    else:
        metric["limitation"] = "RESOURCE-AAAAAAAAAAAAAAAA" + literal
    scan = ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={literal})
    assert not scan.passed


@pytest.mark.parametrize("member", ["manifest.json", "permissions-summary.json", "permissions/degradation-records.json"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["customer", "foreign", "unknown"])
def test_permission_metadata_does_not_hide_customer_values(sdk_base: dict[str, bytes], member: str, profile: str, mutation: str) -> None:
    """Actual protected protocol envelopes still reject plaintext at every boundary."""
    source = json.loads(sdk_base[member])
    operation = transformer(profile)
    protected = operation.transform(source, file_name=member)
    assert not operation.summary.unclassified
    generated = frozenset(PROTECTED_TOKEN_RE.findall(json.dumps(protected)))
    if mutation == "customer":
        protected["limitations"] = ["observed"]
    elif mutation == "foreign":
        protected["provider_id"] = "untrusted-provider"
    else:
        protected["unknown_customer"] = "observed"
    scan = ProtectedArchiveLeakScanner().scan_text(path=member, content=json.dumps(protected), known_original_values={"observed"}, generated_tokens=generated)
    assert not scan.passed


@pytest.mark.parametrize("value", ["observed", True, {}, ["observed"]])
def test_pricing_key_normalization_rejects_malformed(value: object) -> None:
    """The exact operational numeric key cannot exempt malformed customer content."""
    document = {"schema_version": "2026-01", "observed_pages_per_lookup": value}
    before = copy.deepcopy(document)
    scan = ProtectedArchiveLeakScanner().scan_text(path="scan-result/pricing-context.json", content=json.dumps(document), known_original_values={"observed"})
    assert not scan.passed
    assert document == before
