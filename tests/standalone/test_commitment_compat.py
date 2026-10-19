"""Exact Glue operational threshold collisions retain customer and financial leak rejection."""

from __future__ import annotations

import copy
import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tools.collector_analytics.fixture import GLUE, analytics_producer_observation
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["customer", "unknown", "malformed", "foreign", "financial", "boundary"])
def test_glue_threshold_is_not_a_financial_or_customer_exemption(profile: str, mutation: str) -> None:
    """Actual typed configuration thresholds pass; raw customer values and borrowed identities reject."""
    row = analytics_producer_observation(GLUE)["evidence"]
    assert str(row["payload"]["records"][0]["configured_run_dpu"]) == "100.5"
    operation = transformer(profile)
    protected = operation.transform({"scanner_evidence": [row]}, file_name=MEMBER)
    assert not operation.summary.unclassified
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scan = ProtectedArchiveLeakScanner()
    assert scan.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"100.5"}, generated_tokens=generated).passed
    changed = copy.deepcopy(protected)
    record = changed["scanner_evidence"][0]["payload"]["records"][0]
    if mutation == "customer":
        record["sample_job_names"] = ["100.5"]
    elif mutation == "unknown":
        record["unknown_customer_threshold"] = None
    elif mutation == "malformed":
        record["configured_run_dpu"] = "100.5"
    elif mutation == "foreign":
        changed["scanner_evidence"][0]["provider_id"] = "foreign"
    elif mutation == "financial":
        record["service_current_cost"] = "100.5"
    else:
        record["sample_job_names"][0] += "100.5"
    checked = scan.scan_text(path=MEMBER, content=json.dumps(changed), known_original_values={"100.5"}, generated_tokens=generated)
    assert not checked.passed
    assert any(finding.category == "known_original_value" for finding in checked.findings)
