"""Actual serverless/lifecycle producer harness; privacy acceptance remains separate."""

from __future__ import annotations

from importlib import import_module
from unittest.mock import patch

import pytest

from tools.collector_serverless.fixture import COLLECTORS, LAMBDA, LIFECYCLE, POLLING, VARIANTS, serverless_producer_observation
from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS

pytestmark = pytest.mark.offline
CASES = [(scanner, variant) for scanner, variants in VARIANTS.items() for variant in variants]


@pytest.mark.parametrize(("scanner", "variant"), CASES)
def test_actual_serverless_producer_shapes(monkeypatch: pytest.MonkeyPatch, scanner: str, variant: str) -> None:
    """Run real wrappers/providers/callbacks; do not fabricate success for exceptions."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    module, name = COLLECTOR_SCANNER_CLASS_PATHS[scanner].split(":", 1)
    wrapper = COLLECTORS[scanner]
    assert wrapper is getattr(import_module(module), name)
    with patch.object(wrapper, "collect", autospec=True, side_effect=wrapper.collect) as invoked:
        observed = serverless_producer_observation(scanner, variant)
    assert invoked.call_count == 1
    assert observed["provider_calls"]
    assert observed["callbacks"]
    if (scanner, variant) == (LAMBDA, "unavailable"):
        assert observed["collection_exception"] == {"type": "ClientError", "code": "AccessDeniedException"}
        assert "evidence" not in observed
        assert "execution" not in observed
        return
    evidence = observed["evidence"]
    assert evidence["scanner_id"] == scanner
    assert evidence["serialization_status"] == "serialized"
    assert evidence["evidence_type"] == "InventoryEvidence"
    payload = evidence["payload"]
    assert set(payload) == {"records", "regions", "metadata"}
    if variant in {"success", "native"}:
        assert len(payload["records"]) == {LAMBDA: 2, POLLING: 2, LIFECYCLE: 7}[scanner]
        if scanner == LIFECYCLE:
            assert {row["service"] for row in payload["records"]} == {
                "Amazon RDS",
                "AWS Lambda",
                "Amazon EC2",
                "Amazon ElastiCache",
                "Amazon OpenSearch Service",
                "Amazon EKS",
            }
        else:
            assert all(record["metric_summaries"] for record in payload["records"])
            assert all(metric["observed_average"] is not None for record in payload["records"] for metric in record["metric_summaries"])
    if variant == "empty":
        assert payload["records"] == []
