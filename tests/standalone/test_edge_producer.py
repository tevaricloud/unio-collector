"""Actual populated edge producers, strict/standard receipts and rejection cleanup."""

from __future__ import annotations

import copy
from dataclasses import fields
from importlib import import_module
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_edge.fixture import COLLECTORS, VARIANTS, edge_producer_observation
from unio_collector.aws.cloudfront.distribution import CloudFrontDistributionRecord
from unio_collector.privacy.edge.fields import ALB, COST
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS
from unio_collector.scanners.network.cloudfront_alb_protection.evidence import CloudFrontAlbOriginProtectionEvidence

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
ALB_ID, COST_ID = tuple(COLLECTORS)
ERRORS = {"denied", "unavailable", "unsupported", "failure"}
CASES = [(scanner, variant) for scanner in COLLECTORS for variant in VARIANTS if not (scanner == COST_ID and variant in ERRORS)]


@pytest.mark.parametrize("scanner", COLLECTORS)
def test_edge_registered_owner(scanner: str) -> None:
    """No facade or manually constructed DTO substitutes for the live wrapper owner."""
    module, name = COLLECTOR_SCANNER_CLASS_PATHS[scanner].split(":")
    assert COLLECTORS[scanner] is getattr(import_module(module), name)


@pytest.mark.parametrize(("scanner", "variant"), CASES)
def test_edge_actual_source(scanner: str, variant: str) -> None:
    """Require real calls/callbacks and prove success is populated, not a failed empty collection."""
    original = COLLECTORS[scanner].collect
    with patch.object(COLLECTORS[scanner], "collect", autospec=True, side_effect=original) as observed:
        result = edge_producer_observation(scanner, variant)
    assert observed.call_count == 1
    assert result["callbacks"]
    assert result["operations"]
    assert result["evidence"]["serialization_status"] == "serialized"
    payload = result["evidence"]["payload"]
    if scanner == ALB_ID:
        assert bool(payload["cloudfront_origins"]) == (variant not in ERRORS | {"empty"})
        if variant in ERRORS:
            assert payload["limitations"]
            assert result["execution"]["warnings"]
        if variant == "vpc":
            assert payload["vpc_origins"][0]["endpoint_arn"]
            assert payload["header_verifications"][0]["match_state"] == "matched"
        assert "synthetic-transient-header-only" not in str(result)
    else:
        assert payload["records"][0]["distribution_count"] == (0 if variant == "empty" else 1)
        assert result["execution"]["coverage_notes"]
        if variant == "metrics":
            assert "get_metric_data" in result["operations"]
            assert payload["records"][0]["metric_collection_status"] == "collected"
            assert payload["records"][0]["metric_datapoint_count"] > 0
        if variant == "summary":
            assert "list_invalidations" not in result["operations"]
            assert payload["records"][0]["invalidation_detail_collected"] is False


@pytest.mark.parametrize("variant", sorted(ERRORS))
def test_edge_top_level_failure_is_not_serialized_success(variant: str) -> None:
    """The existing inventory contract propagates unavailable top-level distribution evidence."""
    with pytest.raises(ClientError):
        edge_producer_observation(COST_ID, variant)


def test_edge_declared_dto_fields() -> None:
    """Independent DTO inventories detect new fields even when fixtures leave them empty."""

    def direct(specs: dict, prefix: str) -> set[str]:
        return {
            key.removeprefix(prefix)
            for key in specs
            if key.startswith(prefix) and key != prefix and not any(char in key.removeprefix(prefix) for char in ".[]")
        }

    assert direct(ALB, "") == {field.name for field in fields(CloudFrontAlbOriginProtectionEvidence)}
    assert direct(COST, "records[].") == {field.name for field in fields(CloudFrontDistributionRecord)}


@pytest.mark.parametrize(("scanner", "variant"), CASES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_edge_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, variant: str, profile: str) -> None:
    """Actual producer shapes pass independent validation, receipts and full leak scans."""
    _case(tmp_path, monkeypatch, sdk_base, edge_producer_observation(scanner, variant), profile)


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("mutation", ["unknown", "container", "count", "null", "provider", "literal", "note", "parent"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_edge_negative_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, mutation: str, profile: str) -> None:
    """Unknown nested fields, malformed values and mismatched identities leave no artifacts."""
    observed = edge_producer_observation(scanner)
    payload = observed["evidence"]["payload"]
    record = payload["cloudfront_origins"][0] if scanner == ALB_ID else payload["records"][0]
    changes = {
        "unknown": (record, "unknown_edge_control", None),
        "container": (payload, "cloudfront_origins" if scanner == ALB_ID else "records", {}),
        "count": (record, "http_port" if scanner == ALB_ID else "distribution_count", True),
        "null": (record, "enabled" if scanner == ALB_ID else "invalidation_detail_collected", None),
        "provider": (observed["evidence"], "provider_id", "foreign"),
    }
    if mutation in changes:
        target, key, value = changes[mutation]
        target[key] = value
    elif mutation == "literal" and scanner == COST_ID:
        record["behavior_histogram"]["counts"].append(0)
    elif mutation == "note" and scanner == COST_ID:
        observed["execution"]["coverage_notes"][0]["unknown_edge_note"] = None
    elif mutation == "parent" and scanner == COST_ID:
        observed["execution"]["scanner_id"] = "foreign"
    elif mutation == "note":
        payload["coverage"][0]["unknown_coverage"] = None
    else:
        record["origin_kind"] = "unknown-customer-kind" if mutation == "literal" else False
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("scanner", COLLECTORS)
def test_edge_customer_literal_collision_and_untrusted_negatives(scanner: str) -> None:
    """A customer named HTTPS must protect, while foreign and unknown plaintext still rejects."""
    import json  # noqa: PLC0415

    row = edge_producer_observation(scanner, "collision")["evidence"]
    for profile in ("standard", "strict"):
        checked = transformer(profile)
        result = checked.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
        assert checked.summary.unclassified == []
        assert "synthetic-customer-origin" not in str(result)
    for mutation in ("provider", "unknown"):
        changed = copy.deepcopy(row)
        if mutation == "provider":
            changed["provider_id"] = "foreign"
        else:
            changed["payload"]["unknown_customer_field"] = "HTTPS"
        scanned = ProtectedArchiveLeakScanner().scan_text(
            path="scan-result/scanner-evidence.json", content=json.dumps({"scanner_evidence": [changed]}), known_original_values={"HTTPS"}
        )
        assert not scanned.passed
        assert any(finding.category == "known_original_value" for finding in scanned.findings)


@pytest.mark.parametrize(
    ("collection", "name"),
    [
        ("cloudfront_origins", "CloudFrontAlbOriginRecord"),
        ("load_balancers", "AlbOriginLoadBalancerRecord"),
        ("listeners", "AlbOriginListenerRecord"),
        ("listener_rules", "AlbOriginListenerRuleRecord"),
        ("vpc_origins", "CloudFrontVpcOriginRecord"),
        ("header_verifications", "OriginHeaderVerificationRecord"),
        ("coverage", "OriginProtectionCoverageRecord"),
        ("security_group_rules", "AlbOriginSecurityGroupRuleRecord"),
        ("waf_associations", "AlbOriginWafAssociationRecord"),
    ],
)
def test_edge_nested_dto_inventory(collection: str, name: str) -> None:
    """Compare every emitted nested DTO with the explicit static privacy field inventory."""
    module = import_module(CloudFrontAlbOriginProtectionEvidence.__module__)
    prefix = collection + "[]."
    declared = {key.removeprefix(prefix) for key in ALB if key.startswith(prefix) and not any(char in key.removeprefix(prefix) for char in ".[]")}
    assert declared == {field.name for field in fields(getattr(module, name))}
