"""Adversarial checks for narrowly owned edge metadata and raw strict admission."""

from __future__ import annotations

import copy
import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_edge.fixture import COLLECTORS, edge_producer_observation
from unio_collector.privacy.edge.alb import AlbOriginPrivacyContract
from unio_collector.privacy.edge.cost import CloudFrontCostPrivacyContract
from unio_collector.privacy.edge.coverage import EdgeCoverageContract
from unio_collector.privacy.edge.regional import EdgeRegionalCoverageContract
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"
ALB, COST = tuple(COLLECTORS)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("mutation", ["customer", "unknown", "provider", "identity", "malformed", "boundary"])
def test_edge_literal_roles_keep_customer_leaks_visible(profile: str, scanner: str, mutation: str) -> None:
    """Actual generated tokens pass; plaintext, invalid siblings and borrowed roles fail."""
    operation = transformer(profile)
    source = {"scanner_evidence": [edge_producer_observation(scanner, "collision")["evidence"]]}
    protected = operation.transform(source, file_name=MEMBER)
    assert not operation.summary.unclassified
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scan = ProtectedArchiveLeakScanner()
    assert scan.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"HTTPS"}, generated_tokens=generated).passed
    changed = copy.deepcopy(protected)
    row = changed["scanner_evidence"][0]
    record = row["payload"]["cloudfront_origins"][0] if scanner == ALB else row["payload"]["records"][0]
    identity = "origin_id" if scanner == ALB else "sample_distribution_ids"
    if mutation == "customer":
        record[identity] = "HTTPS" if scanner == ALB else ["HTTPS"]
    elif mutation == "unknown":
        record["unknown_edge_customer"] = "HTTPS"
    elif mutation == "provider":
        row["provider_id"] = "foreign"
        record[identity] = "HTTPS" if scanner == ALB else ["HTTPS"]
    elif mutation == "identity":
        row["evidence_type"] += "Foreign"
        record[identity] = "HTTPS" if scanner == ALB else ["HTTPS"]
    elif mutation == "malformed":
        record["enabled" if scanner == ALB else "distribution_count"] = None
        record[identity] = "HTTPS" if scanner == ALB else ["HTTPS"]
    else:
        token = record[identity] if scanner == ALB else record[identity][0]
        record[identity] = token + "HTTPS" if scanner == ALB else [token + "HTTPS"]
    result = scan.scan_text(path=MEMBER, content=json.dumps(changed), known_original_values={"HTTPS"}, generated_tokens=generated)
    assert not result.passed
    assert any(finding.category == "known_original_value" for finding in result.findings)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_generated_global_scope_does_not_preserve_customer_named_global(profile: str) -> None:
    """Scope discriminator and status both matter; no global substring exemption exists."""
    prefix = "$.scanner_evidence[].payload.coverage[].scope_id"
    for evidence_type, status in (("cloudfront_origins", "collected"), ("vpc_origin_detail", "not_applicable")):
        control = EdgeCoverageContract(evidence_type, status)
        decision = control.resolve_string(prefix, "global", profile)
        assert decision is not None
        assert decision.treatment == "preserve"
    customer = EdgeCoverageContract("vpc_origin_detail", "collected")
    decision = customer.resolve_string(prefix, "global", profile)
    assert decision is not None
    assert decision.treatment == "tokenise"
    scope = EdgeRegionalCoverageContract("managed_prefix_lists", "collected")
    assert scope.fields["coverage[].scope_id"][1] == "region"


def test_strict_scan_view_does_not_admit_raw_null_pricing_class_or_unknowns() -> None:
    """Scan-only strict redactions never loosen raw source contract validation."""
    contract = CloudFrontCostPrivacyContract()
    row = edge_producer_observation(COST)["evidence"]["payload"]["records"][0]
    row["sample_price_classes"] = None
    assert contract.unknown_paths(row, MEMBER, "records[]")
    assert contract.admitted_scan_container(row, "records[]")
    row["unknown_customer"] = "HTTPS"
    assert not contract.admitted_scan_container(row, "records[]")


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_operational_price_class_count_and_strict_omission(profile: str) -> None:
    """A price-class counter is an operational fact; the strict sample omission remains."""
    source = {"scanner_evidence": [edge_producer_observation(COST)["evidence"]]}
    operation = transformer(profile)
    protected = operation.transform(source, file_name=MEMBER)
    assert not operation.summary.unclassified
    record = protected["scanner_evidence"][0]["payload"]["records"][0]
    assert record["price_class_all_count"] == source["scanner_evidence"][0]["payload"]["records"][0]["price_class_all_count"]
    assert (record["sample_price_classes"] is None) == (profile == "strict")


def test_invalid_finite_origin_kind_and_histogram_still_reject() -> None:
    """Unknown finite metadata or malformed bins cannot obtain public metadata views."""
    alb = AlbOriginPrivacyContract()
    row = edge_producer_observation(ALB)["evidence"]["payload"]
    row["cloudfront_origins"][0]["origin_kind"] = "unknown-customer-kind"
    assert alb.unknown_paths(row, MEMBER)
    assert not alb.admitted_scan_container(row, "")
    cost = CloudFrontCostPrivacyContract()
    row = edge_producer_observation(COST)["evidence"]["payload"]
    row["records"][0]["behavior_histogram"]["counts"] = [0, True]
    assert cost.unknown_paths(row, MEMBER)
    assert not cost.admitted_scan_container(row, "")
