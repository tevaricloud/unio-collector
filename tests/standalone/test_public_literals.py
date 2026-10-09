"""Finite public metadata must not hide customer values with the same text."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tools.collector_transit_fixture import SCANNER, transit_producer_case
from unio_collector.privacy.ec2.load_balancer import LoadBalancerPrivacyContract
from unio_collector.privacy.leak.public.metadata import is_public_payload_literal
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.leak.structure import known_value_scan_content
from unio_collector.privacy.network.vpc import VpcEndpointPrivacyContract

pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"


def test_network_identity_and_fixed_versions_are_not_customer_content() -> None:
    """Actual producer metadata may legitimately overlap a tokenised tag value."""
    row = transit_producer_case()
    result = ProtectedArchiveLeakScanner().scan_text(path=MEMBER, content=json.dumps({"scanner_evidence": [row]}), known_original_values={"network"})
    assert not any(f.category == "known_original_value" for f in result.findings)
    assert any(f.category == "aws_account_id" for f in result.findings)


@pytest.mark.parametrize("location", ["tag", "unknown_key", "unknown_parent", "version", "module", "scanner", "text", "literal_path", "wrong_kind"])
def test_public_metadata_mask_does_not_hide_other_network_text(location: str) -> None:
    """Unknown identities, containers and customer values remain scanned."""
    row = transit_producer_case()
    if location == "tag":
        row["payload"]["topology"][0]["resources"][0]["facts"]["Tags"] = [{"Key": "Owner", "Value": "network"}]
    elif location == "unknown_key":
        row["payload"]["network"] = None
    elif location == "unknown_parent":
        row["payload"]["foreign"] = {"selection_version": "network-whole-record-v1"}
    elif location == "version":
        row["payload"]["network_evidence_version"] = "network-private-version"
    elif location == "module":
        row["evidence_module"] += ".network"
    elif location == "scanner":
        row["scanner_id"] += "-network"
    elif location == "wrong_kind":
        row["payload"]["topology"][0]["resources"][0].update(kind="addresses", facts={"ResourceType": "network-function"})
    elif location == "text":
        row["limitations"] = ["network"]
    else:
        row["payload"]["topology[].selection_version"] = "network-whole-record-v1"
    result = ProtectedArchiveLeakScanner().scan_text(path=MEMBER, content=json.dumps({"scanner_evidence": [row]}), known_original_values={"network"})
    assert any(f.category == "known_original_value" for f in result.findings)


@pytest.mark.parametrize("member", ["analysis-readiness.json", "collection-summary.json", "scan-result/scanner-results.json"])
@pytest.mark.parametrize("mutation", ["none", "customer", "unknown_id", "wrong_path", "wrong_type", "duplicate"])
def test_only_exact_reference_positions_are_public(member: str, mutation: str) -> None:
    """No suffix matching, arbitrary IDs, malformed containers or duplicate keys."""
    document: dict[str, Any] = {"scanner_evidence_coverage": {"selected_scanner_ids": [SCANNER]}}
    if member == "collection-summary.json":
        document = {"strict_analysis_readiness": document}
    elif member == "scan-result/scanner-results.json":
        document = {"scanner_results": [{"scanner_id": SCANNER}]}
    if mutation == "customer":
        document["customer"] = "network"
    if mutation == "wrong_path":
        document = {"foreign": document}
    content = json.dumps(document)
    if mutation == "unknown_id":
        content = content.replace(SCANNER, SCANNER + "-private")
    if mutation == "wrong_type":
        content = content.replace('"' + SCANNER + '"', '{"network": null}')
    if mutation == "duplicate":
        content = content[:-1] + ', "network": 1, "network": 2}'
    result = ProtectedArchiveLeakScanner().scan_text(path=member, content=content, known_original_values={"network"})
    assert any(f.category == "known_original_value" for f in result.findings) is (mutation != "none")
    assert known_value_scan_content("other.json", content) == content


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        ("records[].load_balancer_type", "network", True),
        ("records[].load_balancer_type", "network-private", False),
        ("records[].load_balancer_name", "network", False),
        ("foreign.load_balancer_type", "network", False),
    ],
)
def test_balancer_public_type_has_exact_finite_boundary(path: str, value: str, *, expected: bool) -> None:
    """A network load-balancer type is public; a name or unrecognized type is not."""
    assert is_public_payload_literal(LoadBalancerPrivacyContract(), path, value) is expected


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        ("records[].sample_candidate_network_interface_contexts[].interface_type", "network_load_balancer", True),
        ("records[].sample_candidate_network_interface_contexts[].interface_type", "network-private", False),
        ("records[].vpc_tags.Owner", "network_load_balancer", False),
        ("foreign.interface_type", "network_load_balancer", False),
        ("records[].sample_candidate_network_interface_contexts[].requester_managed", "true", True),
        ("records[].sample_candidate_network_interface_contexts[].requester_managed", "false", False),
        ("records[].vpc_tags.Owner", "true", False),
        ("foreign.requester_managed", "true", False),
    ],
)
def test_vpc_provider_type_literal_boundary(path: str, value: str, *, expected: bool) -> None:
    """Finite provider type text is public only at its declared context field."""
    assert is_public_payload_literal(VpcEndpointPrivacyContract(), path, value) is expected
