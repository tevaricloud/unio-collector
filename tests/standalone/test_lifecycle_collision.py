"""Cross-producer lifecycle collisions retain customer and untrusted leak rejection."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_storage_fixture import SCANNERS, storage_producer_case
from tools.collector_vpc_fixture import vpc_producer_case
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline


def _scan(row: dict) -> bool:
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json",
        content=json.dumps({"scanner_evidence": [row]}),
        known_original_values={"available"},
    )
    return result.passed


@pytest.mark.parametrize("scanner", SCANNERS[:2])
def test_storage_lifecycle_collision_does_not_hide_customer_values(scanner: str) -> None:
    """Only the reviewed finite state role masks, never identifiers or tags."""
    source, _, _ = storage_producer_case(scanner)
    operation = transformer("standard")
    row = operation.transform({"scanner_evidence": [source]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]
    assert not operation.summary.unclassified
    assert _scan(row)
    for field in ("volume_id", "tags"):
        leaked = deepcopy(row)
        leaked["payload"]["records"][0][field] = "available" if field == "volume_id" else {"Name": "available"}
        assert not _scan(leaked)
    malformed = deepcopy(row)
    malformed["payload"]["records"][0]["state"] = "available-customer"
    assert not _scan(malformed)
    row["scanner_id"] = "untrusted-lifecycle-producer"
    assert not _scan(row)


def test_network_enum_collision_is_kind_bound_and_preserves_plaintext() -> None:
    """Full kind admission precedes masking; customer, malformed and unknown facts scan."""
    source = vpc_producer_case()
    operation = transformer("standard")
    row = operation.transform({"scanner_evidence": [source]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]
    assert not operation.summary.unclassified
    assert _scan(row)
    resource = next(r for t in row["payload"]["topology"] for r in t["resources"] if r["kind"] == "nat_gateways")
    assert resource["facts"]["State"] == "available"
    for field, value in (("NatGatewayId", "available"), ("State", "available-customer"), ("unknown_customer", "available")):
        leaked = deepcopy(row)
        target = next(r for t in leaked["payload"]["topology"] for r in t["resources"] if r["kind"] == "nat_gateways")
        target["facts"][field] = value
        assert not _scan(leaked)
    wrong_kind = deepcopy(row)
    target = next(r for t in wrong_kind["payload"]["topology"] for r in t["resources"] if r["kind"] == "nat_gateways")
    target["kind"] = "subnets"
    assert not _scan(wrong_kind)
    row["scanner_id"] = "untrusted-network-producer"
    assert not _scan(row)
