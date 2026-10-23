"""Attribution unknown/malformed rejection, tuple roles and adversarial leak checks."""

from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING

import pytest

from tests.standalone.test_attribution_producer import FACTORIES
from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_attribution import flow, tagging
from unio_collector.privacy.closed_schema import ClosedProducerContract
from unio_collector.privacy.flow.contract import FlowPrivacyContract
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"


@pytest.mark.parametrize("scanner", FACTORIES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["unknown", "count", "null", "tags", "provider", "container", "category"])
def test_attribution_unknown_and_malformed_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, profile: str, mutation: str
) -> None:
    """Keep malformed fields, unknown descendants and foreign identities fail closed."""
    observed = FACTORIES[scanner]()
    row = observed["evidence"]
    payload, record = row["payload"], row["payload"]["records"][0]
    changes = {
        "unknown": (record, "unknown_attribution_field", None),
        "count": (record, "bytes", True) if scanner == flow.SCANNER else (payload, "analysis_inputs_version", True),
        "null": (record, "action", None) if scanner == flow.SCANNER else (payload, "required_tags_supplied", None),
        "tags": (record, "src_attribution_tags", {"synthetic.customer.COST[0]": None})
        if scanner == flow.SCANNER
        else (record, "tags", {"synthetic.customer.COST[0]": None}),
        "provider": (row, "provider_id", "foreign"),
        "container": (payload, "records", {}),
        "category": (record, "action", "unknown_customer_action") if scanner == flow.SCANNER else (record, "resource_type", "unknown_customer_type"),
    }
    target, key, value = changes[mutation]
    target[key] = value
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["unknown", "target_kind", "target_shape", "association", "cross_kind", "region", "timestamp", "period", "grouping"])
def test_flow_topology_unknown_and_pair_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], profile: str, mutation: str
) -> None:
    """Validate hidden topology and tuple contents before strict removal, preserving all input bytes."""
    observed = flow.flow_producer_observation()
    payload = observed["evidence"]["payload"]
    topology = payload["metadata"]["topology"]["eu-west-2"]
    route = next(fact for fact in topology["facts"] if fact["kind"] == "route")
    interface = next(fact for fact in topology["facts"] if fact["kind"] == "interface")
    changes = {
        "unknown": (route, "unknown_nested_route_field", None),
        "target_kind": (route, "targets", [["UnknownCustomerField", "synthetic-customer"]]),
        "target_shape": (route, "targets", [["NatGatewayId", "nat-synthetic", "extra"]]),
        "association": (route, "associations", [["subnet-synthetic", "unknown_customer_association"]]),
        "cross_kind": (interface, "targets", []),
        "region": (payload["metadata"]["topology"], "unknown-customer-region", {}),
        "timestamp": (payload["scan_period"], "current_start_date", "2026-01"),
        "period": (payload["scan_period"]["raw_input"], "days", 1),
        "grouping": (payload["metadata"]["queries"][0], "grouping", ["srcaddr", "action"]),
    }
    target, key, value = changes[mutation]
    target[key] = value
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["unknown", "source", "parent", "provider", "kind", "count", "api"])
def test_tagging_callback_unknown_and_identity_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], profile: str, mutation: str
) -> None:
    """Actual notes cannot borrow sibling kind fields or foreign parent identities."""
    observed = tagging.tagging_producer_observation("partial")
    notes = observed["execution"]["coverage_notes"]
    fast = next(note for note in notes if note["note_type"] == "fast_path_source")
    api = next(note for note in notes if note["note_type"] == "api_degradation")
    changes = {
        "unknown": (fast, "unknown_tagging_note", None),
        "source": (fast, "source", "foreign-source"),
        "parent": (observed["execution"], "scanner_id", "foreign"),
        "provider": (observed["execution"], "provider_id", "foreign"),
        "kind": (fast, "api_action", "elbv2:DescribeTags"),
        "count": (fast, "records_returned", True),
        "api": (api, "affected_fields", ["unknown_customer_field"]),
    }
    target, key, value = changes[mutation]
    target[key] = value
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("scanner", FACTORIES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["customer", "unknown", "foreign", "malformed", "boundary"])
def test_attribution_literal_and_token_boundaries(scanner: str, profile: str, mutation: str) -> None:
    """Registered actual tokens pass; customer plaintext still rejects under all identities."""
    operation = transformer(profile)
    source = {"scanner_evidence": [FACTORIES[scanner]("collision")["evidence"]]}
    protected = operation.transform(source, file_name=MEMBER)
    assert not operation.summary.unclassified
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scan = ProtectedArchiveLeakScanner()
    assert scan.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"ACCEPT"}, generated_tokens=generated).passed
    changed = copy.deepcopy(protected)
    row = changed["scanner_evidence"][0]
    record = row["payload"]["records"][0]
    field = "src_description" if scanner == flow.SCANNER else "resource_name"
    if mutation == "unknown":
        record["unknown_customer_field"] = "ACCEPT"
    elif mutation == "foreign":
        row["provider_id"] = "foreign"
        record[field] = "ACCEPT"
    elif mutation == "malformed":
        record["action" if scanner == flow.SCANNER else "resource_type"] = False
        record[field] = "ACCEPT"
    elif mutation == "boundary":
        record[field] += "ACCEPT"
    else:
        record[field] = "ACCEPT"
    result = scan.scan_text(path=MEMBER, content=json.dumps(changed), known_original_values={"ACCEPT"}, generated_tokens=generated)
    assert not result.passed
    assert any(finding.category == "known_original_value" for finding in result.findings)


def test_closed_sequence_default_is_unchanged() -> None:
    """Existing contracts keep their homogeneous paths and never opt into tuple behavior."""
    contract = ClosedProducerContract()
    assert contract.for_sequence(["first", "second"], "$.anything") is None
    assert contract.sequence_item_path("$.anything", 0) == "$.anything[]"
    assert contract.sequence_item_path("records[]", 1) == "records[][]"


def test_flow_tuple_controls_keep_positions_and_source() -> None:
    """The public target kind remains readable while its customer resource value protects."""
    source = {"scanner_evidence": [flow.flow_producer_observation()["evidence"]]}
    before = copy.deepcopy(source)
    operation = transformer("standard")
    result = operation.transform(source, file_name=MEMBER)
    assert source == before
    topology = result["scanner_evidence"][0]["payload"]["metadata"]["topology"]["eu-west-2"]
    route = next(fact for fact in topology["facts"] if fact["kind"] == "route")
    assert route["targets"][0][0] in {"NatGatewayId", "EgressOnlyInternetGatewayId"}
    assert route["targets"][0][1].startswith("RESOURCE-")
    assert {pair[1] for pair in route["associations"]} == {"main_vpc", "explicit_subnet"}
    assert not FlowPrivacyContract().unknown_paths(before["scanner_evidence"][0]["payload"], MEMBER)
