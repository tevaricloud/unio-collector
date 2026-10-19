"""Actual populated tag/flow wrappers, conditional producer branches and full protection."""

from __future__ import annotations

from dataclasses import fields
from importlib import import_module
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_attribution import flow, tagging
from unio_collector.aws.flow.observation import FlowObservation
from unio_collector.aws.taggable_resource_record import TaggableResourceRecord
from unio_collector.privacy.flow.record_fields import FIELDS as FLOW_FIELDS
from unio_collector.privacy.tagging.fields import FIELDS as TAG_FIELDS
from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS
from unio_collector.scanners.network.vpc_flow.attribution.collector import VpcFlowLogAttributionCollector
from unio_collector.scanners.tagging.collector import MissingCostTagsCollector

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
FACTORIES = {flow.SCANNER: flow.flow_producer_observation, tagging.SCANNER: tagging.tagging_producer_observation}
COLLECTORS = {flow.SCANNER: VpcFlowLogAttributionCollector, tagging.SCANNER: MissingCostTagsCollector}
TAGGED_RESOURCE_TYPES = {"VPC", "Subnet", "EC2 instance", "EBS volume", "Elastic IP", "NAT Gateway", "Load balancer", "Target group", "Auto Scaling group"}
COMPLETE_TOPOLOGY_FACTS = 4
ERRORS = {"denied", "unavailable", "unsupported", "failure"}
CASES = [(family.SCANNER, variant) for family in (flow, tagging) for variant in family.VARIANTS if variant not in ERRORS]


@pytest.mark.parametrize("scanner", FACTORIES)
def test_attribution_owner_matches_live_registry(scanner: str) -> None:
    """Keep the exercised wrapper tied to its independently registered source owner."""
    module, name = COLLECTOR_SCANNER_CLASS_PATHS[scanner].split(":")
    assert getattr(import_module(module), name) is COLLECTORS[scanner]


@pytest.mark.parametrize(("scanner", "variant"), CASES)
def test_actual_attribution_source(scanner: str, variant: str) -> None:
    """Observe actual SDK work, real gateway callbacks, conditional shapes and serialization."""
    original = COLLECTORS[scanner].collect
    with patch.object(COLLECTORS[scanner], "collect", autospec=True, side_effect=original) as called:
        observed = FACTORIES[scanner](variant)
    assert called.call_count == 1
    assert observed["callbacks"]
    assert observed["operations"]
    row = observed["evidence"]
    assert row["serialization_status"] == "serialized"
    assert row["scanner_id"] == scanner
    records = row["payload"]["records"]
    if variant == "empty" or (scanner == flow.SCANNER and variant in {"destination", "query_failure", "query_denied"}):
        assert records == []
        if variant != "empty":
            assert row["payload"]["metadata"]["collection_state"] == "unavailable"
        return
    assert records
    if scanner == tagging.SCANNER:
        _assert_tagging_source(row, records, observed, variant)
    else:
        _assert_flow_source(row, records, variant)


def _assert_tagging_source(row: dict, records: list, observed: dict, variant: str) -> None:
    """Require actual tag relationships, limitations and deferred-input flags."""
    if variant == "success":
        assert len(records) == len(TAGGED_RESOURCE_TYPES)
        assert {item["resource_type"] for item in records} == {
            "VPC",
            "Subnet",
            "EC2 instance",
            "EBS volume",
            "Elastic IP",
            "NAT Gateway",
            "Load balancer",
            "Target group",
            "Auto Scaling group",
        }
        assert next(item for item in records if item["resource_type"] == "EC2 instance")["associated_resource_type"] == "Target group"
    if variant == "deferred_defaults":
        assert row["payload"]["analysis_inputs_version"] == 1
        assert row["payload"]["required_tags_supplied"] is False
    if variant in {"partial", "tags_denied", "target_groups_denied", "target_health_denied", "asg_denied"}:
        assert observed["execution"]["warnings"]
    assert observed["execution"]["coverage_notes"]


def _assert_flow_source(row: dict, records: list, variant: str) -> None:
    """Distinguish complete, ambiguous, capped and period-specific actual flow evidence."""
    assert len(records) == 1
    metadata = row["payload"]["metadata"]
    topology = metadata["topology"]["eu-west-2"]
    if variant == "success":
        assert records[0]["src_address_status"] == "resolved_uniquely"
        assert records[0]["dst_address_status"] == "resolved_uniquely"
        assert topology["state"] == "complete"
        assert topology["facts_retained"] == COMPLETE_TOPOLOGY_FACTS
    if variant == "ambiguous":
        assert topology["state"] == "ambiguous"
        assert records[0]["src_address_status"] == "ambiguous"
    if variant in {"cap", "definitions_cap"}:
        assert metadata["collection_state"] == "capped"
    if variant in {"days", "months", "years"}:
        assert row["payload"]["scan_period"]["kind"] == variant


@pytest.mark.parametrize("scanner", FACTORIES)
@pytest.mark.parametrize("variant", sorted(ERRORS))
def test_unavailable_top_level_enumeration_does_not_become_empty_success(scanner: str, variant: str) -> None:
    """Retain existing propagation/fail-closed NAT enumeration rather than inventing success."""
    error = ClientError if scanner == flow.SCANNER else ValueError
    with pytest.raises(error):
        FACTORIES[scanner](variant)


@pytest.mark.parametrize(("specs", "dto"), [(FLOW_FIELDS, FlowObservation), (TAG_FIELDS, TaggableResourceRecord)])
def test_actual_attribution_dto_fields(specs: dict, dto: type) -> None:
    """Catch newly emitted optional fields independently of the generated fixture."""
    prefix = "records[]."
    declared = {path.removeprefix(prefix) for path in specs if path.startswith(prefix) and not any(char in path.removeprefix(prefix) for char in ".[]")}
    assert declared == {field.name for field in fields(dto)}


@pytest.mark.parametrize(("scanner", "variant"), CASES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_attribution_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, variant: str, profile: str
) -> None:
    """Full producer shapes pass independent validation, verified receipts and empty findings."""
    _case(tmp_path, monkeypatch, sdk_base, FACTORIES[scanner](variant), profile)
