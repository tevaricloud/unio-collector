"""Independent RDS DTO inventories, controlled roles and adversarial scan views."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import fields

import pytest

from tools.collector_rds.fixture import rds_producer_observation
from unio_collector.aws.metric.summary import MetricSummary
from unio_collector.aws.rds.instance_record import RdsInstanceRecord
from unio_collector.aws.rds.snapshot.record import RdsSnapshotRecord
from unio_collector.privacy.closed_schema import PREFIX
from unio_collector.privacy.leak.public.lifecycle import KEYS, VALUES
from unio_collector.privacy.leak.public.protocol import ProtocolScanContract
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.producer_fields import producer_category
from unio_collector.privacy.rds.instance import RdsInstancePrivacyContract
from unio_collector.privacy.rds.snapshot import RdsSnapshotPrivacyContract

pytestmark = pytest.mark.offline


@pytest.mark.parametrize(
    ("scanner", "dto", "contract"),
    [
        ("rds-utilization-review", RdsInstanceRecord, RdsInstancePrivacyContract),
        ("rds-snapshot-retention-review", RdsSnapshotRecord, RdsSnapshotPrivacyContract),
    ],
)
def test_complete_actual_rds_record_inventory(scanner: str, dto: type, contract: type) -> None:
    """Compare explicit paths with real DTO fields and populated actual serialization."""
    row = rds_producer_observation(scanner)["evidence"]
    expected = {field.name for field in fields(dto)}
    declared = {
        key.removeprefix("records[].")
        for key in contract.fields
        if key.startswith("records[].") and "." not in key.removeprefix("records[].") and ("[" not in key.removeprefix("records[]."))
    }
    assert declared == expected == set(row["payload"]["records"][0])
    assert contract.for_record(row) is not None


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_bound_lifecycle_controls_do_not_rebind_or_admit_arbitrary_text(profile: str) -> None:
    """Finite lifecycle strings remain useful while arbitrary status text protects."""
    root = RdsInstancePrivacyContract()
    for status in ("available", "stopped", "stopping", "unknown"):
        bound = root.for_container({"status": status}, PREFIX + ".records[]")
        assert bound is not None
        assert bound.for_container({"status": status}, PREFIX + ".records[]") is None
        decision = bound.resolve(PREFIX + ".records[].status", profile)
        assert decision is not None
        assert decision.treatment == "preserve"
    arbitrary = root.for_container({"status": "synthetic-customer-status"}, PREFIX + ".records[]")
    assert arbitrary is not None
    decision = arbitrary.resolve(PREFIX + ".records[].status", profile)
    assert decision is not None
    assert decision.treatment == "tokenise"
    malformed = root.for_container({"status": {}, "snapshot_type": []}, PREFIX + ".records[]")
    assert malformed is not None


def _protected_month_record() -> dict:
    record = json.loads(json.dumps(rds_producer_observation("rds-utilization-review")["evidence"]["payload"]["records"][0]))
    for metric in record["metrics"]:
        metric["start_time"] = metric["end_time"] = "2026-07"
        for point in metric["datapoints"]:
            point["timestamp"] = "2026-07"
    return record


def test_strict_scan_admission_keeps_collection_timestamp_validation_strict() -> None:
    """Only scan-view validation accepts canonical transformed month timestamps."""
    record = _protected_month_record()
    original = deepcopy(record)
    contract = RdsInstancePrivacyContract()
    assert contract.unknown_paths(record, "synthetic-member", "records[]")
    assert contract.admitted_scan_record(record)
    assert record == original
    record["metrics"][0]["start_time"] = "2026-99"
    assert not contract.admitted_scan_record(record)
    record["metrics"][0]["start_time"] = "2026-07"
    record["metrics"][0]["unknown_rds"] = None
    assert not contract.admitted_scan_record(record)


@pytest.mark.parametrize("field", ["engine", "db_instance_identifier", "db_instance_class"])
def test_rds_scan_view_rejects_customer_plaintext_in_declared_fields(field: str) -> None:
    """Strict temporal admission cannot mask real customer text elsewhere."""
    row = rds_producer_observation("rds-utilization-review")["evidence"]
    record = _protected_month_record()
    record[field] = "SyntheticPlaintextCustomer"
    row["payload"]["records"] = [record]
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps({"scanner_evidence": [row]}), known_original_values={"SyntheticPlaintextCustomer"}
    )
    assert not result.passed
    assert any(f.category == "known_original_value" for f in result.findings)


@pytest.mark.parametrize("provider", ["untrusted", "azure"])
def test_rds_identity_cannot_be_borrowed(provider: str) -> None:
    """Foreign providers reject before closed contract or import selection."""
    row = rds_producer_observation("rds-utilization-review")["evidence"]
    row["provider_id"] = provider
    with pytest.raises(ValueError, match="matching registered AWS evidence identity"):
        RdsInstancePrivacyContract.for_record(row)


def test_actual_metric_dataclass_fields_are_explicitly_classified() -> None:
    """Inventory current canonical wire fields separately from legacy computed count."""
    metric = rds_producer_observation("rds-utilization-review")["evidence"]["payload"]["records"][0]["metrics"][0]
    expected = {field.name for field in fields(MetricSummary)}
    declared = {
        key.removeprefix("records[].metrics[].")
        for key in RdsInstancePrivacyContract.fields
        if key.startswith("records[].metrics[].")
        and "." not in key.removeprefix("records[].metrics[].")
        and "[" not in key.removeprefix("records[].metrics[].")
    }
    assert expected == set(metric)
    assert declared == expected
    assert "datapoint_count" not in metric


@pytest.mark.parametrize(("member", "path", "literal"), [(member, path, literal) for (member, path), values in VALUES.items() for literal in sorted(values)])
def test_protocol_lifecycle_exact_roles_do_not_hide_customer_text(member: str, path: str, literal: str) -> None:
    """Finite exact fields normalize; arbitrary text and lookalike positions scan."""
    contract = ProtocolScanContract()
    assert producer_category(member, path) is not None
    assert contract.mask(member, literal, path) == ""
    assert contract.mask(member, literal + "-customer", path) == literal + "-customer"
    assert contract.mask(member, literal, path + ".customer") == literal
    assert contract.mask("untrusted.json", literal, path) == literal


@pytest.mark.parametrize(("member", "path"), sorted(KEYS))
def test_protocol_lifecycle_list_names_never_hide_list_values(member: str, path: str) -> None:
    """Mask only the finite key; customer list items and malformed containers survive."""
    contract = ProtocolScanContract()
    assert contract._declared(member, path, ["available"])  # noqa: SLF001
    assert contract.mask(member, ["available"], path) == ["available"]
    assert not contract._declared(member, path, {"available": 1})  # noqa: SLF001


def test_api_runtime_member_masks_exact_count_keys_but_not_unknowns() -> None:
    """The actual separate summary member receives the same closed structural view."""
    content = {"enabled": True, "records": [], "totals": {"service_unavailable_count": 1, "late_service_unavailable_count": 0}}
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path="scan-result/api-runtime-summary.json", content=json.dumps(content), known_original_values={"available"}).passed
    content["totals"]["unknown_customer"] = "available"
    assert not scanner.scan_text(path="scan-result/api-runtime-summary.json", content=json.dumps(content), known_original_values={"available"}).passed


@pytest.mark.parametrize(
    ("member", "path"),
    [
        ("manifest.json", "$.permission_limitations[].category"),
        ("manifest.json", "$.permission_limitations[].error_classification"),
        ("permissions-summary.json", "$.permission_degradation.degradation_details[].limitation_category"),
        ("permissions/degradation-records.json", "$.records[].category"),
    ],
)
def test_unknown_protocol_category_cannot_borrow_another_schema_role(member: str, path: str) -> None:
    """A known word at an unsupported member path remains customer-visible to scans."""
    assert producer_category(member, path) is None
    assert ProtocolScanContract().mask(member, "evidence_unavailable", path) == "evidence_unavailable"
