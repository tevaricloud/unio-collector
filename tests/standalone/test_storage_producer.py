"""Actual storage DTO/privacy contract parity and fail-closed negative cases."""

from __future__ import annotations

import json
from dataclasses import fields

import pytest
from botocore.loaders import Loader

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_storage_fixture import SCANNERS, VARIANTS, storage_producer_case
from unio_collector.aws.ebs.provisioned_iops import ProvisionedIopsVolumeRecord
from unio_collector.aws.ebs.volume_record import EbsVolumeRecord
from unio_collector.aws.ec2.stopped_instance_record import StoppedInstanceRecord
from unio_collector.privacy.ec2.base import VOCABULARIES
from unio_collector.privacy.ec2.iops import ProvisionedIopsPrivacyContract
from unio_collector.privacy.ec2.stopped import StoppedInstancePrivacyContract
from unio_collector.privacy.ec2.volume import EbsVolumePrivacyContract
from unio_collector.scanners.inventory_evidence import InventoryEvidence

pytestmark = pytest.mark.offline
CONTRACTS = (EbsVolumePrivacyContract, ProvisionedIopsPrivacyContract, StoppedInstancePrivacyContract)


def test_storage_independent_dto_contracts() -> None:
    """Every DTO field and SDK volume vocabulary has an explicit reviewed treatment."""
    for contract, dto in zip(CONTRACTS, (EbsVolumeRecord, ProvisionedIopsVolumeRecord, StoppedInstanceRecord), strict=True):
        for prefix, model in (("", InventoryEvidence), ("records[].", dto)):
            declared = {
                p[len(prefix) :]
                for p in contract.fields
                if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]
            }
            assert declared == {f.name for f in fields(model)}
    shapes = Loader().load_service_model("ec2", "service-2")["shapes"]
    assert set(VOCABULARIES["volume_type"]) == set(shapes["VolumeType"]["enum"]) | {"unknown"}
    assert set(VOCABULARIES["volume_state"]) == set(shapes["VolumeState"]["enum"]) | {"unknown"}


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("legacy", [False, True])
def test_actual_storage_profiles(scanner: str, variant: str, profile: str, monkeypatch: pytest.MonkeyPatch, *, legacy: bool) -> None:
    """Exercise current production paths, optional nulls and registered historical aliases."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row, statuses, warnings = storage_producer_case(scanner, variant)
    if legacy:
        row["evidence_module"] = row["evidence_module"].replace("inventory_evidence", "fixture_parity.synthetic_types")
        row["evidence_type"] = CONTRACTS[SCANNERS.index(scanner)].fixture_type
    t = transformer(profile)
    protected = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    assert "synthetic-customer" not in json.dumps(protected)
    expected = {"denied": "permission_denied", "unsupported": "unsupported_region", "unavailable": "failed", "failure": "failed", "partial": "throttled"}.get(
        variant, "completed"
    )
    assert statuses == [expected]
    assert bool(warnings) == (expected != "completed")
    assert len(protected["records"]) == int(variant in {"success", "optional"})
    for old, new in zip(row["payload"]["records"], protected["records"], strict=True):
        assert old["account_id"] != new["account_id"]
        assert new["region"] == ("aws-region" if profile == "strict" else old["region"])
        for key in ("volume_type", "state", "instance_type", "size_gib", "encrypted", "provisioned_iops"):
            if key in old:
                assert new[key] == old[key]
        for key in ("create_time", "launch_time"):
            if old.get(key):
                assert new[key] == ("2026-09" if profile == "strict" else old[key])


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["root", "record", "metadata", "tags"])
@pytest.mark.parametrize("value", [None, {}, [], 1])
def test_storage_unknown_and_malformed_containers(scanner: str, profile: str, location: str, value: object) -> None:
    """Unknown and malformed descendants reject before omission or tag tokenisation."""
    row, _, _ = storage_producer_case(scanner)
    payload = row["payload"]
    record = payload["records"][0]
    target = {"root": payload, "record": record, "metadata": payload["metadata"], "tags": record["tags"]}[location]
    target["unknown_synthetic_field"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("index", "key", "value"),
    [
        (0, "volume_type", "synthetic-secret"),
        (0, "state", "synthetic-secret"),
        (0, "create_time", "synthetic-secret"),
        (0, "size_gib", True),
        (0, "encrypted", 1),
        (1, "provisioned_iops", -1),
        (2, "instance_type", "synthetic-secret"),
        (2, "launch_time", {}),
        (2, "attached_volume_ids", [{}]),
        (0, "launch_time", None),
    ],
)
def test_storage_invalid_fields(profile: str, index: int, key: str, value: object) -> None:
    """Finite metadata, DTO types and scanner-specific boundaries remain closed."""
    row, _, _ = storage_producer_case(SCANNERS[index])
    row["payload"]["records"][0][key] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_storage_cross_record_identifier_consistency(profile: str) -> None:
    """The volume reference on an instance retains its relationship to volume evidence."""
    rows = [storage_producer_case(scanner)[0] for scanner in SCANNERS]
    t = transformer(profile)
    result = t.transform({"scanner_evidence": rows}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"]
    assert not t.summary.unclassified
    volume = result[0]["payload"]["records"][0]["volume_id"]
    assert volume != rows[0]["payload"]["records"][0]["volume_id"]
    assert result[1]["payload"]["records"][0]["volume_id"] == volume
    assert result[2]["payload"]["records"][0]["attached_volume_ids"] == [volume]


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize(
    ("key", "value"),
    [("provider_id", "foreign"), ("evidence_module", "foreign.module"), ("evidence_type", "ForeignEvidence"), ("evidence_schema_id", "unknown.schema")],
)
def test_storage_identity_conflicts(scanner: str, key: str, value: str) -> None:
    """No unrecognized identity can borrow the concrete storage policy."""
    row, _, _ = storage_producer_case(scanner)
    row[key] = value
    with pytest.raises(ValueError, match="identity|schema"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("key", ["records[].volume_type", "records[].state", "records[].region"])
def test_path_shaped_literal_fields_reject(profile: str, key: str) -> None:
    """A literal object key must never impersonate a nested schema path."""
    row, _, _ = storage_producer_case(SCANNERS[0])
    row["payload"][key] = {"records[].volume_type": "io2", "records[].state": "available", "records[].region": "eu-west-2"}[key]
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_dynamic_tag_keys_with_path_characters_remain_protected(profile: str) -> None:
    """Legitimate arbitrary string tag keys retain exact-container handling."""
    row, _, _ = storage_producer_case(SCANNERS[0])
    row["payload"]["records"][0]["tags"] = {"synthetic.owner[0].name": "synthetic-customer-tag"}
    t = transformer(profile)
    protected = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    assert "synthetic-customer-tag" not in json.dumps(protected)
    assert "synthetic.owner" not in json.dumps(protected)
