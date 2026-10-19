"""Actual security/config producer privacy across populated and limited branches."""

from __future__ import annotations

import json
from dataclasses import fields

import pytest
from botocore.loaders import Loader

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_security_fixture import SCANNERS, VARIANTS, security_producer_payload
from unio_collector.privacy.active_findings import FIELDS as SECURITY_FIELDS
from unio_collector.privacy.active_findings import VOCABULARIES as SECURITY_VOCABULARIES
from unio_collector.privacy.config_compliance import FIELDS as CONFIG_FIELDS
from unio_collector.privacy.config_compliance import VOCABULARIES as CONFIG_VOCABULARIES
from unio_collector.scanners.config.compliance.evidence import ConfigComplianceEvidence
from unio_collector.scanners.config.compliance.rule_record import ConfigComplianceRuleRecord
from unio_collector.scanners.security_finding.active.evidence import ActiveSecurityFindingEvidence
from unio_collector.scanners.security_finding.record import SecurityFindingRecord

pytestmark = pytest.mark.offline


def test_security_contracts_match_actual_provider_and_dataclass_fields() -> None:
    """Independent contracts detect omitted DTO fields or provider vocabulary changes."""
    for spec, prefix, dto in (
        (SECURITY_FIELDS, "", ActiveSecurityFindingEvidence),
        (SECURITY_FIELDS, "findings[].", SecurityFindingRecord),
        (CONFIG_FIELDS, "", ConfigComplianceEvidence),
        (CONFIG_FIELDS, "records[].", ConfigComplianceRuleRecord),
    ):
        declared = {p[len(prefix) :] for p in spec if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {f.name for f in fields(dto)}
    loader = Loader()
    config = loader.load_service_model("config", "service-2")["shapes"]
    assert set(CONFIG_VOCABULARIES["compliance"]) == set(config["ComplianceType"]["enum"])
    assert set(CONFIG_VOCABULARIES["pack_compliance"]) == set(config["ConformancePackComplianceType"]["enum"])
    prefix = "conformance_pack_records[]."
    declared = {p[len(prefix) :] for p in CONFIG_FIELDS if p.startswith(prefix) and "[" not in p[len(prefix) :]}
    assert declared == set(config["ConformancePackRuleCompliance"]["members"]) | {"region", "ConformancePackName"}
    hub = loader.load_service_model("securityhub", "service-2")["shapes"]
    assert set(SECURITY_VOCABULARIES["workflow"]) == set(hub["WorkflowStatus"]["enum"]) | {"active"}
    assert set(SECURITY_VOCABULARIES["state"]) == set(hub["RecordState"]["enum"]) | {"active"}


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_security_profiles(scanner: str, variant: str, profile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Use real collectors and serialization with SDK clients forbidden."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_args, **_kwargs: pytest.fail("AWS forbidden"))
    original = security_producer_payload(scanner, variant)
    t = transformer(profile)
    protected = t.transform({"scanner_evidence": [original]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    assert "synthetic-customer" not in json.dumps(protected)
    before = original["payload"]
    assert bool(protected["warnings"]) == bool(before["warnings"])
    key = "findings" if scanner == "active-security-finding-review" else "records"
    assert len(protected[key]) == len(before[key])
    assert protected["regions"] == (["aws-region"] if profile == "strict" else ["eu-west-2"])
    for old, new in zip(before[key], protected[key], strict=True):
        if key == "findings":
            assert new["provider"] == old["provider"]
            assert new["severity"] == old["severity"]
            assert new["workflow_status"] == old["workflow_status"]
            assert new["record_state"] == old["record_state"]
            assert not new.get("description")
            if old["updated_at"]:
                assert new["updated_at"] == (old["updated_at"][:7] if profile == "strict" else old["updated_at"])
        else:
            assert new["compliance_type"] == old["compliance_type"]
            assert not new.get("annotation")
    if key == "records" and protected["records"] and protected["conformance_pack_records"]:
        assert protected["records"][0]["rule_name"] == protected["conformance_pack_records"][0]["ConfigRuleName"]


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["root", "record", "container"])
@pytest.mark.parametrize("value", [None, {}, [], "synthetic"])
def test_security_unknown_descendants(scanner: str, profile: str, location: str, value: object) -> None:
    """Unknown null/empty/value paths reject even within removable fields."""
    row = security_producer_payload(scanner)
    payload = row["payload"]
    records = payload.get("findings", payload.get("records"))
    target = payload if location == "root" else records[0]
    if location == "container":
        target = payload.get("conformance_pack_records", records)[0]
    target["unknown_synthetic_field"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any("unknown_synthetic_field" in path for path in t.summary.unclassified)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("scanner", "field", "value"),
    [
        ("active-security-finding-review", "workflow_status", "invented"),
        ("active-security-finding-review", "record_state", {}),
        ("active-security-finding-review", "severity", True),
        ("active-security-finding-review", "severity", "customer-secret"),
        ("active-security-finding-review", "updated_at", "customer-secret"),
        ("aws-config-compliance-review", "compliance_type", "invented"),
        ("aws-config-compliance-review", "annotation", {}),
    ],
)
def test_security_malformed_values_reject(profile: str, scanner: str, field: str, value: object) -> None:
    """Validate known enums and types before any diagnostic removal."""
    row = security_producer_payload(scanner)
    records = row["payload"].get("findings", row["payload"].get("records"))
    records[0][field] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize(
    ("field", "value"),
    [("evidence_module", "foreign.module"), ("evidence_type", "ForeignEvidence"), ("provider_id", "foreign"), ("evidence_schema_id", "unknown.schema")],
)
def test_security_identity_conflicts(scanner: str, field: str, value: str) -> None:
    """A recognized scanner cannot borrow another identity's field policy."""
    row = security_producer_payload(scanner)
    row[field] = value
    with pytest.raises(ValueError, match="identity|schema"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [float("inf"), float("nan"), 10**500])
def test_security_nonfinite_severity_rejects(profile: str, value: float) -> None:
    """Malformed numeric severity fails classification without overflow."""
    row = security_producer_payload("active-security-finding-review")
    row["payload"]["findings"][0]["severity"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified
