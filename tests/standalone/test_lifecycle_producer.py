"""Actual lifecycle inventory: semantic public versions, strict dates and closed attributes."""

from __future__ import annotations

import copy
import json
from dataclasses import fields
from typing import TYPE_CHECKING

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import _case
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_serverless.base import synthetic_arn
from tools.collector_serverless.fixture import LIFECYCLE, VARIANTS, serverless_producer_observation
from tools.collector_serverless.lifecycle_client import SyntheticLifecycleClient
from unio_collector.aws.versioned_resource_record import VersionedResourceRecord
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.serverless.lifecycle import RECORD_KEYS

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline


def test_lifecycle_contract_matches_declared_record() -> None:
    """The explicit privacy record contract tracks every actual producer DTO field."""
    assert {field.name for field in fields(VersionedResourceRecord)} == RECORD_KEYS


@pytest.mark.parametrize("variant", VARIANTS[LIFECYCLE])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_lifecycle_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], variant: str, profile: str) -> None:
    """Actual six-service populated/limited/optional producers protect and independently validate."""
    _case(tmp_path, monkeypatch, sdk_base, serverless_producer_observation(LIFECYCLE, variant), profile)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_lifecycle_public_versions_protected_identities(profile: str) -> None:
    """Preserve existing lifecycle semantics while protecting customer resources, AMIs and tags."""
    observed = serverless_producer_observation(LIFECYCLE)
    before = copy.deepcopy(observed)
    operation = transformer(profile)
    result = operation.transform({"scanner_evidence": [observed["evidence"]]}, file_name="scan-result/scanner-evidence.json")
    assert not operation.summary.unclassified
    for original, protected in zip(observed["evidence"]["payload"]["records"], result["scanner_evidence"][0]["payload"]["records"], strict=True):
        assert protected["resource_id"] != original["resource_id"]
        assert protected["service"] == original["service"]
        assert protected["resource_type"] == original["resource_type"]
        assert protected["evidence_source"] == original["evidence_source"]
        assert protected["engine"] == original["engine"]
        if original["service"] == "Amazon EC2":
            assert protected["version"] != original["version"]
            assert protected["version"] == protected["attributes"]["ami_id"]
            assert protected["attributes"]["ami_name"] != original["attributes"]["ami_name"]
            assert protected["attributes"]["ami_creation_date"] == ("2024-01" if profile == "strict" else original["attributes"]["ami_creation_date"])
        else:
            assert protected["version"] == original["version"]
    assert observed == before


@pytest.mark.parametrize("mutation", ["unknown", "null", "attributes", "service", "controls", "tags", "timestamp", "identity"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_lifecycle_rejection_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], mutation: str, profile: str) -> None:
    """Unknown members and malformed/foreign producer fields fail without final artifacts."""
    observed = serverless_producer_observation(LIFECYCLE)
    record = next(r for r in observed["evidence"]["payload"]["records"] if r["service"] == "Amazon EC2")
    if mutation == "unknown":
        record["attributes"]["unknown_lifecycle_control"] = None
    elif mutation == "null":
        record["attributes"] = None
    elif mutation == "attributes":
        observed["evidence"]["payload"]["records"][0]["attributes"] = dict(record["attributes"])
    elif mutation == "service":
        record["service"] = "untrusted-service"
    elif mutation == "controls":
        record["evidence_source"] = "lambda:ListFunctions"
    elif mutation == "tags":
        record["tags"] = {"synthetic-customer-key": 7}
    elif mutation == "timestamp":
        record["attributes"]["ami_creation_date"] = "not-a-timestamp"
    else:
        observed["evidence"]["provider_id"] = "azure"
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)


@pytest.mark.parametrize("mutation", ["customer", "unknown", "foreign", "provider", "boundary"])
def test_lifecycle_scan_rejects_plaintext(mutation: str) -> None:
    """Public runtime literals cannot exempt arbitrary customer fields or untrusted identities."""
    row = serverless_producer_observation(LIFECYCLE)["evidence"]
    operation = transformer("standard")
    protected = operation.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not operation.summary.unclassified
    record = protected["scanner_evidence"][0]
    resource = next(r for r in record["payload"]["records"] if r["service"] == "AWS Lambda")
    literal = resource["version"]
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    baseline = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={literal}, generated_tokens=generated
    )
    assert baseline.passed, baseline.findings
    if mutation == "customer":
        resource["resource_name"] = literal
    elif mutation == "unknown":
        resource["unknown_customer"] = literal
    elif mutation == "foreign":
        record["scanner_id"] = "untrusted-wrapper"
    elif mutation == "provider":
        record["provider_id"] = "azure"
    else:
        resource["resource_name"] = "RESOURCE-AAAAAAAAAAAAAAAA" + literal
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={literal}, generated_tokens=generated
    )
    assert not result.passed
    assert any(finding.category == "known_original_value" for finding in result.findings)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("variant", ["nullable_controls", "legacy_defaults"])
def test_lifecycle_declared_legacy_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], profile: str, variant: str) -> None:
    """Preserve VersionedResourceRecord's declared optional/default compatibility surfaces."""
    observed = serverless_producer_observation(LIFECYCLE)
    for record in observed["evidence"]["payload"]["records"]:
        for key in ("platform", "resource_type", "evidence_source", "attributes"):
            if variant == "legacy_defaults":
                record.pop(key)
            else:
                record[key] = {} if key == "attributes" else None
    _case(tmp_path, monkeypatch, sdk_base, observed, profile)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_temporal_role_collision(profile: str) -> None:
    """Actual metric/AMI dates normalize only in owned timestamp roles, never customer text."""
    observed = serverless_producer_observation(LIFECYCLE)
    operation = transformer(profile)
    protected = operation.transform({"scanner_evidence": [observed["evidence"]]}, file_name="scan-result/scanner-evidence.json")
    assert not operation.summary.unclassified
    literal = "2024-01"
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scanner = ProtectedArchiveLeakScanner()
    baseline = scanner.scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={literal}, generated_tokens=generated
    )
    assert baseline.passed, baseline.findings
    protected["scanner_evidence"][0]["payload"]["records"][0]["resource_name" if LIFECYCLE == "extended-support-and-eol-review" else "function_name"] = literal
    rejected = scanner.scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={literal}, generated_tokens=generated
    )
    assert any(finding.category == "known_original_value" for finding in rejected.findings)


@pytest.mark.parametrize("literal", ["mysql", "redis", "production", "unknown", "test", "high"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_lifecycle_actual_identifier_control_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], literal: str, profile: str
) -> None:
    """Real SDK-response identifiers equal to public engine/environment controls still protect whole."""
    original = SyntheticLifecycleClient.describe_db_instances

    def renamed(client: SyntheticLifecycleClient, **kwargs: object) -> dict[str, object]:
        result = original(client, **kwargs)
        result["DBInstances"][0]["DBInstanceIdentifier"] = literal
        result["DBInstances"][0]["DBInstanceArn"] = synthetic_arn("rds", "db:" + literal)
        return result

    monkeypatch.setattr(SyntheticLifecycleClient, "describe_db_instances", renamed)
    observed = serverless_producer_observation(LIFECYCLE)
    assert observed["evidence"]["payload"]["records"][0]["resource_id"] == literal
    _case(tmp_path, monkeypatch, sdk_base, observed, profile)
