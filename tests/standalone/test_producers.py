"""Full wire-ledger producer envelope exercised before and after export."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from unittest.mock import Mock
from zipfile import ZipFile

import pytest
from botocore.exceptions import ClientError

from tools.build_native_collector import _add_synthetic_region_scope
from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.collector.protocol import DEFAULT_PROTOCOL
from unio_collector.collector_cli.app import main
from unio_collector.privacy.producer_fields import unknown_producer_paths

FIXTURES = Path(__file__).parent / "fixtures"
pytestmark = pytest.mark.offline


def producer_bundle(tmp_path: Path) -> Path:
    """Use the same enrichment and complete input as frozen native smoke."""
    bundle = tmp_path / "producer-shapes.zip"
    assert main(["collect", "--fixture", str(FIXTURES / "cost.json"), "--output", str(bundle), "--quiet"]) == 0
    _add_synthetic_region_scope(bundle, FIXTURES / "region-scope.json")
    assert EvidenceBundleValidator().validate(bundle).passed
    return bundle


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_complete_producer_envelope_protects_and_validates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """Catch package-name rewrites of wire paths with full protect/validate."""
    source = producer_bundle(tmp_path)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "transfer/protected.zip"
    vault = tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-test-only-input\n"))
    assert (
        main(
            [
                "privacy",
                "protect",
                "--bundle",
                str(source),
                "--output",
                str(output),
                "--vault",
                str(vault),
                "--profile",
                profile,
                "--passphrase-stdin",
                "--acknowledge-vault-loss-risk",
            ]
        )
        == 0
    )
    assert main(["validate-bundle", str(output)]) == 0
    assert EvidenceBundleValidator().validate(output).passed
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    with ZipFile(output) as archive:
        records = [json.loads(line) for line in archive.read("collection-log.jsonl").splitlines()]
        if profile == "strict":
            assert records == []
        else:
            metadata = records[0][DEFAULT_PROTOCOL.namespace]
            assert metadata["attempt_id"] != "synthetic-attempt-01234567"
            assert "123456789012" not in json.dumps(records)
            assert metadata["operation_declared_in_registry"] is True
            assert metadata["authoritative_cloudtrail"] is False
            assert "requestParameters" not in records[0]
            assert "awsRequestId" not in records[0]["responseElements"]


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("unknown", [None, {}, [], "unknown"])
def test_unknown_nested_envelope_rejects_and_cleans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, unknown: object) -> None:
    """Reject null, scalar and empty unknown containers before strict omission."""
    source = producer_bundle(tmp_path)
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "region-scope.json").write_bytes((FIXTURES / "region-scope.json").read_bytes())
    payload = json.loads((FIXTURES / "protection-producers.json").read_text())
    payload["collection_log"][DEFAULT_PROTOCOL.namespace]["unknown_synthetic_field"] = unknown
    (fixtures / "protection-producers.json").write_text(json.dumps(payload))
    _add_synthetic_region_scope(source, fixtures / "region-scope.json")
    assert EvidenceBundleValidator().validate(source).passed
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "transfer/protected.zip"
    vault = tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-test-only-input\n"))
    assert (
        main(
            [
                "privacy",
                "protect",
                "--bundle",
                str(source),
                "--output",
                str(output),
                "--vault",
                str(vault),
                "--profile",
                profile,
                "--passphrase-stdin",
                "--acknowledge-vault-loss-risk",
            ]
        )
        == 1
    )
    assert not output.exists()
    assert not output.with_suffix(".zip.receipt.json").exists()
    assert not vault.exists()
    assert not list(tmp_path.rglob("*.tmp"))
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("failed", [False, True])
def test_actual_local_ledger_matches_full_fixture(*, failed: bool) -> None:
    """Call only the in-memory producer, covering optional fields and containers."""
    ledger = ApiCallLedger()
    ledger.set_identity({"Account": "123456789012", "UserId": "synthetic-user"})
    attempt = Mock()
    attempt.attempt_id = "synthetic-attempt"
    attempt.get_completion_classification.return_value = "late"
    attempt.get_outcome_reason.return_value = "synthetic outcome"
    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "synthetic diagnostic"}}, "DescribeInstances") if failed else None
    ledger.record(
        context=AwsAuditContext("root_advisory", "synthetic", ("ec2:DescribeInstances",), attempt=attempt),
        service_name="ec2",
        operation_name="DescribeInstances",
        region_name=None,
        request_parameters={},
        error=error,
    )
    record = ledger.records[0]
    fixture = json.loads((FIXTURES / "protection-producers.json").read_text())["collection_log"]
    assert set(record) == set(fixture)
    assert set(record[DEFAULT_PROTOCOL.namespace]) == set(fixture[DEFAULT_PROTOCOL.namespace])
    assert unknown_producer_paths(record, "collection-log.jsonl") == []
    assert record[DEFAULT_PROTOCOL.namespace]["attempt_id"] == "synthetic-attempt"
