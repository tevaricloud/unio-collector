"""Full wire-ledger producer envelope exercised before and after export."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock
from zipfile import ZipFile

import pytest
from botocore.exceptions import ClientError

from tools.build_native_collector import _add_synthetic_region_scope
from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.aws.api.telemetry_recorder import AwsApiTelemetryRecorder
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics
from unio_collector.aws.collection.task import AwsCollectionTask, AwsCollectionTaskStatus
from unio_collector.aws.collection.task_result import AwsCollectionTaskResult
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
        summary = json.loads(archive.read("collection-summary.json"))["api_runtime_summary"]
        assert summary["totals"] == json.loads((FIXTURES / "protection-producers.json").read_text())["api_runtime_summary"]["populated"]["totals"]
        for record in summary["records"]:
            assert record["account_id"] != "123456789012"
            assert record["attempt_id"] != "synthetic-attempt-01234567"
            assert record["region"] == ("aws-region" if profile == "strict" else record["region"])
            for field in ("error_code_counts", "error_category_counts", "expected_absence_reason_counts", "service_availability_status_counts"):
                assert record[field] == {}
        assert "123456789012" not in json.dumps(summary)
        collection = json.loads(archive.read("collection-summary.json"))["collection_runtime_summary"]
        assert all(collection[key] == {} for key in ("by_scanner", "by_operation", "by_throttle_domain"))
        assert "123456789012" not in json.dumps(collection)
        assert all(task["name"] != "synthetic-task-01234567" for task in collection["slowest_tasks"])
        assert json.loads(archive.read("scan-result/api-runtime-summary.json")) == summary
        manifest = json.loads(archive.read("manifest.json"))
        assert "123456789012" not in manifest["product_execution"]["report_label"]
        protected_summary = json.loads(archive.read("collection-summary.json"))
        if profile == "strict":
            assert protected_summary["billing_region_coverage"] is None
        assert "123456789012" not in json.dumps(protected_summary["stable_limitation_details"])
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
@pytest.mark.parametrize("location", ["ledger", "runtime", "collection", "product", "billing", "limitation"])
def test_unknown_nested_envelope_rejects_and_cleans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, unknown: object, location: str) -> None:
    """Reject null, scalar and empty unknown containers before strict omission."""
    source = producer_bundle(tmp_path)
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "region-scope.json").write_bytes((FIXTURES / "region-scope.json").read_bytes())
    payload = json.loads((FIXTURES / "protection-producers.json").read_text())
    if location == "ledger":
        payload["collection_log"][DEFAULT_PROTOCOL.namespace]["unknown_synthetic_field"] = unknown
    elif location == "product":
        payload["product_execution"]["period_policy"]["unknown_synthetic_field"] = unknown
    elif location == "billing":
        payload["billing_region_coverage"]["region_costs"][0]["unknown_synthetic_field"] = unknown
    elif location == "limitation":
        payload["stable_limitation_details"][0]["unknown_synthetic_field"] = unknown
    elif location == "collection":
        groups = payload["collection_runtime_summary"]["by_operation"]
        groups[next(iter(groups))]["unknown_synthetic_field"] = unknown
    else:
        payload["api_runtime_summary"]["populated"]["records"][0]["unknown_synthetic_field"] = unknown
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


def test_actual_runtime_summary_matches_export_fixture() -> None:
    """Generate full records from the real in-memory producer, without AWS."""
    recorder = AwsApiTelemetryRecorder()
    for status in ("success", "failure", "late_success", "late_failure"):
        recorder.record_call(
            scanner_id="synthetic-scanner",
            account_id="123456789012",
            region="us-east-1",
            service="ec2",
            operation="DescribeInstances",
            status=status,
            latency_ms=25.5,
            expected_absence=status != "success",
            service_unavailable=True,
            throttled=True,
            permission_denied=True,
            error_code="SyntheticError-123456789012",
            error_category="synthetic-category",
            expected_absence_reason="synthetic-reason-123456789012",
            service_availability_status="unavailable",
            page_count=2,
            result_count=3,
            resource_count=4,
            metric_datapoint_count=5,
            rate_limit_wait_ms=7.5,
            replayed=True,
            attempt_id="synthetic-attempt-01234567",
        )
    recorder.record_call(
        scanner_id="synthetic-scanner", account_id=None, region=None, service="ec2", operation="DescribeInstances", status="success", latency_ms=0.0
    )
    actual = {
        "populated": recorder.convert_to_summary(),
        "disabled": AwsApiTelemetryRecorder(enabled=False).convert_to_summary(),
        "empty": AwsApiTelemetryRecorder().convert_to_summary(),
    }
    fixture = json.loads((FIXTURES / "protection-producers.json").read_text())["api_runtime_summary"]
    assert actual == fixture
    for summary in actual.values():
        assert unknown_producer_paths({"api_runtime_summary": summary}, "collection-summary.json") == []


@pytest.mark.parametrize("invalid", [None, [], {"error": "not a count"}, {"error": True}, {"error": -1}])
def test_runtime_diagnostic_count_maps_fail_closed(invalid: object) -> None:
    """Opaque provider labels are omitted; only valid count maps are admitted."""
    payload = {"api_runtime_summary": {"records": [{"error_code_counts": invalid}]}}
    assert unknown_producer_paths(payload, "collection-summary.json")


def synthetic_collection_summary() -> dict[str, Any]:
    """Exercise populated actual task diagnostics without invoking collect callbacks."""
    diagnostics = AwsCollectionDiagnostics()
    results: list[AwsCollectionTaskResult[None]] = []
    statuses: tuple[AwsCollectionTaskStatus, ...] = ("completed", "failed", "permission_denied", "throttled", "unsupported_region")
    for status in statuses:
        task = AwsCollectionTask(
            name="synthetic-task-01234567",
            scanner_id="synthetic-scanner",
            collector_id="synthetic-collector",
            account_id=None if status == "completed" else "123456789012",
            region=None if status == "completed" else "us-east-1",
            service="ec2",
            operation="DescribeInstances",
            collect=lambda: None,
        )
        results.append(
            AwsCollectionTaskResult(
                task=task,
                status=status,
                duration_ms=25,
                result_count=3,
                resource_count=4,
                metric_datapoint_count=5,
                page_count=2,
                error_code=None if status == "completed" else "SyntheticError-123456789012",
                error_message=None if status == "completed" else "synthetic account 123456789012",
            )
        )
    diagnostics.record_results(results)
    return diagnostics.convert_to_summary()


def test_actual_collection_summary_matches_export_fixture() -> None:
    """Compare the complete actual grouped/conditional producer output."""
    fixture = json.loads((FIXTURES / "protection-producers.json").read_text())
    actual = synthetic_collection_summary()
    assert actual == fixture["collection_runtime_summary"]
    assert AwsCollectionDiagnostics().convert_to_summary() == fixture["empty_collection_runtime_summary"]
    assert unknown_producer_paths({"collection_runtime_summary": actual}, "collection-summary.json") == []


@pytest.mark.parametrize("unknown", [None, {}, [], "unexpected"])
def test_unknown_collection_diagnostic_group_fields_reject(unknown: object) -> None:
    """Typed dynamic labels are omitted; unknown record fields never are admitted."""
    value = synthetic_collection_summary()
    value["by_operation"][next(iter(value["by_operation"]))]["unknown_synthetic_field"] = unknown
    assert unknown_producer_paths({"collection_runtime_summary": value}, "collection-summary.json")
