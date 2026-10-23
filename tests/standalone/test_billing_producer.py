"""Actual billing provider output through protection and independent validation."""

from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import producer_bundle
from tools.collector_billing.fixture import billing_producer_observation
from tools.collector_billing.response import VARIANTS
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

pytestmark = pytest.mark.offline


@pytest.fixture(scope="module")
def billing_base(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """Reuse immutable actual shared producer input within this owner only."""
    with ZipFile(producer_bundle(tmp_path_factory.mktemp("billing-base"))) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, billing_base: dict[str, bytes], profile: str, variant: str, mutation: str | None = None) -> None:
    """Keep producer limitations and reject invalid/unknown SDK descendants before omission."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    observed = billing_producer_observation(variant)
    row = observed["evidence"]
    assert row is not None
    assert row["evidence_type"] == "BillingGuardrailRecord"
    assert observed["events"]
    assert observed["operations"]
    payload = row["payload"]
    if mutation:
        _mutate(row, mutation)
    _assert_observation(payload, variant)
    files = dict(billing_base)
    add_scanner_producer_payload(files, row, execution=observed["execution"])
    checksums = build_checksums(files)
    manifest = json.loads(files["manifest.json"])
    manifest["checksums"] = checksums
    files["manifest.json"] = json.dumps(manifest).encode()
    files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}).encode()
    source = tmp_path / "input.zip"
    with ZipFile(source, "w") as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    assert main(["validate-bundle", str(source)]) == (1 if mutation == "infinite_threshold" else 0)
    output = tmp_path / "transfer/protected.zip"
    vault = tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-billing-only\n"))
    result = main(
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
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
    invalid = (mutation is not None and not (mutation == "leak_money" and profile == "strict")) or variant in {"null_field", "malformed", "unknown"}
    assert result == (1 if invalid else 0)
    if invalid:
        assert not output.exists()
        assert not vault.exists()
        assert not output.with_suffix(".zip.receipt.json").exists()
        assert not list(tmp_path.rglob("*.tmp"))
        return
    assert main(["validate-bundle", str(output)]) == 0
    inspected = ProtectedBundleInspector().inspect(output)
    assert inspected.validation_passed
    receipt = inspected.summary["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["verified"]
    leak_scan = inspected.summary["leak_scan"]
    assert isinstance(leak_scan, dict)
    assert leak_scan["passed"]
    assert leak_scan["findings"] == []
    with ZipFile(output) as archive:
        after = next(
            record["payload"]
            for record in json.loads(archive.read("scan-result/scanner-evidence.json"))["scanner_evidence"]
            if record["scanner_id"] == row["scanner_id"]
        )
    assert after["account_id"] != payload["account_id"]
    for operation in (
        "budgets:describe_budgets",
        "budgets:describe_notifications_for_budget",
        "budgets:describe_subscribers_for_notification",
        "ce:get_anomaly_monitors",
        "ce:get_anomaly_subscriptions",
        "cloudwatch:describe_alarms",
    ):
        assert any(operation in error for error in after["permission_errors"]) == any(operation in error for error in payload["permission_errors"])
    if payload["permission_errors"]:
        assert after["permission_errors"] != payload["permission_errors"]
    if payload["budgets"]:
        budget = after["budgets"][0]["budget"]
        original = payload["budgets"][0]["budget"]
        if "BudgetName" in original:
            assert budget["BudgetName"] != original["BudgetName"]
        if "BudgetLimit" in original:
            assert budget["BudgetLimit"]["Amount"] == ("" if profile == "strict" else original["BudgetLimit"]["Amount"])


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("variant", VARIANTS)
def test_actual_billing_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, billing_base: dict[str, bytes], profile: str, variant: str) -> None:
    """Exercise supported actual producer and SDK expression/window choices."""
    _case(tmp_path, monkeypatch, billing_base, profile, variant)


MUTATIONS = (
    "identity",
    "foreign_namespace",
    "provider",
    "missing_root",
    "unknown_root",
    "unknown_alarm",
    "unknown_expression",
    "null_amount",
    "infinite_threshold",
    "count_bool",
    "bad_enum",
    "null_diagnostic",
    "map_value_object",
    "unknown_null",
    "map_key_path",
    "window_union",
    "leak_money",
)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", MUTATIONS)
def test_billing_unknown_malformed_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, billing_base: dict[str, bytes], profile: str, mutation: str
) -> None:
    """Unknown/malformed payloads and customer values fail closed before output."""
    _case(tmp_path, monkeypatch, billing_base, profile, "success", mutation)


def _mutate(row: dict[str, Any], mutation: str) -> None:
    """Mutate actual producer output, never hand-written substitute DTOs."""
    value = row["payload"]
    budget = value["budgets"][0]["budget"]
    alarm = value["billing_alarms"][0]
    if mutation in {"identity", "foreign_namespace", "provider", "missing_root", "unknown_root", "unknown_alarm"}:
        _envelope_mutation(row, mutation)
        return
    if mutation == "unknown_expression":
        value["anomaly_monitors"][0]["MonitorSpecification"]["Dimensions"]["unknown_billing_field"] = []
    elif mutation == "null_amount":
        budget["BudgetLimit"]["Amount"] = None
    elif mutation == "infinite_threshold":
        alarm["Threshold"] = float("inf")
    elif mutation == "count_bool":
        value["budgets"][0]["notification_details"][0]["subscriber_count"] = True
    elif mutation == "bad_enum":
        budget["BudgetType"] = "untrusted"
    elif mutation == "null_diagnostic":
        value["permission_errors"].append(None)
    else:
        _container_mutation(row, mutation)


def _container_mutation(row: dict[str, Any], mutation: str) -> None:
    """Mutate exact typed SDK maps, unions or financial units."""
    value = row["payload"]
    budget = value["budgets"][0]["budget"]
    alarm = value["billing_alarms"][0]
    if mutation == "map_value_object":
        budget["CostFilters"]["Service"] = {"customer": "synthetic"}
    elif mutation == "unknown_null":
        budget["BudgetLimit"]["unknown_billing_field"] = None
    elif mutation == "map_key_path":
        budget["CostFilters"]["customer.path"] = ["synthetic"]
    elif mutation == "window_union":
        alarm["EvaluationWindow"]["SlidingWindow"] = {}
    elif mutation == "leak_money":
        budget["BudgetLimit"]["Unit"] = "arn:aws:ec2:eu-west-2:123456789012:instance/i-synthetic-leak"


def _envelope_mutation(row: dict[str, Any], mutation: str) -> None:
    """Mutate exact envelope and nested alarm ownership boundaries."""
    value = row["payload"]
    alarm = value["billing_alarms"][0]
    if mutation == "identity":
        row["evidence_type"] = "UntrustedBillingRecord"
    if mutation == "foreign_namespace":
        row["evidence_module"] = "untrusted.aws.billing_guardrails.record"
    if mutation == "provider":
        row["provider_id"] = "untrusted"
    if mutation == "missing_root":
        value.pop("account_id")
    if mutation == "unknown_root":
        value["unknown_billing_field"] = {}
    if mutation == "unknown_alarm":
        alarm["Metrics"][0]["MetricStat"]["Metric"]["unknown_billing_field"] = "synthetic-customer"


def _assert_observation(payload: dict[str, Any], variant: str) -> None:
    """Assert provider failures remain explicit limitations, never a clean audit."""
    if variant in {"denied", "unavailable", "failure", "partial", "later_page", "summary", "budgets_only"}:
        assert payload["permission_errors"]
    if variant == "denied":
        assert all("AccessDeniedException" in error for error in payload["permission_errors"])
    if variant == "unavailable":
        assert all("ServiceUnavailableException" in error for error in payload["permission_errors"])
    if variant == "success":
        assert all(payload[key] for key in ("budgets", "anomaly_monitors", "anomaly_subscriptions", "billing_alarms"))
