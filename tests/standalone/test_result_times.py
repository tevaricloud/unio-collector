"""Actual execution timestamps cannot collide with protected customer clocks."""

from __future__ import annotations

import json
from datetime import UTC, datetime, tzinfo
from typing import TYPE_CHECKING, Any, Self
from zipfile import ZipFile

import pytest

import unio_collector.providers.aws.collection.executor as collection_executor
import unio_collector.scan_workflow.scanner.collection.service as collection_service
from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_logs_branches import test_actual_logs_branch_bundle as exercise_logs_branch
from tools.collector_logs_fixture import SyntheticLogsSession
from unio_collector.collector.bundle import payload_writer
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.scanners.scanner.result import ScannerExecutionResult

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-results.json"


class FixtureClock(datetime):
    """Provide an actual collection-clock input, never a substituted scan result."""

    @classmethod
    def now(cls, tz: tzinfo | None = None) -> Self:
        """Cross a schedule clock substring at the minute/second boundary."""
        value = cls(2026, 10, 15, 11, 9, 0, 123456, tzinfo=UTC)
        return value.replace(tzinfo=None) if tz is None else value.astimezone(tz)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_execution_clock_collision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """Run populated producers, independent validation, receipts and source integrity."""
    monkeypatch.setattr(collection_service, "datetime", FixtureClock)
    exercise_logs_branch(tmp_path, monkeypatch, "failure", profile, "cloudwatch-log-cost-and-relevance-review")
    with ZipFile(tmp_path / "producer-shapes.zip") as source, ZipFile(tmp_path / "transfer/protected.zip") as protected:
        old_rows = json.loads(source.read(MEMBER))["scanner_results"]
        rows = json.loads(protected.read(MEMBER))["scanner_results"]
        assert any(row.get("completed_at") == FixtureClock.now(UTC).isoformat() for row in old_rows)
        for old, new in zip(old_rows, rows, strict=True):
            for field in ("started_at", "completed_at"):
                assert new[field] == (old[field][:7] if profile == "strict" and old[field] else old[field])
        before = json.loads(source.read("scan-result/scanner-evidence.json"))["scanner_evidence"]
        after = json.loads(protected.read("scan-result/scanner-evidence.json"))["scanner_evidence"]
        running = next(row["payload"] for row in before if row["scanner_id"] == "ec2-idle-instance-review")
        periods = next(iter(running["metadata"]["scheduled_shutdown"]["schedules"].values()))["periods"]
        assert periods[0]["start"] == "09:00"
        running = next(row["payload"] for row in after if row["scanner_id"] == "ec2-idle-instance-review")
        assert "09:00" not in json.dumps(running["metadata"]["scheduled_shutdown"])


def _execution(profile: str) -> dict[str, Any]:
    result = ScannerExecutionResult(
        scanner_id="billing-alerts-and-budgets-review", status="completed", started_at=FixtureClock.now(UTC), completed_at=FixtureClock.now(UTC)
    )
    return transformer(profile).transform({"scanner_results": [result.convert_to_dict()]}, file_name=MEMBER)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("literal", ["09:00", "2026-10"])
def test_typed_execution_time_roles(profile: str, literal: str) -> None:
    """Standard datetimes and strict months retain their declared temporal role."""
    result = ProtectedArchiveLeakScanner().scan_text(path=MEMBER, content=json.dumps(_execution(profile)), known_original_values={literal})
    assert result.passed, result.findings


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["customer", "unknown", "foreign_owner", "foreign_provider", "conflict", "wrong_type", "wrong_format", "wrong_member"])
def test_customer_time_and_untrusted_roles_still_reject(profile: str, mutation: str) -> None:
    """No global clock/date exemption, unknown path escape or identity bypass."""
    document = _execution(profile)
    row = document["scanner_results"][0]
    literal = "09:00" if profile == "standard" else "2026-10"
    member = MEMBER
    if mutation == "customer":
        row["errors"] = [literal]
    elif mutation == "unknown":
        row["unknown_customer_time"] = literal
    elif mutation == "foreign_owner":
        row["scanner_id"] = "untrusted-owner"
    elif mutation == "foreign_provider":
        row["provider_id"] = "untrusted-provider"
    elif mutation == "conflict":
        row["evidence_type"] = "untrusted-evidence"
    elif mutation == "wrong_type":
        row["completed_at"] = {"customer": literal}
    elif mutation == "wrong_format":
        row["completed_at"] = "customer-" + literal
    else:
        member = "unknown-results.json"
    result = ProtectedArchiveLeakScanner().scan_text(path=member, content=json.dumps(document), known_original_values={literal})
    assert any(finding.category == "known_original_value" for finding in result.findings)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("clock_owner", ["manifest", "bundle_context", "sdk_payload"])
def test_actual_adjacent_clock_collisions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, clock_owner: str) -> None:
    """Actual producer timestamps must not collide with protected schedule clocks."""
    if clock_owner == "manifest":
        monkeypatch.setattr(payload_writer, "datetime", FixtureClock)
    elif clock_owner == "bundle_context":
        monkeypatch.setattr(collection_executor, "datetime", FixtureClock)
    else:
        original = SyntheticLogsSession.describe_log_groups

        def groups(self: SyntheticLogsSession, **kwargs: object) -> dict[str, Any]:
            response = original(self, **kwargs)
            for group in response.get("logGroups", []):
                group["creationTime"] = int(FixtureClock.now(UTC).timestamp() * 1000)
            return response

        monkeypatch.setattr(SyntheticLogsSession, "describe_log_groups", groups)
    exercise_logs_branch(tmp_path, monkeypatch, "success" if clock_owner == "sdk_payload" else "failure", profile, "cloudwatch-log-cost-and-relevance-review")
    with ZipFile(tmp_path / "producer-shapes.zip") as source, ZipFile(tmp_path / "transfer/protected.zip") as protected:
        if clock_owner == "manifest":
            old = json.loads(source.read("manifest.json"))["generated_at"]
            new = json.loads(protected.read("manifest.json"))["generated_at"]
            assert old == FixtureClock.now(UTC).isoformat()
            assert new == (old[:7] if profile == "strict" else old)
        elif clock_owner == "sdk_payload":
            old_rows = json.loads(source.read("scan-result/scanner-evidence.json"))["scanner_evidence"]
            rows = json.loads(protected.read("scan-result/scanner-evidence.json"))["scanner_evidence"]
            old_log = next(row["payload"] for row in old_rows if row["scanner_id"] == "cloudwatch-log-cost-and-relevance-review")
            log = next(row["payload"] for row in rows if row["scanner_id"] == "cloudwatch-log-cost-and-relevance-review")
            assert old_log["records"][0]["creation_time"].startswith("2026-10-15T11:09:00")
            assert log["records"][0]["creation_time"] == ("2026-10" if profile == "strict" else old_log["records"][0]["creation_time"])
