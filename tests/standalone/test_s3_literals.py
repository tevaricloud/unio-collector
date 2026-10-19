"""S3 fixed provider literals do not exempt arbitrary customer strings."""

from __future__ import annotations

import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_s3_fixture import s3_producer_case
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", [None, "name", "tag", "unknown", "wrong-schema"])
def test_s3_literal_positions(profile: str, mutation: str | None) -> None:
    """Real rule IDs colliding with statuses protect; leaked user positions still fail."""
    t = transformer(profile)
    document = t.transform({"scanner_evidence": [s3_producer_case("s3-lifecycle-cost-review", "collision")]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    payload = document["scanner_evidence"][0]["payload"]
    record = payload["records"][0]
    if mutation == "name":
        record["bucket_name"] = "Enabled"
    elif mutation == "tag":
        record["tags"]["synthetic-key"] = "Enabled"
    elif mutation == "unknown":
        record["unknown"] = {"Enabled": None}
    elif mutation == "wrong-schema":
        document["scanner_evidence"][0]["evidence_type"] = "Unknown"
    result = ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(document), known_original_values={"Enabled"})
    assert any(item.category == "known_original_value" for item in result.findings) is (mutation is not None)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_s3_arbitrary_error_code_is_protected(profile: str) -> None:
    """Only finite provider error codes are public; arbitrary diagnostic text tokenises."""
    row = s3_producer_case("s3-public-access-security-review", "denied")
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert result["scanner_evidence"][0]["payload"]["account_public_access_block_error_code"] == "AccessDenied"
    row["payload"]["account_public_access_block_error_code"] = "synthetic-customer-error"
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    assert "synthetic-customer-error" not in json.dumps(result)
