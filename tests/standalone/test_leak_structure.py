"""Structural key collisions must not suppress evidence or unknown-key leak detection."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tools.collector_risk_fixture import account_risk_producer_payload
from tools.collector_storage_fixture import SCANNERS, storage_producer_case
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.leak.structure import known_value_scan_content

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"


def test_known_trail_key_does_not_become_private_content() -> None:
    """A tokenised Name tag must not conflict with a fixed CloudTrail field name."""
    row = account_risk_producer_payload()
    content = json.dumps({"scanner_evidence": [row]})
    assert '"Name"' in content
    result = ProtectedArchiveLeakScanner().scan_text(path=MEMBER, content=content, known_original_values={"Name"})
    assert not any(f.category == "known_original_value" for f in result.findings)
    assert any(f.category == "aws_account_id" for f in result.findings)


@pytest.mark.parametrize("location", ["value", "unknown_key", "unknown_parent", "tag_key", "tag_value", "envelope"])
def test_schema_mask_never_hides_content(location: str) -> None:
    """Private text in values, dynamic keys or unknown positions still fails."""
    row, _, _ = storage_producer_case(SCANNERS[0])
    record = row["payload"]["records"][0]
    if location == "value":
        record["volume_type"] = "Name"
    elif location == "unknown_key":
        record["Name"] = None
    elif location == "unknown_parent":
        row["payload"]["foreign"] = {"records": [{"volume_id": "Name"}]}
    elif location == "tag_key":
        record["tags"]["Name"] = "safe"
    elif location == "tag_value":
        record["tags"] = {"safe": "Name"}
    else:
        row["Name"] = "safe"
    result = ProtectedArchiveLeakScanner().scan_text(path=MEMBER, content=json.dumps({"scanner_evidence": [row]}), known_original_values={"Name"})
    assert any(f.category == "known_original_value" for f in result.findings)


@pytest.mark.parametrize(
    "content",
    ['{"scanner_evidence": [{"payload":{"Name":"value"}}]}', '{"scanner_evidence": [], "Name": 1, "Name": 2}', '{"Name":', '{"scanner_evidence":[null]}'],
)
def test_unrecognized_or_malformed_documents_remain_scanned(content: str) -> None:
    """Identity, duplicate and parsing failures cannot gain key exclusions."""
    assert "Name" in known_value_scan_content(MEMBER, content) if "Name" in content else known_value_scan_content(MEMBER, content) == content


def test_other_files_receive_no_structural_exclusions() -> None:
    """The exact member boundary is mandatory."""
    content = json.dumps({"scanner_evidence": [account_risk_producer_payload()]})
    assert known_value_scan_content("other.json", content) == content


def test_escaped_private_values_remain_detectable() -> None:
    """JSON decoding must expose escaped values, never discard duplicate entries."""
    row, _, _ = storage_producer_case(SCANNERS[0])
    row["payload"]["records"][0]["tags"] = {"private": "Name"}
    content = json.dumps({"scanner_evidence": [row]}).replace('"Name"', '"\\u004eame"')
    result = ProtectedArchiveLeakScanner().scan_text(path=MEMBER, content=content, known_original_values={"Name"})
    assert any(f.category == "known_original_value" for f in result.findings)


@pytest.mark.parametrize("location", ["literal", "unknown_parent", "wrong_container"])
def test_path_syntax_cannot_mask_unknown_keys(location: str) -> None:
    """Only structurally declared field positions can receive key exclusions."""
    row, _, _ = storage_producer_case(SCANNERS[0])
    private = "records[].volume_type"
    if location == "literal":
        row["payload"][private] = "io2"
    elif location == "unknown_parent":
        row["payload"]["records[]"] = {"volume_type": "io2", private: "io2"}
    else:
        row["payload"]["records"] = {private: "io2"}
    result = ProtectedArchiveLeakScanner().scan_text(path=MEMBER, content=json.dumps({"scanner_evidence": [row]}), known_original_values={private})
    assert any(f.category == "known_original_value" for f in result.findings)


@pytest.mark.parametrize(
    "mutation", ["none", "altered_hash", "unknown_target", "unknown_value", "hash_customer", "plaintext_body", "wrong_algorithm", "duplicate_target"]
)
def test_checksum_collisions_require_actual_archive_bytes(tmp_path: Path, mutation: str) -> None:
    """A computed protocol digest is distinct from arbitrary hash-shaped plaintext."""
    data = json.dumps({"synthetic_checksum_payload": "offline-collision-1768"}).encode()
    digest = hashlib.sha256(data).hexdigest()
    assert "1200" in digest
    assert b"1200" not in data
    target = "customer.json" if mutation == "unknown_target" else "evidence/ec2.json"
    files = {target: data}
    checksums = build_checksums(files)
    if mutation == "altered_hash":
        checksums[target] = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    if mutation == "plaintext_body":
        files[target] = b'{"customer":"1200"}'
        checksums = build_checksums(files)
    payload = {"algorithm": "foreign" if mutation == "wrong_algorithm" else "sha256", "checksums": checksums}
    if mutation == "unknown_value":
        payload["customer"] = "1200"
    if mutation == "hash_customer":
        payload["customer"] = digest
    originals = {digest} if mutation == "hash_customer" else {"1200"}
    files["checksums.json"] = json.dumps(payload).encode()
    files["manifest.json"] = json.dumps({"checksums": checksums}).encode()
    archive_path = tmp_path / "synthetic.zip"
    with ZipFile(archive_path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        if mutation == "duplicate_target":
            with pytest.warns(UserWarning, match="Duplicate name"):
                archive.writestr(target, data)
    scanner = ProtectedArchiveLeakScanner()
    before = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    result = scanner.scan_zip_bytes(archive_path=archive_path, known_original_values=originals)
    assert result.passed is (mutation == "none")
    assert hashlib.sha256(archive_path.read_bytes()).hexdigest() == before
    assert not scanner.scan_text(path="checksums.json", content=files["checksums.json"].decode(), known_original_values={checksums[target]}).passed
