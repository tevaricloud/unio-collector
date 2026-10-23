"""Fixed protocol paths are not private content; adjacent paths and payload values are."""

from __future__ import annotations

import json

import pytest

from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline


@pytest.mark.parametrize(
    ("member", "document"),
    [
        ("bundle-schema.json", {"required_files": ["evidence/lambda.json"]}),
        ("checksums.json", {"checksums": {"evidence/lambda.json": "0" * 64}}),
        ("manifest.json", {"evidence_files": ["evidence/lambda.json"], "checksums": {"evidence/lambda.json": "0" * 64}}),
        ("evidence/lambda.json", {"service": "lambda", "records": []}),
    ],
)
def test_exact_public_protocol_literals(member: str, document: dict[str, object]) -> None:
    """The same known original cannot make required producer filenames illegal."""
    result = ProtectedArchiveLeakScanner().scan_text(path=member, content=json.dumps(document), known_original_values={"lambda"})
    assert result.passed


@pytest.mark.parametrize(
    ("member", "document"),
    [
        ("bundle-schema.json", {"required_files": ["evidence/lambda-private.json"]}),
        ("bundle-schema.json", {"foreign": {"required_files": ["evidence/lambda.json"]}}),
        ("checksums.json", {"checksums": {"evidence/lambda.json": "lambda"}}),
        ("manifest.json", {"foreign": "lambda"}),
        ("evidence/lambda.json", {"service": "lambda-private", "records": []}),
        ("evidence/lambda.json", {"service": "lambda", "records": [{"name": "lambda"}]}),
        ("evidence/ec2.json", {"service": "lambda"}),
    ],
)
def test_unknown_paths_and_customer_content_remain_scanned(member: str, document: dict[str, object]) -> None:
    """No field suffix, arbitrary service or malformed checksum receives normalization."""
    result = ProtectedArchiveLeakScanner().scan_text(path=member, content=json.dumps(document), known_original_values={"lambda"})
    assert any(f.category == "known_original_value" for f in result.findings)


@pytest.mark.parametrize("path", ["evidence/lambda-private.json", "foreign/evidence/lambda.json", "evidence/lambda.json.bak"])
def test_protocol_lookalike_filename_rejects(path: str) -> None:
    """Only exact reserved paths avoid a known-original filename false positive."""
    result = ProtectedArchiveLeakScanner().scan_text(path=path, content="{}", known_original_values={"lambda"})
    assert any(f.category == "known_original_value_filename" for f in result.findings)


def test_protocol_raw_patterns_and_duplicate_keys_remain_scanned() -> None:
    """Fixed filenames never exempt payload secrets or ambiguously repeated keys."""
    scanner = ProtectedArchiveLeakScanner()
    result = scanner.scan_text(path="evidence/lambda.json", content='{"service":"lambda","account":"123456789012"}', known_original_values={"lambda"})
    assert any(f.category == "aws_account_id" for f in result.findings)
    result = scanner.scan_text(path="evidence/lambda.json", content='{"service":"lambda","service":"lambda"}', known_original_values={"lambda"})
    assert any(f.category == "known_original_value" for f in result.findings)
