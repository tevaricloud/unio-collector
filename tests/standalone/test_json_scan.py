"""Known-original scans distinguish JSON syntax from customer string content."""

from __future__ import annotations

import json

import pytest

from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("path", ["manifest.json", "collection-log.jsonl", "unknown.json"])
@pytest.mark.parametrize("literal", ["true", "false", "null"])
@pytest.mark.parametrize("position", ["syntax", "value", "key", "nested", "escaped"])
def test_json_syntax_is_not_customer_text(path: str, literal: str, position: str) -> None:
    """Only typed boolean/null syntax is excluded, even in unknown member schemas."""
    content = '{"flag": ' + literal + "}"
    if position == "value":
        content = json.dumps({"flag": literal})
    elif position == "key":
        content = json.dumps({literal: True})
    elif position == "nested":
        content = json.dumps({"unknown": [{"value": literal}]})
    elif position == "escaped":
        content = '{"flag": "' + "".join(f"\\u{ord(char):04x}" for char in literal) + '"}'
    result = ProtectedArchiveLeakScanner().scan_text(path=path, content=content, known_original_values={literal})
    assert any(item.category == "known_original_value" for item in result.findings) is (position != "syntax")


@pytest.mark.parametrize("content", ['{"flag": true', '{"flag": true, "flag": false}', '{"flag": true}\nINVALID'])
def test_invalid_json_remains_fully_scanned(content: str) -> None:
    """Parsing failures cannot hide potential original values."""
    result = ProtectedArchiveLeakScanner().scan_text(path="collection-log.jsonl", content=content, known_original_values={"true"})
    assert any(item.category == "known_original_value" for item in result.findings)


def test_plain_text_and_raw_security_patterns_remain_scanned() -> None:
    """Syntax handling never changes raw credential scans or non-JSON content."""
    scanner = ProtectedArchiveLeakScanner()
    assert not scanner.scan_text(path="notes.txt", content="true", known_original_values={"true"}).passed
    result = scanner.scan_text(path="manifest.json", content='{"flag": true, "id": "123456789012"}', known_original_values={"true"})
    assert any(item.category == "aws_account_id" for item in result.findings)


@pytest.mark.parametrize("registered", [False, True])
@pytest.mark.parametrize("position", ["token", "plaintext", "lookalike", "token_original", "credential", "containing_token", "left_boundary", "right_boundary"])
def test_registered_tokens_do_not_hide_customer_values(*, registered: bool, position: str) -> None:
    """Only exact registered generated tokens avoid random substring collisions."""
    generated = "RESOURCE-AAAAHTTPSAAAAAAA"
    originals = {"HTTPS"}
    value = generated
    if position == "plaintext":
        value += " HTTPS"
    elif position == "lookalike":
        value += "A"
    elif position == "token_original":
        originals.add(generated)
    elif position == "credential":
        value += " 123456789012"
    if position == "containing_token":
        value = "before " + generated + " after"
        originals.add(value)
    elif position == "left_boundary":
        value = "before " + generated
        originals.add("before RESOURCE-AAAA")
    elif position == "right_boundary":
        value = generated + " after"
        originals.add("AAAAAAA after")
    result = ProtectedArchiveLeakScanner().scan_text(
        path="unknown.json",
        content=json.dumps({"value": value}),
        known_original_values=originals,
        generated_tokens=frozenset({generated}) if registered else frozenset(),
    )
    assert result.passed is (registered and position == "token")
