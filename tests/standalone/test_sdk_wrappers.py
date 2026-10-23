"""Actual registered SDK-seam wrappers and callback notes through full protection."""

from __future__ import annotations

import copy
import hashlib
import io
import json
from importlib import import_module
from typing import TYPE_CHECKING, Any
from unittest.mock import patch
from zipfile import ZipFile

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_producers import producer_bundle
from tools.collector_athena_fixture import VARIANTS as ATHENA_VARIANTS
from tools.collector_athena_fixture import athena_producer_observation
from tools.collector_bedrock_fixture import SyntheticBedrockSession, bedrock_producer_observation
from tools.collector_gateway_fixture import VARIANTS as GATEWAY_VARIANTS
from tools.collector_gateway_fixture import gateway_producer_observation
from tools.collector_risk_fixture import account_risk_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from tools.collector_sdk_fixture import WRAPPERS
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.scanners.collection.class_paths import COLLECTOR_SCANNER_CLASS_PATHS

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
RISK = "account-cost-risk-signal-review"
GATEWAY = "api-gateway-cost-review"
ATHENA = "athena-query-efficiency-review"
BEDROCK = "bedrock-cost-review"
VARIANTS = {
    RISK: ("success", "empty", "unavailable", "denied", "partial", "capped", "status_unavailable", "name_only"),
    GATEWAY: GATEWAY_VARIANTS,
    ATHENA: ATHENA_VARIANTS,
    BEDROCK: ("success", "denied", "unsupported", "failure", "unavailable", "client_model", "validation_unsupported"),
}
FACTORIES = {
    RISK: account_risk_producer_observation,
    GATEWAY: gateway_producer_observation,
    ATHENA: athena_producer_observation,
    BEDROCK: bedrock_producer_observation,
}
CASES = [
    (scanner, variant, billing) for scanner, variants in VARIANTS.items() for variant in variants for billing in ((True,) if scanner == RISK else (True, False))
]


@pytest.mark.parametrize("scanner", tuple(WRAPPERS))
def test_synthetic_wrappers_match_live_registry(scanner: str) -> None:
    """The actual producer proof must exercise the live registered owner."""
    module, name = COLLECTOR_SCANNER_CLASS_PATHS[scanner].split(":", 1)
    assert WRAPPERS[scanner] is getattr(import_module(module), name)


@pytest.fixture(autouse=True)
def forbid_live_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Forbid live SDK clients before invoking any synthetic actual wrapper."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))


@pytest.fixture(scope="module")
def sdk_base(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """Share the same immutable expanded input used by the packaged smoke recipe."""
    with ZipFile(producer_bundle(tmp_path_factory.mktemp("sdk-base"))) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def observe(scanner: str, variant: str, *, billing: bool = True) -> dict[str, Any]:
    """Require the registered wrapper itself, not just its underlying SDK helper."""
    wrapper = WRAPPERS[scanner]
    original = wrapper.collect
    with patch.object(wrapper, "collect", autospec=True, side_effect=original) as observed:
        result = FACTORIES[scanner](variant, **({} if scanner == RISK else {"billing": billing}))
    assert observed.call_count == 1
    assert result["evidence"]["scanner_id"] == scanner
    assert result["evidence"]["serialization_status"] == "serialized"
    assert result["callbacks"]
    if scanner != RISK:
        assert result["execution"]["coverage_notes"]
    return result


@pytest.mark.parametrize(("scanner", "variant", "billing"), CASES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_registered_sdk_wrapper_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, variant: str, profile: str, *, billing: bool
) -> None:
    """Cover actual populated/empty/degraded/optional producers and all callback shapes."""
    observed = observe(scanner, variant, billing=billing)
    _case(tmp_path, monkeypatch, sdk_base, observed, profile)


@pytest.mark.parametrize("scanner", [GATEWAY, ATHENA, BEDROCK])
@pytest.mark.parametrize("mutation", ["payload_unknown", "note_unknown", "count", "scope", "missing", "foreign", "prose"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_sdk_note_privacy_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], scanner: str, mutation: str, profile: str
) -> None:
    """Reject nested unknown/type/identity errors and protect complete arbitrary prose."""
    observed = observe(scanner, "success")
    note = observed["execution"]["coverage_notes"][0]
    if mutation == "payload_unknown":
        observed["evidence"]["payload"]["unknown_sdk_field"] = None
    elif mutation == "note_unknown":
        note["detail_counts"]["unknown_sdk_note_count"] = None
    elif mutation == "count":
        note["resource_count"] = True
    elif mutation == "scope":
        note["scope_area"] += "-customer"
    elif mutation == "missing":
        del note["resource_label"]
    elif mutation == "foreign":
        observed["execution"]["scanner_id"] = "untrusted-wrapper"
    else:
        note["summary"] = "synthetic-customer-free-prose"
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=mutation != "prose")


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base: dict[str, bytes], observed: dict[str, Any], profile: str, *, invalid: bool = False) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    files = dict(base)
    add_scanner_producer_payload(files, observed["evidence"], execution=observed["execution"])

    before_observation = copy.deepcopy(observed)
    checks = build_checksums(files)
    manifest = json.loads(files["manifest.json"])
    manifest["checksums"] = checks
    files["manifest.json"] = json.dumps(manifest).encode()
    files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checks}).encode()
    source = tmp_path / "source.zip"
    with ZipFile(source, "w") as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    output, vault = tmp_path / "transfer/protected.zip", tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-sdk-only\n"))
    code = main(
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
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    assert observed == before_observation
    if invalid:
        assert code == 1
        assert not output.exists()
        assert not vault.exists()
        assert not output.with_suffix(".zip.receipt.json").exists()
        assert not list(tmp_path.rglob("*.tmp"))
        return
    assert code == 0
    assert main(["validate-bundle", str(output)]) == 0
    checked = ProtectedBundleInspector().inspect(output)
    assert checked.validation_passed
    receipt, leak = checked.summary["receipt"], checked.summary["leak_scan"]
    assert isinstance(receipt, dict)
    assert isinstance(leak, dict)
    assert receipt["verified"]
    assert leak["passed"]
    assert leak["findings"] == []
    with ZipFile(output) as archive:
        assert b"synthetic-customer-free-prose" not in archive.read("scan-result/scanner-results.json")


@pytest.mark.parametrize("scanner", [GATEWAY, ATHENA, BEDROCK])
@pytest.mark.parametrize("mutation", ["customer", "foreign", "unknown", "literal"])
def test_sdk_notes_reject_customer_leaks(scanner: str, mutation: str) -> None:
    """Finite metadata roles never exempt arbitrary text or a forged parent binding."""
    result = observe(scanner, "success")["execution"]
    operation = transformer("standard")
    protected = operation.transform({"scanner_results": [result]}, file_name="scan-result/scanner-results.json")
    assert not operation.summary.unclassified
    note = protected["scanner_results"][0]["coverage_notes"][0]
    original = scanner
    if mutation == "customer":
        note["summary"] = scanner
    elif mutation == "foreign":
        protected["scanner_results"][0]["scanner_id"] = "untrusted-wrapper"
    elif mutation == "unknown":
        note["unknown_customer"] = scanner
    else:
        note["scope_area"] = scanner
    scan = ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-results.json", content=json.dumps(protected), known_original_values={original})
    assert not scan.passed


@pytest.mark.parametrize(
    ("variant", "literal"),
    [
        ("unsupported", "UnknownOperationException"),
        ("client_model", "UnsupportedClientModelOperation"),
        ("validation_unsupported", "ValidationException"),
        ("unsupported", "execution_detail"),
        ("unsupported", "bedrock_operation_capability"),
    ],
)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_bedrock_capability_identifier_collisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], variant: str, literal: str, profile: str
) -> None:
    """Real provisioned-model names equal to finite controls still protect and validate."""
    monkeypatch.setattr(
        SyntheticBedrockSession, "list_provisioned_model_throughputs", lambda *_a, **_k: {"provisionedModelSummaries": [{"provisionedModelName": literal}]}
    )
    _case(tmp_path, monkeypatch, sdk_base, observe(BEDROCK, variant), profile)


@pytest.mark.parametrize("mutation", ["unknown_code", "wrong_pair", "missing_action"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_bedrock_capability_malformed_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sdk_base: dict[str, bytes], mutation: str, profile: str) -> None:
    """Exact status/code pairing and complete capability DTOs are admission contracts."""
    observed = observe(BEDROCK, "unsupported")
    limitation = observed["evidence"]["payload"]["records"][0]["operation_limitations"][0]
    if mutation == "unknown_code":
        limitation["error_code"] = "synthetic-customer-code"
    elif mutation == "wrong_pair":
        limitation["error_code"] = "UnsupportedClientModelOperation"
    else:
        del limitation["api_action"]
    _case(tmp_path, monkeypatch, sdk_base, observed, profile, invalid=True)
