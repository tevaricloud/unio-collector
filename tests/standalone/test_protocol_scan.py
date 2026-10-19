"""Typed metadata cannot hide customer text, unknown paths or forged tokens."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_identity_fixture import identity_producer_observation
from unio_collector.privacy.leak.public import region as region_contract
from unio_collector.privacy.leak.public.region import registered_arn_view
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.profiles import load_privacy_profile
from unio_collector.privacy.strict_verifier import StrictTransformationVerifier

if TYPE_CHECKING:
    from botocore.loaders import Loader

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("literal", ["complete", "eu-west-2"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_alias_customer_plaintext_remains_visible(literal: str, profile: str) -> None:
    """Same producer values survive only as declared metadata, never customer names."""
    row = identity_producer_observation("iam-access-analyzer-evidence-review", "name_complete" if literal == "complete" else "name_region")["evidence"]
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    result["scanner_evidence"][0]["payload"]["analyzers"][0]["analyzer_name"] = literal
    scan = ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={literal})
    assert any(f.category == "known_original_value" for f in scan.findings)


@pytest.mark.parametrize("mutation", ["unknown", "wrong_type", "forged_owner", "foreign_provider", "conflict", "unknown_customer"])
@pytest.mark.parametrize("literal", ["complete", "eu-west-2"])
def test_execution_metadata_trust_boundary(mutation: str, literal: str) -> None:
    """Only an owned, typed execution reference admits finite metadata."""
    row = {"scanner_id": "iam-access-analyzer-evidence-review", "status": "completed", "completed_at": None, "regions_scanned": ["eu-west-2"]}
    if mutation == "unknown":
        row["unknown"] = literal
    elif mutation == "wrong_type":
        row["completed_at"] = "complete" if literal == "complete" else literal
    elif mutation == "forged_owner":
        row["scanner_id"] = "untrusted"
    elif mutation == "foreign_provider":
        row["provider_id"] = "untrusted"
    elif mutation == "conflict":
        row["evidence_module"] = "untrusted"
    else:
        row["customer_name"] = literal
    if literal == "complete" and mutation in {"forged_owner", "foreign_provider", "conflict"}:
        row["status"] = "completed"
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-results.json", content=json.dumps({"scanner_results": [row]}), known_original_values={literal}
    )
    assert any(f.category == "known_original_value" for f in result.findings)


@pytest.mark.parametrize("literal", ["complete", "eu-west-2"])
def test_valid_execution_metadata(literal: str) -> None:
    """Nullable completion time and finite execution status/regions are protocol."""
    row = {"scanner_id": "iam-access-analyzer-evidence-review", "status": "completed", "completed_at": None, "regions_scanned": ["eu-west-2"]}
    assert (
        ProtectedArchiveLeakScanner()
        .scan_text(path="scan-result/scanner-results.json", content=json.dumps({"scanner_results": [row]}), known_original_values={literal})
        .passed
    )


@pytest.mark.parametrize("value", ["complete", ["complete"], {"complete": True}])
def test_malformed_protocol_fields_stay_visible(value: object) -> None:
    """A wrong type cannot borrow the boolean completion-key contract."""
    scan = ProtectedArchiveLeakScanner().scan_text(
        path="analysis-contract.json", content=json.dumps({"contains_completed_report_bundle": value}), known_original_values={"complete"}
    )
    assert not scan.passed


@pytest.mark.parametrize("registered", [False, True])
@pytest.mark.parametrize("malformed", [False, True])
def test_arn_region_requires_real_registered_tokens(*, registered: bool, malformed: bool) -> None:
    """Retained public ARN regions never excuse malformed/unregistered identifiers."""
    account = "ACCOUNT-AAAAAAAAAAAAAAAA" if not malformed else "ACCOUNT-complete"
    resource = "RESOURCE-BBBBBBBBBBBBBBBB" if not malformed else "RESOURCE-complete"
    arn = f"arn:aws:access-analyzer:eu-west-2:{account}:{resource}"
    tokens = frozenset({account, resource}) if registered else frozenset()
    viewed = registered_arn_view(arn, tokens)
    assert (viewed != arn) is (registered and not malformed)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_profile_arn_region_contract(profile: str) -> None:
    """Strict removes regional ARN components; independent verifier rejects restoration."""
    row = identity_producer_observation("iam-access-analyzer-evidence-review")["evidence"]
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    arn = result["scanner_evidence"][0]["payload"]["analyzers"][0]["analyzer_arn"]
    assert arn.split(":", 5)[3] == ("aws-region" if profile == "strict" else "eu-west-2")
    if profile == "strict":
        result["scanner_evidence"][0]["payload"]["analyzers"][0]["analyzer_arn"] = arn.replace(":aws-region:", ":eu-west-2:")
        with pytest.raises(ValueError, match="Strict privacy transformation verification failed"):
            StrictTransformationVerifier().verify({"scan-result/scanner-evidence.json": json.dumps(result).encode()}, load_privacy_profile("strict"))


@pytest.mark.parametrize("position", ["left_boundary", "full_arn", "plaintext", "inside_token"])
def test_owned_arn_view_preserves_registered_boundaries(position: str) -> None:
    """Public-region normalization cannot hide a composite customer original."""
    row = identity_producer_observation("iam-access-analyzer-evidence-review")["evidence"]
    transformed = transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    arn = transformed["scanner_evidence"][0]["payload"]["analyzers"][0]["analyzer_arn"]
    parts = arn.split(":", 5)
    tokens = frozenset(parts[4:])
    original = parts[3] + ":" + parts[4][:12]
    if position == "full_arn":
        original = arn
    elif position == "plaintext":
        original = "eu-west-2"
        transformed["scanner_evidence"][0]["payload"]["analyzers"][0]["analyzer_name"] = original
    elif position == "inside_token":
        original = parts[4][-8:]
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(transformed), known_original_values={original, "eu-west-2"}, generated_tokens=tokens
    )
    assert result.passed is (position == "inside_token")


@pytest.mark.parametrize(
    ("partition", "service", "region"),
    [
        ("", "iam", "eu-west-2"),
        ("untrusted", "iam", "eu-west-2"),
        ("aws-cn", "iam", "eu-west-2"),
        ("aws", "", "eu-west-2"),
        ("aws", "bad service", "eu-west-2"),
    ],
)
def test_malformed_arn_frame_cannot_borrow_regional_view(partition: str, service: str, region: str) -> None:
    """Unknown partitions, mismatched locations and malformed services stay visible."""
    tokens = frozenset({"ACCOUNT-AAAAAAAAAAAAAAAA", "RESOURCE-BBBBBBBBBBBBBBBB"})
    arn = f"arn:{partition}:{service}:{region}:ACCOUNT-AAAAAAAAAAAAAAAA:RESOURCE-BBBBBBBBBBBBBBBB"
    assert registered_arn_view(arn, tokens) == arn


def test_pinned_arn_inventory_does_not_cache_token_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    """Repeated table use never lends one operation's token authorisation."""
    original = region_contract.create_loader
    calls = []

    def observed_loader() -> Loader:
        calls.append(True)
        return original()

    region_contract.public_partitions.cache_clear()
    monkeypatch.setattr(region_contract, "create_loader", observed_loader)
    tokens = frozenset({"ACCOUNT-AAAAAAAAAAAAAAAA", "RESOURCE-BBBBBBBBBBBBBBBB"})
    account, resource = sorted(tokens)
    arn = f"arn:aws:access-analyzer:eu-west-2:{account}:{resource}"
    try:
        for _ in range(3):
            assert registered_arn_view(arn, tokens) != arn
            assert registered_arn_view(arn, frozenset()) == arn
            malformed = arn.replace("arn:aws:", "arn:aws-cn:")
            assert registered_arn_view(malformed, tokens) == malformed
        assert len(calls) == 1
    finally:
        region_contract.public_partitions.cache_clear()
