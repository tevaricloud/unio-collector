"""Generated dynamic tag keys cannot acquire financial field semantics."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_billing_producer import _case as _exercise_billing
from tests.standalone.test_producers import producer_bundle
from tests.standalone.test_vpc_bundle import test_actual_vpc_bundle as _exercise_vpc
from tools.collector_billing.fixture import billing_producer_observation
from tools.collector_identity_fixture import identity_producer_observation
from tools.collector_storage_fixture import SCANNERS, storage_producer_case
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.profiles import load_privacy_profile
from unio_collector.privacy.strict_verifier import StrictTransformationVerifier
from unio_collector.privacy.token.codec import TokenV1Codec

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.privacy.canonicalization import CanonicalValue
    from unio_collector.privacy.token.domain import TokenDomain

pytestmark = pytest.mark.offline
TAG_KEY = "TAG-VRUVWAUE7VRCOSTA"


def _files() -> dict[str, bytes]:
    source, _, _ = storage_producer_case(SCANNERS[0])
    payload = transformer("strict").transform({"scanner_evidence": [source]}, file_name="scan-result/scanner-evidence.json")
    payload["scanner_evidence"][0]["payload"]["records"][0]["tags"] = {TAG_KEY: "TAG-AAAAAAAAAAAAAAAA"}
    return {"scan-result/scanner-evidence.json": json.dumps(payload).encode()}


def test_registered_tag_key_has_no_financial_semantics() -> None:
    """The exact observed suffix passes only with operation-local registration."""
    files = _files()
    verifier = StrictTransformationVerifier()
    with pytest.raises(ValueError, match="Strict privacy transformation"):
        verifier.verify(files, load_privacy_profile("strict"))
    verifier.verify(files, load_privacy_profile("strict"), generated_tokens=frozenset({TAG_KEY}))


@pytest.mark.parametrize("mutation", ["foreign", "malformed", "fixed_cost", "retained_arn"])
def test_registration_does_not_exempt_other_fields_or_values(mutation: str) -> None:
    """Registered text is not a blanket exemption for identity, shape or values."""
    files = _files()
    payload = json.loads(files["scan-result/scanner-evidence.json"])
    row = payload["scanner_evidence"][0]
    if mutation == "foreign":
        row["scanner_id"] = "untrusted-producer"
    elif mutation == "malformed":
        row["payload"]["records"][0]["tags"][TAG_KEY] = {"cost": "0.05"}
    elif mutation == "fixed_cost":
        payload["cost"] = "0.05"
    else:
        row["payload"]["records"][0]["tags"][TAG_KEY] = ":".join(("arn", "aws", "ec2", "eu-west-2", str(10**11 + 1), "volume/synthetic-resource"))
    files["scan-result/scanner-evidence.json"] = json.dumps(payload).encode()
    with pytest.raises(ValueError, match="Strict privacy transformation|matching registered AWS"):
        StrictTransformationVerifier().verify(files, load_privacy_profile("strict"), generated_tokens=frozenset({TAG_KEY, "cost"}))


@pytest.mark.parametrize("category", ["tag_key", "resource_id"])
def test_actual_strict_vpc_bundle_with_cost_like_generated_tags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, category: str) -> None:
    """Actual collection, protection, validation and receipts tolerate the suffix."""
    original = TokenV1Codec.candidate

    def candidate(
        self: TokenV1Codec,
        *,
        token_key: bytes,
        provider: str,
        domain: TokenDomain,
        canonical: CanonicalValue,
        collision_index: int,
        suffix_bytes: int,
    ) -> str:
        token = original(
            self, token_key=token_key, provider=provider, domain=domain, canonical=canonical, collision_index=collision_index, suffix_bytes=suffix_bytes
        )
        return token.split("-", 1)[0] + "-COST" + token.split("-", 1)[1][:12] if canonical.category == category else token

    monkeypatch.setattr(TokenV1Codec, "candidate", candidate)
    _exercise_vpc(tmp_path, monkeypatch, "optional", "strict", None)


@pytest.mark.parametrize("foreign", [False, True])
def test_generated_key_does_not_hide_plaintext_tag_values(*, foreign: bool) -> None:
    """Leak scanning still rejects customer text beside registered tag keys."""
    payload = json.loads(_files()["scan-result/scanner-evidence.json"])
    row = payload["scanner_evidence"][0]
    row["payload"]["records"][0]["tags"][TAG_KEY] = "synthetic-customer-marker"
    if foreign:
        row["scanner_id"] = "untrusted-producer"
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json",
        content=json.dumps(payload),
        known_original_values={"synthetic-customer-marker"},
        generated_tokens=frozenset({TAG_KEY}),
    )
    assert not result.passed


@pytest.mark.parametrize("mutation", [None, "unregistered", "amount", "unit", "foreign"])
def test_actual_budget_map_keys_keep_financial_value_enforcement(mutation: str | None) -> None:
    """Authenticated SDK-map keys are not money fields; their values remain checked."""
    source = billing_producer_observation()["evidence"]
    protected = transformer("strict").transform({"scanner_evidence": [source]}, file_name="scan-result/scanner-evidence.json")
    row = protected["scanner_evidence"][0]
    limits = row["payload"]["budgets"][0]["budget"]["PlannedBudgetLimits"]
    limit = next(iter(limits.values()))
    resource_key = "RESOURCE-CXDE6ZCHCOSTZYVS"
    row["payload"]["budgets"][0]["budget"]["PlannedBudgetLimits"] = {resource_key: limit}
    if mutation in {"amount", "unit"}:
        limit["Amount" if mutation == "amount" else "Unit"] = "0.05" if mutation == "amount" else "USD"
    if mutation == "foreign":
        row["provider_id"] = "untrusted-provider"
    files = {"scan-result/scanner-evidence.json": json.dumps(protected).encode()}
    registered = frozenset() if mutation == "unregistered" else frozenset({resource_key})
    if mutation is None:
        StrictTransformationVerifier().verify(files, load_privacy_profile("strict"), generated_tokens=registered)
    else:
        with pytest.raises(ValueError, match="Strict privacy transformation|matching registered AWS"):
            StrictTransformationVerifier().verify(files, load_privacy_profile("strict"), generated_tokens=registered)


def test_actual_strict_budget_bundle_with_cost_like_generated_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Actual SDK collection and final protection verify opaque map-key roles."""
    original = TokenV1Codec.candidate

    def candidate(
        self: TokenV1Codec,
        *,
        token_key: bytes,
        provider: str,
        domain: TokenDomain,
        canonical: CanonicalValue,
        collision_index: int,
        suffix_bytes: int,
    ) -> str:
        token = original(
            self, token_key=token_key, provider=provider, domain=domain, canonical=canonical, collision_index=collision_index, suffix_bytes=suffix_bytes
        )
        return "RESOURCE-COST" + token.split("-", 1)[1][:12] if canonical.category == "resource_id" else token

    monkeypatch.setattr(TokenV1Codec, "candidate", candidate)
    with ZipFile(producer_bundle(tmp_path)) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    _exercise_billing(tmp_path, monkeypatch, files, "strict", "success")


@pytest.mark.parametrize("registered", [False, True])
def test_registered_region_cannot_restore_strict_identity_map(*, registered: bool) -> None:
    """The region-key consumer removes the map in strict mode regardless of token registration."""
    source = identity_producer_observation("iam-access-analyzer-evidence-review")["evidence"]
    protected = transformer("strict").transform({"scanner_evidence": [source]}, file_name="scan-result/scanner-evidence.json")
    row = protected["scanner_evidence"][0]
    assert row["payload"]["analyzer_inventory_status"] == {}
    key = "REGION-COSTAAAAAAAAAAAA"
    row["payload"]["analyzer_inventory_status"] = {key: "complete"}
    files = {"scan-result/scanner-evidence.json": json.dumps(protected).encode()}
    with pytest.raises(ValueError, match="Strict privacy transformation"):
        StrictTransformationVerifier().verify(files, load_privacy_profile("strict"), generated_tokens=frozenset({key}) if registered else frozenset())
