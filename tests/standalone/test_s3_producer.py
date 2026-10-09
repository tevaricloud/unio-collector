"""Actual S3 producer contracts and explicit profile treatments."""

from __future__ import annotations

import copy
import json
from dataclasses import fields

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_s3_fixture import COLLECTORS, VARIANTS, s3_producer_case
from unio_collector.aws.s3.lifecycle.collection_summary import S3LifecycleCollectionSummary
from unio_collector.aws.s3.lifecycle.record import S3BucketLifecycleRecord
from unio_collector.aws.s3.multipart.bucket_context import S3MultipartBucketContext
from unio_collector.aws.s3.multipart.collection_summary import S3MultipartCollectionSummary
from unio_collector.aws.s3.multipart.upload import S3MultipartUploadRecord
from unio_collector.privacy.s3.fields import LIFECYCLE, MULTIPART, PUBLIC
from unio_collector.privacy.selection import select_producer_contract
from unio_collector.scanners.s3.incomplete_multipart.evidence import S3MultipartEvidence
from unio_collector.scanners.s3.lifecycle.evidence import S3LifecycleEvidence
from unio_collector.scanners.s3.public_access.bucket_record import S3PublicAccessBucketRecord
from unio_collector.scanners.s3.public_access.evidence import S3PublicAccessEvidence

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_s3_producer(scanner: str, variant: str, profile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run real wrappers and collectors, not hand-authored evidence DTOs."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row = s3_producer_case(scanner, variant)
    assert row["serialization_status"] == "serialized"
    payload = row["payload"]
    records = payload.get("records", payload.get("buckets"))
    assert len(records) == (0 if variant == "empty" else 1)
    if "public-access" not in scanner and variant in {"denied", "unavailable", "unsupported", "failure"}:
        assert payload["collection_summary"]["collection_complete"] is False
        assert payload["collection_summary"]["collection_partial"] or payload["collection_summary"]["collection_unavailable"]
    t = transformer(profile)
    protected = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    result = protected["scanner_evidence"][0]["payload"]
    encoded = json.dumps(result)
    assert "123456789012" not in encoded
    assert "synthetic-customer" not in encoded
    if "records" in payload:
        if profile == "strict":
            assert result["regions"] == ["aws-region"] if result["regions"] else not payload["regions"]
            assert "2026-09-01" not in encoded
            assert "123.45" not in encoded
        elif records:
            assert result["records"][0]["service_current_cost"] == "123.45"
            assert result["records"][0]["region"] == "eu-west-2"


@pytest.mark.parametrize(
    ("field_map", "prefix", "dto"),
    [
        (PUBLIC, "", S3PublicAccessEvidence),
        (PUBLIC, "buckets[].", S3PublicAccessBucketRecord),
        (LIFECYCLE, "", S3LifecycleEvidence),
        (LIFECYCLE, "records[].", S3BucketLifecycleRecord),
        (LIFECYCLE, "collection_summary.", S3LifecycleCollectionSummary),
        (MULTIPART, "", S3MultipartEvidence),
        (MULTIPART, "records[].", S3MultipartUploadRecord),
        (MULTIPART, "collection_summary.", S3MultipartCollectionSummary),
        (MULTIPART, "bucket_contexts[].", S3MultipartBucketContext),
    ],
)
def test_all_actual_dto_fields(field_map: dict, prefix: str, dto: type) -> None:
    """Fail when actual producer contracts grow beyond the explicitly reviewed fields."""
    actual = {
        path[len(prefix) :]
        for path in field_map
        if path.startswith(prefix) and path[len(prefix) :] and "." not in path[len(prefix) :] and "[" not in path[len(prefix) :]
    }
    assert actual == {field.name for field in fields(dto)}


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [None, {}, [], True, "synthetic-private"])
def test_unknown_s3_descendants(scanner: str, profile: str, value: object) -> None:
    """Reject unknown nulls, booleans, containers and strings before strict omission."""
    row = s3_producer_case(scanner)
    payload = row["payload"]
    for target in [
        payload,
        *payload.get("records", payload.get("buckets", [])),
        *([payload["collection_summary"]] if payload.get("collection_summary") else []),
    ]:
        mutated = copy.deepcopy(row)

        if target is payload:
            node = mutated["payload"]
        elif target is payload.get("collection_summary"):
            node = mutated["payload"]["collection_summary"]
        else:
            node = mutated["payload"].get("records", mutated["payload"].get("buckets"))[0]
        node["unknown_s3_field"] = value
        t = transformer(profile)
        t.transform({"scanner_evidence": [mutated]}, file_name="scan-result/scanner-evidence.json")
        assert any(path.endswith("unknown_s3_field") for path in t.summary.unclassified)


@pytest.mark.parametrize("scanner", COLLECTORS)
def test_s3_conflicting_identity(scanner: str) -> None:
    """No schema alias can admit a conflicting provider, module or DTO."""
    row = s3_producer_case(scanner)
    for key, value in (("provider_id", "unknown"), ("evidence_type", "Unknown"), ("evidence_module", "untrusted.module")):
        mutated = copy.deepcopy(row)
        mutated[key] = value
        with pytest.raises(ValueError, match="matching registered AWS evidence identity"):
            select_producer_contract(mutated)
