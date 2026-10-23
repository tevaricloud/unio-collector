"""Mechanism regressions for exact metadata collisions without plaintext exemptions."""

from __future__ import annotations

import copy
import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tests.standalone.test_sdk_wrappers import sdk_base as sdk_base  # noqa: PLC0414
from tools.collector_dynamodb.fixture import dynamodb_producer_observation
from tools.collector_serverless.fixture import COLLECTORS, LAMBDA, serverless_producer_observation
from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.dynamodb.contract import DynamoPrivacyContract
from unio_collector.privacy.known_originals import collect_known_original_values
from unio_collector.privacy.leak.public.protocol import ProtocolScanContract
from unio_collector.privacy.leak.public.result import ResultMetadataScanContract
from unio_collector.privacy.leak.public.serverless import ServerlessScanContract
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

MEMBER = "scan-result/scanner-evidence.json"
pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", COLLECTORS)
def test_actual_serverless_implementation_roles(scanner: str) -> None:
    """Compare source-declared identities; module/class text is public only as an exact pair."""
    row = serverless_producer_observation(scanner)["execution"]
    assert ServerlessScanContract.implementation(row)
    actual = copy.deepcopy(row)
    rendered = json.dumps(ResultMetadataScanContract.mask(actual))
    assert row["implementation_module"] not in rendered
    assert row["implementation_class"] not in rendered
    assert actual == row
    for field in ("implementation_module", "implementation_class", "implementation_type"):
        invalid = copy.deepcopy(row)
        invalid[field] += "-customer"
        assert not ServerlessScanContract.implementation(invalid)
        masked = ResultMetadataScanContract.mask(invalid)
        assert invalid[field] in json.dumps(masked)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["customer", "unknown", "foreign", "service", "boundary"])
def test_registered_lambda_syntax_retains_leak_checks(profile: str, mutation: str) -> None:
    """Actual registered-token ARNs are distinct from customer values or borrowed roles."""
    source = {"scanner_evidence": [serverless_producer_observation(LAMBDA)["evidence"]]}
    operation = transformer(profile)
    protected = operation.transform(source, file_name=MEMBER)
    assert not operation.summary.unclassified
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(
        path=MEMBER, content=json.dumps(protected), known_original_values={"lambda", "InventoryEvidence"}, generated_tokens=generated
    ).passed
    row = protected["scanner_evidence"][0]
    record = row["payload"]["records"][0]
    if mutation == "customer":
        record["function_name"] = "lambda"
    elif mutation == "unknown":
        record["unknown_customer"] = "lambda"
    elif mutation == "foreign":
        row["provider_id"] = "untrusted-provider"
    elif mutation == "service":
        record["function_arn"] = record["function_arn"].replace(":lambda:", ":lambda-customer:")
    else:
        record["function_arn"] += "lambda"
    result = scanner.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"lambda", "InventoryEvidence"}, generated_tokens=generated)
    assert any(finding.category == "known_original_value" for finding in result.findings)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_sampled_tag_keys_follow_the_existing_mapping_policy(profile: str) -> None:
    """Standard non-personal keys and strict/private keys match their map representation."""
    observed = dynamodb_producer_observation()
    operation = transformer(profile)
    protected = operation.transform({"scanner_evidence": [observed["evidence"]]}, file_name=MEMBER)
    assert not operation.summary.unclassified
    keys = protected["scanner_evidence"][0]["payload"]["records"][0]["sample_tag_keys"]
    assert ("Environment" in keys) == (profile == "standard")
    assert "Owner" not in keys
    originals = collect_known_original_values(operation._value_tokens._token_service, minimum_length=4)  # noqa: SLF001
    assert "Owner" in originals
    assert ("Environment" in originals) == (profile == "strict")


@pytest.mark.parametrize("field", ["service_current_cost", "service_previous_cost", "regional_current_cost"])
def test_scan_redactions_do_not_admit_empty_raw_money(field: str) -> None:
    """A scan-only copy recognises exact removed money; raw source remains invalid."""
    record = dynamodb_producer_observation()["evidence"]["payload"]["records"][0]
    record[field] = ""
    before = copy.deepcopy(record)
    contract = DynamoPrivacyContract()
    assert contract.unknown_paths(record, "source", "records[]")
    assert contract.admitted_scan_record(record)
    assert record == before
    record["unknown_customer"] = None
    assert not contract.admitted_scan_record(record)


@pytest.mark.parametrize("literal", ["available", "unavailable"])
def test_scalar_protocol_roles_do_not_borrow_whole_root_admission(literal: str) -> None:
    """An explicit field call works; an unknown full root never obtains that role."""
    contract = ProtocolScanContract()
    assert contract.mask("collection-summary.json", literal, "$.billing_region_coverage.status") == ""
    source = {"billing_region_coverage": {"status": literal}, "unknown_customer": literal}
    assert contract.mask("collection-summary.json", source) == source


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("spelling", ["wire", "collector"])
def test_actual_permission_assessment_labels(sdk_base: dict[str, bytes], profile: str, spelling: str) -> None:
    """Actual permissions output and both published labels retain their exact role."""
    source = json.loads(sdk_base["permissions-summary.json"])
    assert source["assessment_method"] == f"observed_{UNIO_PROTOCOL.import_namespace}_api_calls"
    operation = transformer(profile)
    protected = operation.transform(source, file_name="permissions-summary.json")
    assert not operation.summary.unclassified
    namespace = UNIO_PROTOCOL.namespace if spelling == "wire" else "unio_collector"
    protected["assessment_method"] = f"observed_{namespace}_api_calls"
    tokens = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    assert (
        ProtectedArchiveLeakScanner()
        .scan_text(path="permissions-summary.json", content=json.dumps(protected), known_original_values={"observed"}, generated_tokens=tokens)
        .passed
    )


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["customer", "unknown", "method", "type", "provider", "member", "boundary"])
def test_assessment_labels_do_not_hide_customer_text(sdk_base: dict[str, bytes], profile: str, mutation: str) -> None:
    """No arbitrary method, customer field, foreign root or suffix borrows the finite role."""
    operation = transformer(profile)
    protected = operation.transform(json.loads(sdk_base["permissions-summary.json"]), file_name="permissions-summary.json")
    assert not operation.summary.unclassified
    member = "permissions-summary.json"
    if mutation == "customer":
        protected["profile_name"] = "observed"
    elif mutation == "unknown":
        protected["unknown_customer"] = "observed"
    elif mutation == "method":
        protected["assessment_method"] = "observed_untrusted_api_calls"
    elif mutation == "type":
        protected["assessment_method"] = ["observed"]
    elif mutation == "provider":
        protected["provider_id"] = "untrusted-provider"
    elif mutation == "member":
        member = "account-scope.json"
    else:
        protected["assessment_method"] += "-observed"
    tokens = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    result = ProtectedArchiveLeakScanner().scan_text(path=member, content=json.dumps(protected), known_original_values={"observed"}, generated_tokens=tokens)
    assert any(finding.category == "known_original_value" for finding in result.findings)
