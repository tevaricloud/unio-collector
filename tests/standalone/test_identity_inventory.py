"""Independent emitted DTO and pinned SDK vocabulary completeness assertions."""

from dataclasses import fields

import pytest
from botocore.session import Session

from unio_collector.privacy.identity.fields import ACCOUNT, ANALYZER, CENTER, COVERAGE, SUMMARY_KEYS, VOCABULARIES
from unio_collector.scanners.access_analyzer.evidence import AccessAnalyzerEvidence
from unio_collector.scanners.access_analyzer.finding_record import AccessAnalyzerFindingRecord
from unio_collector.scanners.access_analyzer.record import AccessAnalyzerRecord
from unio_collector.scanners.iam.access_key_record import IamAccessKeyRecord
from unio_collector.scanners.iam.account_security.evidence import IamAccountSecurityEvidence
from unio_collector.scanners.iam.policy_grant_record import IamPolicyGrantRecord
from unio_collector.scanners.iam.user_security_record import IamUserSecurityRecord
from unio_collector.scanners.identity_center.evidence import IdentityCenterEvidence
from unio_collector.scanners.identity_center.instance_record import IdentityCenterInstanceRecord
from unio_collector.scanners.identity_center.permission_set_record import IdentityCenterPermissionSetRecord
from unio_collector.scanners.regional.security_service_record import RegionalSecurityServiceRecord
from unio_collector.scanners.security_governance.service.coverage.evidence import SecurityServiceCoverageEvidence

pytestmark = pytest.mark.offline


@pytest.mark.parametrize(
    ("mapping", "prefix", "dto"),
    [
        (ACCOUNT, "", IamAccountSecurityEvidence),
        (ACCOUNT, "users[].", IamUserSecurityRecord),
        (ACCOUNT, "users[].access_keys[].", IamAccessKeyRecord),
        (ACCOUNT, "policy_grants[].", IamPolicyGrantRecord),
        (ANALYZER, "", AccessAnalyzerEvidence),
        (ANALYZER, "analyzers[].", AccessAnalyzerRecord),
        (ANALYZER, "findings[].", AccessAnalyzerFindingRecord),
        (CENTER, "", IdentityCenterEvidence),
        (CENTER, "instances[].", IdentityCenterInstanceRecord),
        (CENTER, "instances[].permission_sets[].", IdentityCenterPermissionSetRecord),
        (COVERAGE, "", SecurityServiceCoverageEvidence),
        (COVERAGE, "records[].", RegionalSecurityServiceRecord),
    ],
)
def test_identity_dto_inventory(mapping: dict, prefix: str, dto: type) -> None:
    """New actual DTO fields cannot disappear through mirrored fixture simplification."""
    declared = {
        path[len(prefix) :]
        for path in mapping
        if path.startswith(prefix) and path[len(prefix) :] and "." not in path[len(prefix) :] and "[" not in path[len(prefix) :]
    }
    assert declared == {field.name for field in fields(dto)}


@pytest.mark.parametrize(
    ("kind", "service", "shape", "extra"),
    [
        ("key_status", "iam", "statusType", set()),
        ("analyzer_type", "accessanalyzer", "Type", {"UNKNOWN"}),
        ("analyzer_status", "accessanalyzer", "AnalyzerStatus", set()),
        ("finding_type", "accessanalyzer", "FindingType", {"UNKNOWN"}),
        ("instance_status", "sso-admin", "InstanceStatus", set()),
    ],
)
def test_identity_sdk_values(kind: str, service: str, shape: str, extra: set[str]) -> None:
    """Finite vocabularies correlate with the pinned independent SDK model."""
    assert VOCABULARIES[kind] == set(Session().get_service_model(service).shape_for(shape).enum) | extra


def test_identity_sdk_summary() -> None:
    """Every provider SummaryMap key has an explicit typed count treatment."""
    assert set(SUMMARY_KEYS) == set(Session().get_service_model("iam").shape_for("summaryKeyType").enum)
