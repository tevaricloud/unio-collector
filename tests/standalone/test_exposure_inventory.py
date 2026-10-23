"""Compare explicit privacy fields with actual producer DTOs and pinned SDK models."""

from dataclasses import fields
from typing import Any

import pytest
from botocore.session import Session

from unio_collector.privacy.exposure.fields import ECR, GROUP, PUBLIC, SCANNERS, VOCABULARIES
from unio_collector.scanners.account_risk.root.recovery.evidence import RootAccountRecoveryAdvisoryEvidence
from unio_collector.scanners.ecr.image_scan.evidence import EcrImageScanPostureEvidence
from unio_collector.scanners.ecr.image_scan.registry_record import EcrRegistryScanRecord
from unio_collector.scanners.ecr.image_scan.repository_record import EcrRepositoryScanRecord
from unio_collector.scanners.security_governance.public_exposure.evidence import PublicServiceExposureEvidence
from unio_collector.scanners.security_governance.public_exposure.record import PublicServiceExposureRecord
from unio_collector.scanners.security_governance.security_group.evidence import SecurityGroupExposureEvidence
from unio_collector.scanners.security_governance.security_group.ingress_rule import SecurityGroupIngressRule

pytestmark = pytest.mark.offline


@pytest.mark.parametrize(
    ("mapping", "prefix", "dto"),
    [
        (GROUP, "", SecurityGroupExposureEvidence),
        (GROUP, "public_ingress_rules[].", SecurityGroupIngressRule),
        (PUBLIC, "", PublicServiceExposureEvidence),
        (PUBLIC, "records[].", PublicServiceExposureRecord),
        (PUBLIC, "global_records[].", PublicServiceExposureRecord),
        (ECR, "", EcrImageScanPostureEvidence),
        (ECR, "repositories[].", EcrRepositoryScanRecord),
        (ECR, "registries[].", EcrRegistryScanRecord),
        (SCANNERS["root-account-recovery-advisory"][2], "", RootAccountRecoveryAdvisoryEvidence),
    ],
)
def test_exposure_dto_inventory(mapping: dict, prefix: str, dto: type) -> None:
    """Producer field additions cannot disappear through simplified synthetic fixtures."""
    declared = {
        path[len(prefix) :]
        for path in mapping
        if path.startswith(prefix) and path != prefix and "." not in path[len(prefix) :] and "[" not in path[len(prefix) :]
    }
    assert declared == {field.name for field in fields(dto)}


@pytest.mark.parametrize(
    ("kind", "service", "operation", "path"),
    [
        ("registry_scan", "ecr", "GetRegistryScanningConfiguration", ("scanningConfiguration", "scanType")),
        ("tag_mutability", "ecr", "DescribeRepositories", ("repositories", "[]", "imageTagMutability")),
        ("repository_encryption", "ecr", "DescribeRepositories", ("repositories", "[]", "encryptionConfiguration", "encryptionType")),
        ("balancer_type", "elbv2", "DescribeLoadBalancers", ("LoadBalancers", "[]", "Type")),
        ("api_protocol", "apigatewayv2", "GetApis", ("Items", "[]", "ProtocolType")),
        ("endpoint_type", "apigateway", "GetRestApis", ("items", "[]", "endpointConfiguration", "types", "[]")),
    ],
)
def test_exposure_sdk_vocabulary(kind: str, service: str, operation: str, path: tuple[str, ...]) -> None:
    """Finite controls match independently inspected pinned provider output models."""
    shape: Any = Session().get_service_model(service).operation_model(operation).output_shape
    for name in path:
        shape = shape.member if name == "[]" else shape.members[name]
    assert VOCABULARIES[kind] == set(shape.enum)


def test_ecr_actual_sdk_response_collects_registry() -> None:
    """Use the real SDK response spelling, not a fixture matching a wrong lookup."""
    from tools.collector_exposure.fixture import exposure_producer_observation  # noqa: PLC0415

    observed = exposure_producer_observation("ecr-image-scan-posture-review")
    records = observed["evidence"]["payload"]["registries"]
    assert records == [{"region": "eu-west-2", "scan_type": "ENHANCED", "rule_count": 1}]
    assert observed["warnings"] == []
    assert observed["coverage_notes"][0]["registry_configuration_count"] == 1
