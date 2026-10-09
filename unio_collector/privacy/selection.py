"""Explicit selection of reviewed scanner privacy contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.privacy.account_risk import AccountRiskPrivacyContract
from unio_collector.privacy.active_findings import SecurityFindingsPrivacyContract
from unio_collector.privacy.athena import AthenaPrivacyContract
from unio_collector.privacy.bedrock import BedrockPrivacyContract
from unio_collector.privacy.config_compliance import ConfigCompliancePrivacyContract
from unio_collector.privacy.daily_evidence import DailyEvidencePrivacyContract
from unio_collector.privacy.ec2.elastic_ip import ElasticIpPrivacyContract
from unio_collector.privacy.ec2.iops import ProvisionedIopsPrivacyContract
from unio_collector.privacy.ec2.load_balancer import LoadBalancerPrivacyContract
from unio_collector.privacy.ec2.nat_inventory import NatInventoryPrivacyContract
from unio_collector.privacy.ec2.snapshot import SnapshotPrivacyContract
from unio_collector.privacy.ec2.stopped import StoppedInstancePrivacyContract
from unio_collector.privacy.ec2.volume import EbsVolumePrivacyContract
from unio_collector.privacy.gateway import GatewayPrivacyContract
from unio_collector.privacy.log_activity import LogActivityPrivacyContract
from unio_collector.privacy.network.nat_cost import NatCostPrivacyContract
from unio_collector.privacy.network.privatelink import PrivateLinkPrivacyContract
from unio_collector.privacy.network.public_ipv4 import PublicIpv4PrivacyContract
from unio_collector.privacy.network.transit import TransitGatewayPrivacyContract
from unio_collector.privacy.network.vpc import VpcEndpointPrivacyContract
from unio_collector.privacy.s3.lifecycle import S3LifecyclePrivacyContract
from unio_collector.privacy.s3.multipart import S3MultipartPrivacyContract
from unio_collector.privacy.s3.public_access import S3PublicAccessPrivacyContract
from unio_collector.privacy.service.coverage import ServiceCoveragePrivacyContract

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract


def select_producer_contract(record: dict[str, Any]) -> ClosedProducerContract | None:
    """Select only enumerated identities without dynamic imports or schema registration."""
    return (
        BedrockPrivacyContract.for_record(record)
        or AccountRiskPrivacyContract.for_record(record)
        or DailyEvidencePrivacyContract.for_record(record)
        or SecurityFindingsPrivacyContract.for_record(record)
        or ConfigCompliancePrivacyContract.for_record(record)
        or AthenaPrivacyContract.for_record(record)
        or GatewayPrivacyContract.for_record(record)
        or EbsVolumePrivacyContract.for_record(record)
        or ProvisionedIopsPrivacyContract.for_record(record)
        or StoppedInstancePrivacyContract.for_record(record)
        or SnapshotPrivacyContract.for_record(record)
        or LoadBalancerPrivacyContract.for_record(record)
        or ElasticIpPrivacyContract.for_record(record)
        or LogActivityPrivacyContract.for_record(record)
        or NatInventoryPrivacyContract.for_record(record)
        or PublicIpv4PrivacyContract.for_record(record)
        or PrivateLinkPrivacyContract.for_record(record)
        or TransitGatewayPrivacyContract.for_record(record)
        or NatCostPrivacyContract.for_record(record)
        or VpcEndpointPrivacyContract.for_record(record)
        or ServiceCoveragePrivacyContract.for_record(record)
        or S3PublicAccessPrivacyContract.for_record(record)
        or S3LifecyclePrivacyContract.for_record(record)
        or S3MultipartPrivacyContract.for_record(record)
    )
