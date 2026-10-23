"""Explicit selection of reviewed scanner privacy contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.privacy.account_risk import AccountRiskPrivacyContract
from unio_collector.privacy.active_findings import SecurityFindingsPrivacyContract
from unio_collector.privacy.analytics.glue import GluePrivacyContract
from unio_collector.privacy.analytics.sagemaker import SageMakerPrivacyContract
from unio_collector.privacy.athena import AthenaPrivacyContract
from unio_collector.privacy.audit.governance.config import ConfigGovernancePrivacyContract
from unio_collector.privacy.audit.governance.guardduty import GuardDutyPrivacyContract
from unio_collector.privacy.audit.governance.security import SecurityServicesPrivacyContract
from unio_collector.privacy.audit.governance.waf import WafPrivacyContract
from unio_collector.privacy.audit.secrets import SecretsPrivacyContract
from unio_collector.privacy.audit.trail.cost import TrailCostPrivacyContract
from unio_collector.privacy.audit.trail.security import TrailSecurityPrivacyContract
from unio_collector.privacy.audit.xray import XRayPrivacyContract
from unio_collector.privacy.backup.contract import BackupPrivacyContract
from unio_collector.privacy.bedrock import BedrockPrivacyContract
from unio_collector.privacy.billing.contract import BillingPrivacyContract
from unio_collector.privacy.commitment.contract import CommitmentPrivacyContract
from unio_collector.privacy.config_compliance import ConfigCompliancePrivacyContract
from unio_collector.privacy.cost_delta import CostDeltaPrivacyContract
from unio_collector.privacy.cur import CurPrivacyContract
from unio_collector.privacy.daily_evidence import DailyEvidencePrivacyContract
from unio_collector.privacy.dynamodb.contract import DynamoPrivacyContract
from unio_collector.privacy.ec2.elastic_ip import ElasticIpPrivacyContract
from unio_collector.privacy.ec2.idle import IdleBundlePrivacyContract
from unio_collector.privacy.ec2.iops import ProvisionedIopsPrivacyContract
from unio_collector.privacy.ec2.load_balancer import LoadBalancerPrivacyContract
from unio_collector.privacy.ec2.nat_inventory import NatInventoryPrivacyContract
from unio_collector.privacy.ec2.running import RunningInstancePrivacyContract
from unio_collector.privacy.ec2.snapshot import SnapshotPrivacyContract
from unio_collector.privacy.ec2.stopped import StoppedInstancePrivacyContract
from unio_collector.privacy.ec2.volume import EbsVolumePrivacyContract
from unio_collector.privacy.edge.alb import AlbOriginPrivacyContract
from unio_collector.privacy.edge.cost import CloudFrontCostPrivacyContract
from unio_collector.privacy.exposure.ecr import EcrPrivacyContract
from unio_collector.privacy.exposure.group import SecurityGroupPrivacyContract
from unio_collector.privacy.exposure.public import PublicExposurePrivacyContract
from unio_collector.privacy.exposure.root import RootRecoveryPrivacyContract
from unio_collector.privacy.flow.contract import FlowPrivacyContract
from unio_collector.privacy.free_tier import FreeTierPrivacyContract
from unio_collector.privacy.gateway import GatewayPrivacyContract
from unio_collector.privacy.identity.account import AccountSecurityPrivacyContract
from unio_collector.privacy.identity.analyzer import AnalyzerPrivacyContract
from unio_collector.privacy.identity.center import IdentityCenterPrivacyContract
from unio_collector.privacy.identity.coverage import SecurityCoveragePrivacyContract
from unio_collector.privacy.key_controls.encryption import EncryptionPrivacyContract
from unio_collector.privacy.key_controls.kms.cost import KmsCostPrivacyContract
from unio_collector.privacy.key_controls.kms.posture import KmsPosturePrivacyContract
from unio_collector.privacy.key_controls.securityhub import ControlSummaryPrivacyContract
from unio_collector.privacy.log_activity import LogActivityPrivacyContract
from unio_collector.privacy.network.nat_cost import NatCostPrivacyContract
from unio_collector.privacy.network.privatelink import PrivateLinkPrivacyContract
from unio_collector.privacy.network.public_ipv4 import PublicIpv4PrivacyContract
from unio_collector.privacy.network.transit import TransitGatewayPrivacyContract
from unio_collector.privacy.network.vpc import VpcEndpointPrivacyContract
from unio_collector.privacy.platform.ecs import EcsPrivacyContract
from unio_collector.privacy.platform.eks import EksPrivacyContract
from unio_collector.privacy.platform.elasticache import ElastiCachePrivacyContract
from unio_collector.privacy.platform.opensearch import OpenSearchPrivacyContract
from unio_collector.privacy.platform.redshift import RedshiftPrivacyContract
from unio_collector.privacy.quota import QuotaPrivacyContract
from unio_collector.privacy.rds.instance import RdsInstancePrivacyContract
from unio_collector.privacy.rds.snapshot import RdsSnapshotPrivacyContract
from unio_collector.privacy.recommendation.compute import ComputeRecommendationPrivacyContract
from unio_collector.privacy.recommendation.hub import HubRecommendationPrivacyContract
from unio_collector.privacy.retention import LogRetentionPrivacyContract
from unio_collector.privacy.s3.lifecycle import S3LifecyclePrivacyContract
from unio_collector.privacy.s3.multipart import S3MultipartPrivacyContract
from unio_collector.privacy.s3.public_access import S3PublicAccessPrivacyContract
from unio_collector.privacy.serverless.lambda_cycle.contract import LambdaPrivacyContract
from unio_collector.privacy.serverless.lifecycle import LifecyclePrivacyContract
from unio_collector.privacy.serverless.polling import SqsPollingPrivacyContract
from unio_collector.privacy.service.coverage import ServiceCoveragePrivacyContract
from unio_collector.privacy.tagging.contract import TaggingPrivacyContract

if TYPE_CHECKING:
    from unio_collector.privacy.closed_schema import ClosedProducerContract


def select_producer_contract(record: dict[str, Any]) -> ClosedProducerContract | None:
    """Select only enumerated identities without dynamic imports or schema registration."""
    return (
        CommitmentPrivacyContract.for_record(record)
        or FlowPrivacyContract.for_record(record)
        or TaggingPrivacyContract.for_record(record)
        or AlbOriginPrivacyContract.for_record(record)
        or CloudFrontCostPrivacyContract.for_record(record)
        or DynamoPrivacyContract.for_record(record)
        or BackupPrivacyContract.for_record(record)
        or LambdaPrivacyContract.for_record(record)
        or LifecyclePrivacyContract.for_record(record)
        or SqsPollingPrivacyContract.for_record(record)
        or RunningInstancePrivacyContract.for_record(record)
        or IdleBundlePrivacyContract.for_record(record)
        or RdsInstancePrivacyContract.for_record(record)
        or RdsSnapshotPrivacyContract.for_record(record)
        or BillingPrivacyContract.for_record(record)
        or ComputeRecommendationPrivacyContract.for_record(record)
        or HubRecommendationPrivacyContract.for_record(record)
        or CurPrivacyContract.for_record(record)
        or CostDeltaPrivacyContract.for_record(record)
        or FreeTierPrivacyContract.for_record(record)
        or QuotaPrivacyContract.for_record(record)
        or SecurityGroupPrivacyContract.for_record(record)
        or PublicExposurePrivacyContract.for_record(record)
        or EcrPrivacyContract.for_record(record)
        or RootRecoveryPrivacyContract.for_record(record)
        or BedrockPrivacyContract.for_record(record)
        or AccountRiskPrivacyContract.for_record(record)
        or DailyEvidencePrivacyContract.for_record(record)
        or SecurityFindingsPrivacyContract.for_record(record)
        or ConfigCompliancePrivacyContract.for_record(record)
        or EcsPrivacyContract.for_record(record)
        or EksPrivacyContract.for_record(record)
        or ElastiCachePrivacyContract.for_record(record)
        or OpenSearchPrivacyContract.for_record(record)
        or RedshiftPrivacyContract.for_record(record)
        or GluePrivacyContract.for_record(record)
        or SageMakerPrivacyContract.for_record(record)
        or AthenaPrivacyContract.for_record(record)
        or GatewayPrivacyContract.for_record(record)
        or EbsVolumePrivacyContract.for_record(record)
        or ProvisionedIopsPrivacyContract.for_record(record)
        or StoppedInstancePrivacyContract.for_record(record)
        or SnapshotPrivacyContract.for_record(record)
        or LoadBalancerPrivacyContract.for_record(record)
        or ElasticIpPrivacyContract.for_record(record)
        or LogActivityPrivacyContract.for_record(record)
        or LogRetentionPrivacyContract.for_record(record)
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
        or SecretsPrivacyContract.for_record(record)
        or TrailCostPrivacyContract.for_record(record)
        or TrailSecurityPrivacyContract.for_record(record)
        or XRayPrivacyContract.for_record(record)
        or ConfigGovernancePrivacyContract.for_record(record)
        or GuardDutyPrivacyContract.for_record(record)
        or SecurityServicesPrivacyContract.for_record(record)
        or WafPrivacyContract.for_record(record)
        or KmsCostPrivacyContract.for_record(record)
        or KmsPosturePrivacyContract.for_record(record)
        or EncryptionPrivacyContract.for_record(record)
        or ControlSummaryPrivacyContract.for_record(record)
        or AccountSecurityPrivacyContract.for_record(record)
        or AnalyzerPrivacyContract.for_record(record)
        or IdentityCenterPrivacyContract.for_record(record)
        or SecurityCoveragePrivacyContract.for_record(record)
    )
