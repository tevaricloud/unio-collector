from __future__ import annotations  # noqa: D104

from typing import TYPE_CHECKING

from unio_collector.scanners.registry.definitions.analytics_ai import (
    ANALYTICS_AI_SCANNER_DEFINITION_SOURCE,
    ANALYTICS_AI_SCANNERS,
)
from unio_collector.scanners.registry.definitions.audit_cost import (
    AUDIT_COST_SCANNER_DEFINITION_SOURCE,
    AUDIT_COST_SCANNERS,
)
from unio_collector.scanners.registry.definitions.aws_native_recommendations import (
    AWS_NATIVE_RECOMMENDATION_SCANNER_DEFINITION_SOURCE,
    AWS_NATIVE_RECOMMENDATION_SCANNERS,
)
from unio_collector.scanners.registry.definitions.cost import (
    COST_SCANNER_DEFINITION_SOURCE,
    COST_SCANNERS,
)
from unio_collector.scanners.registry.definitions.dynamodb import (
    DYNAMODB_SCANNER_DEFINITION_SOURCE,
    DYNAMODB_SCANNERS,
)
from unio_collector.scanners.registry.definitions.ec2 import (
    EC2_SCANNER_DEFINITION_SOURCE,
    EC2_SCANNERS,
)
from unio_collector.scanners.registry.definitions.network import (
    NETWORK_SCANNER_DEFINITION_SOURCE,
    NETWORK_SCANNERS,
)
from unio_collector.scanners.registry.definitions.observability import (
    OBSERVABILITY_SCANNER_DEFINITION_SOURCE,
    OBSERVABILITY_SCANNERS,
)
from unio_collector.scanners.registry.definitions.platform import (
    PLATFORM_SCANNER_DEFINITION_SOURCE,
    PLATFORM_SCANNERS,
)
from unio_collector.scanners.registry.definitions.security.governance import (
    SECURITY_GOVERNANCE_SCANNER_DEFINITION_SOURCE,
    SECURITY_GOVERNANCE_SCANNERS,
)
from unio_collector.scanners.registry.definitions.serverless import (
    SERVERLESS_SCANNER_DEFINITION_SOURCE,
    SERVERLESS_SCANNERS,
)
from unio_collector.scanners.registry.definitions.service.coverage import (
    SERVICE_COVERAGE_SCANNER_DEFINITION_SOURCE,
    SERVICE_COVERAGE_SCANNERS,
)
from unio_collector.scanners.registry.definitions.service.quotas import (
    SERVICE_QUOTA_SCANNER_DEFINITION_SOURCE,
    SERVICE_QUOTA_SCANNERS,
)
from unio_collector.scanners.registry.definitions.storage import (
    STORAGE_SCANNER_DEFINITION_SOURCE,
    STORAGE_SCANNERS,
)
from unio_collector.scanners.registry.definitions.tagging import (
    TAGGING_SCANNER_DEFINITION_SOURCE,
    TAGGING_SCANNERS,
)
from unio_collector.scanners.registry.definitions.utilization import (
    UTILIZATION_SCANNER_DEFINITION_SOURCE,
    UTILIZATION_SCANNERS,
)
from unio_collector.scanners.registry.discovery import ScannerDiscoveryRegistry

if TYPE_CHECKING:
    from unio_collector.scanners.registry.source import ScannerDefinitionSource
    from unio_collector.scanners.scanner.definition import ScannerDefinition

BUILT_IN_SCANNER_DEFINITION_SOURCES: tuple[ScannerDefinitionSource, ...] = (
    ANALYTICS_AI_SCANNER_DEFINITION_SOURCE,
    AUDIT_COST_SCANNER_DEFINITION_SOURCE,
    AWS_NATIVE_RECOMMENDATION_SCANNER_DEFINITION_SOURCE,
    COST_SCANNER_DEFINITION_SOURCE,
    DYNAMODB_SCANNER_DEFINITION_SOURCE,
    EC2_SCANNER_DEFINITION_SOURCE,
    NETWORK_SCANNER_DEFINITION_SOURCE,
    OBSERVABILITY_SCANNER_DEFINITION_SOURCE,
    PLATFORM_SCANNER_DEFINITION_SOURCE,
    SECURITY_GOVERNANCE_SCANNER_DEFINITION_SOURCE,
    SERVICE_COVERAGE_SCANNER_DEFINITION_SOURCE,
    SERVICE_QUOTA_SCANNER_DEFINITION_SOURCE,
    SERVERLESS_SCANNER_DEFINITION_SOURCE,
    STORAGE_SCANNER_DEFINITION_SOURCE,
    TAGGING_SCANNER_DEFINITION_SOURCE,
    UTILIZATION_SCANNER_DEFINITION_SOURCE,
)

SCANNERS: dict[str, ScannerDefinition] = ScannerDiscoveryRegistry(
    BUILT_IN_SCANNER_DEFINITION_SOURCES,
).discover_definitions()

__all__ = [
    "ANALYTICS_AI_SCANNERS",
    "ANALYTICS_AI_SCANNER_DEFINITION_SOURCE",
    "AUDIT_COST_SCANNERS",
    "AUDIT_COST_SCANNER_DEFINITION_SOURCE",
    "AWS_NATIVE_RECOMMENDATION_SCANNERS",
    "AWS_NATIVE_RECOMMENDATION_SCANNER_DEFINITION_SOURCE",
    "BUILT_IN_SCANNER_DEFINITION_SOURCES",
    "COST_SCANNERS",
    "COST_SCANNER_DEFINITION_SOURCE",
    "DYNAMODB_SCANNERS",
    "DYNAMODB_SCANNER_DEFINITION_SOURCE",
    "EC2_SCANNERS",
    "EC2_SCANNER_DEFINITION_SOURCE",
    "NETWORK_SCANNERS",
    "NETWORK_SCANNER_DEFINITION_SOURCE",
    "OBSERVABILITY_SCANNERS",
    "OBSERVABILITY_SCANNER_DEFINITION_SOURCE",
    "PLATFORM_SCANNERS",
    "PLATFORM_SCANNER_DEFINITION_SOURCE",
    "SCANNERS",
    "SECURITY_GOVERNANCE_SCANNERS",
    "SECURITY_GOVERNANCE_SCANNER_DEFINITION_SOURCE",
    "SERVERLESS_SCANNERS",
    "SERVERLESS_SCANNER_DEFINITION_SOURCE",
    "SERVICE_COVERAGE_SCANNERS",
    "SERVICE_COVERAGE_SCANNER_DEFINITION_SOURCE",
    "SERVICE_QUOTA_SCANNERS",
    "SERVICE_QUOTA_SCANNER_DEFINITION_SOURCE",
    "STORAGE_SCANNERS",
    "STORAGE_SCANNER_DEFINITION_SOURCE",
    "TAGGING_SCANNERS",
    "TAGGING_SCANNER_DEFINITION_SOURCE",
    "UTILIZATION_SCANNERS",
    "UTILIZATION_SCANNER_DEFINITION_SOURCE",
]
