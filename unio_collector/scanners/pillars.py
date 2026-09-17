from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.scanners.registry.catalog import validate_scanner_ids
from unio_collector.scanners.registry.definitions import SCANNERS

SCAN_PILLAR_IDS = ("optimise", "secure", "govern", "automate")


@dataclass(frozen=True)
class ScannerPillarPolicy:
    """Classifies scanners into product pillars for coarse execution shaping."""

    scanner_pillars: dict[str, tuple[str, ...]]

    def get_pillars(self, scanner_id: str) -> tuple[str, ...]:  # noqa: D102
        return self.scanner_pillars.get(scanner_id, ("optimise",))

    def get_matching_scanner_ids(  # noqa: D102
        self,
        selected_pillars: tuple[str, ...],
    ) -> tuple[str, ...]:
        if not selected_pillars or set(selected_pillars) == set(SCAN_PILLAR_IDS):
            return tuple(sorted(SCANNERS))
        selected = set(selected_pillars)
        return tuple(scanner_id for scanner_id in sorted(SCANNERS) if selected & set(self.get_pillars(scanner_id)))

    def build_summary(self, selected_pillars: tuple[str, ...]) -> dict[str, object]:  # noqa: D102
        normalized = normalize_scan_pillars(selected_pillars)
        selected_set = set(normalized)
        all_selected = not normalized or selected_set == set(SCAN_PILLAR_IDS)
        by_pillar = {pillar: sorted(scanner_id for scanner_id in SCANNERS if pillar in self.get_pillars(scanner_id)) for pillar in SCAN_PILLAR_IDS}
        return {
            "selected_pillars": list(normalized or SCAN_PILLAR_IDS),
            "all_pillars_selected": all_selected,
            "available_pillars": list(SCAN_PILLAR_IDS),
            "scanner_count_by_pillar": {pillar: len(scanner_ids) for pillar, scanner_ids in by_pillar.items()},
        }


def normalize_scan_pillars(  # noqa: D103
    values: tuple[str, ...] | list[str] | None,
) -> tuple[str, ...]:
    if not values:
        return ()
    cleaned: list[str] = []
    for raw in values:
        for part in str(raw).split(","):
            value = part.strip().lower()
            if not value:
                continue
            if value == "all":
                return ()
            if value not in SCAN_PILLAR_IDS:
                allowed = ", ".join((*SCAN_PILLAR_IDS, "all"))
                msg = f"Scan pillar must be one of: {allowed}."
                raise ValueError(msg)
            if value not in cleaned:
                cleaned.append(value)
    return tuple(cleaned)


def build_default_scanner_pillar_policy() -> ScannerPillarPolicy:  # noqa: D103
    policy = ScannerPillarPolicy(scanner_pillars=_build_scanner_pillar_map())
    validate_scanner_ids(list(policy.scanner_pillars))
    return policy


def _build_scanner_pillar_map() -> dict[str, tuple[str, ...]]:
    return {
        "account-cost-risk-signal-review": ("optimise", "govern"),
        "active-security-finding-review": ("secure", "govern"),
        "api-gateway-cost-review": ("optimise", "govern"),
        "athena-query-efficiency-review": ("optimise",),
        "aws-config-compliance-review": ("secure", "govern"),
        "aws-security-service-coverage-review": ("secure", "govern"),
        "backup-retention-review": ("secure", "govern", "automate"),
        "bedrock-cost-review": ("optimise", "govern"),
        "billing-alerts-and-budgets-review": ("optimise", "govern", "automate"),
        "cloudfront-alb-origin-protection-review": (
            "secure",
            "govern",
            "automate",
        ),
        "cloudfront-origin-cost-review": ("optimise", "secure", "govern"),
        "cloudtrail-cost-governance-review": ("optimise", "govern"),
        "cloudtrail-security-posture-review": ("secure", "govern", "automate"),
        "cloudwatch-idle-log-review": ("optimise", "govern", "automate"),
        "cloudwatch-log-cost-and-relevance-review": ("optimise", "govern", "automate"),
        "cloudwatch-log-groups-without-retention": (
            "optimise",
            "secure",
            "govern",
            "automate",
        ),
        "commitment-and-pricing-review": ("optimise",),
        "compute-optimizer-recommendation-review": ("optimise", "automate"),
        "config-cost-governance-review": ("optimise", "govern"),
        "cost-explorer-service-delta": ("optimise", "govern"),
        "cost-optimization-hub-recommendation-review": ("optimise", "automate"),
        "cost-spike-analysis": ("optimise", "govern"),
        "cur-data-export-attribution": ("optimise", "govern"),
        "data-transfer-cost-review": ("optimise",),
        "dynamodb-cost-governance-review": ("optimise", "govern"),
        "ec2-idle-instance-review": ("optimise",),
        "ec2-security-group-exposure-review": ("secure", "govern"),
        "ec2-stopped-instances-with-storage": ("optimise",),
        "ec2-unassociated-elastic-ips": ("optimise",),
        "ec2-unattached-ebs-volumes": ("optimise",),
        "ecr-image-scan-posture-review": ("secure", "govern", "automate"),
        "ecs-cost-governance-review": ("optimise", "govern"),
        "eks-cost-risk-review": ("optimise", "secure", "govern"),
        "elasticache-cost-review": ("optimise", "secure", "govern"),
        "encryption-baseline-review": ("secure", "govern", "automate"),
        "extended-support-and-eol-review": ("secure", "govern", "automate"),
        "free-tier-usage-review": ("optimise",),
        "glue-job-crawler-cost-review": ("optimise", "govern"),
        "guardduty-cost-governance-review": ("optimise", "govern"),
        "iam-access-analyzer-evidence-review": ("secure", "govern"),
        "iam-account-security-review": ("secure", "govern", "automate"),
        "iam-identity-center-visibility-review": ("secure", "govern"),
        "idle-zombie-resource-detector": ("optimise", "automate"),
        "kms-cost-governance-review": ("optimise", "govern"),
        "kms-key-posture-review": ("secure", "govern", "automate"),
        "lambda-cost-cycle-risk-review": ("optimise", "govern", "automate"),
        "lightsail-cost-governance-review": ("optimise", "secure", "govern"),
        "load-balancer-idle-review": ("optimise",),
        "nat-gateway-cost-review": ("optimise",),
        "nat-gateway-inventory": ("optimise", "govern"),
        "network-privatelink-cost-review": ("optimise",),
        "network-public-ipv4-review": ("optimise", "secure", "govern"),
        "network-transit-gateway-cost-review": ("optimise",),
        "network-vpc-endpoint-opportunity-review": ("optimise", "automate"),
        "opensearch-cost-review": ("optimise", "secure", "govern"),
        "provisioned-iops-review": ("optimise",),
        "public-service-exposure-review": ("secure", "govern"),
        "rds-snapshot-retention-review": ("secure", "govern", "automate"),
        "rds-utilization-review": ("optimise",),
        "redshift-cost-review": ("optimise", "secure", "govern"),
        "root-account-recovery-advisory": ("secure", "govern"),
        "route53-cost-governance-review": ("optimise", "govern"),
        "s3-incomplete-multipart-review": ("optimise",),
        "s3-lifecycle-cost-review": ("optimise", "govern", "automate"),
        "s3-public-access-security-review": ("secure", "govern"),
        "s3-versioning-and-replication-review": ("secure", "govern", "automate"),
        "sagemaker-cost-review": ("optimise", "govern"),
        "secrets-manager-cost-governance-review": ("optimise", "govern"),
        "securityhub-control-summary-review": ("secure", "govern"),
        "securityhub-inspector-macie-cost-review": ("optimise", "secure", "govern"),
        "service-quota-proximity-review": ("govern",),
        "snapshot-age-review": ("optimise", "govern"),
        "sns-cost-governance-review": ("optimise", "govern"),
        "sqs-lambda-polling-cost-review": ("optimise",),
        "step-functions-cost-governance-review": ("optimise", "govern"),
        "tagging-missing-cost-tags": ("govern", "automate"),
        "vpc-flow-log-attribution": ("secure", "govern"),
        "waf-cost-governance-review": ("optimise", "secure", "govern"),
        "xray-tracing-cost-governance-review": ("optimise", "govern"),
    }


DEFAULT_SCANNER_PILLAR_POLICY = build_default_scanner_pillar_policy()
