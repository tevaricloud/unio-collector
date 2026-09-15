from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.network.cloudfront_alb_protection.collection_helpers import (
    action_types,
    collect_items,
    condition_values,
    fixed_response_status,
    host_matches,
    http_header_conditions,
    is_default_deny,
    origins_by_load_balancer,
    to_int,
)
from unio_collector.scanners.network.cloudfront_alb_protection.coverage_record import (
    OriginProtectionCoverageRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.header import (
    OriginHeaderVerificationRecord,
    OriginHeaderVerifier,
)
from unio_collector.scanners.network.cloudfront_alb_protection.listener.rule_record import (
    AlbOriginListenerRuleRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.vpc_origin_record import (
    CloudFrontVpcOriginRecord,
)

if TYPE_CHECKING:
    from unio_collector.scanners.network.cloudfront_alb_protection.listener.record import (
        AlbOriginListenerRecord,
    )
    from unio_collector.scanners.network.cloudfront_alb_protection.load_balancer_record import (
        AlbOriginLoadBalancerRecord,
    )
    from unio_collector.scanners.network.cloudfront_alb_protection.origin_record import (
        CloudFrontAlbOriginRecord,
    )
    from unio_collector.scanners.scanner.context import ScannerContext


class ResidualOriginEvidenceCollector:
    """Collect VPC-origin and listener-rule evidence without retaining secrets."""

    def collect_vpc_origins(
        self,
        context: ScannerContext,
        origins: list[CloudFrontAlbOriginRecord],
        limitations: list[str],
        coverage: list[OriginProtectionCoverageRecord],
    ) -> list[CloudFrontVpcOriginRecord]:
        """Resolve each distinct VPC-origin ID once."""
        ids = sorted({origin.vpc_origin_id for origin in origins if origin.vpc_origin_id})
        if not ids:
            coverage.append(OriginProtectionCoverageRecord("global", "vpc_origin_detail", "not_applicable"))
            return []
        client = context.security.create_client(
            "cloudfront",
            region_name="us-east-1",
            collector_name="CloudFrontAlbOriginProtectionReviewScanner",
        )
        records: list[CloudFrontVpcOriginRecord] = []
        for vpc_origin_id in ids:
            evidence_ref = f"cloudfront-vpc-origin:{vpc_origin_id}"
            try:
                response = client.get_vpc_origin(Id=vpc_origin_id)
                vpc_origin = response.get("VpcOrigin")
                endpoint = vpc_origin.get("VpcOriginEndpointConfig") if isinstance(vpc_origin, dict) else None
                if not isinstance(endpoint, dict) or not endpoint.get("Arn"):
                    msg = f"CloudFront VPC-origin endpoint evidence was incomplete for {vpc_origin_id}."
                    limitations.append(msg)
                    records.append(CloudFrontVpcOriginRecord(vpc_origin_id=vpc_origin_id, evidence_ref=evidence_ref, limitation=msg))
                    coverage.append(OriginProtectionCoverageRecord(vpc_origin_id, "vpc_origin_detail", "unavailable", evidence_ref, msg))
                    continue
                records.append(
                    CloudFrontVpcOriginRecord(
                        vpc_origin_id=vpc_origin_id,
                        endpoint_arn=str(endpoint.get("Arn") or ""),
                        http_port=to_int(endpoint.get("HTTPPort")),
                        https_port=to_int(endpoint.get("HTTPSPort")),
                        origin_protocol_policy=str(endpoint.get("OriginProtocolPolicy") or ""),
                        status=str(vpc_origin.get("Status") or ""),
                        evidence_ref=evidence_ref,
                    ),
                )
                coverage.append(OriginProtectionCoverageRecord(vpc_origin_id, "vpc_origin_detail", "collected", evidence_ref))
            except Exception as exc:  # noqa: BLE001
                msg = f"CloudFront VPC-origin evidence unavailable for {vpc_origin_id}: {exc}"
                limitations.append(msg)
                records.append(CloudFrontVpcOriginRecord(vpc_origin_id=vpc_origin_id, evidence_ref=evidence_ref, limitation=msg))
                coverage.append(OriginProtectionCoverageRecord(vpc_origin_id, "vpc_origin_detail", "unavailable", evidence_ref, msg))
        return records

    def collect_listener_rules(
        self,
        context: ScannerContext,
        origins: list[CloudFrontAlbOriginRecord],
        vpc_origins: list[CloudFrontVpcOriginRecord],
        load_balancers: list[AlbOriginLoadBalancerRecord],
        listeners: list[AlbOriginListenerRecord],
        transient_headers: dict[tuple[str, str], dict[str, str]],
        limitations: list[str],
        coverage: list[OriginProtectionCoverageRecord],
    ) -> tuple[list[AlbOriginListenerRuleRecord], list[OriginHeaderVerificationRecord]]:
        """Collect sanitized rules and derived header comparisons."""
        rules: list[AlbOriginListenerRuleRecord] = []
        verifications: list[OriginHeaderVerificationRecord] = []
        verifier = OriginHeaderVerifier()
        origins_by_alb = origins_by_load_balancer(origins, vpc_origins, load_balancers)
        for listener in listeners:
            if not listener.listener_arn:
                coverage.append(OriginProtectionCoverageRecord(listener.load_balancer_arn, "listener_rules", "legacy_unknown"))
                continue
            client = context.security.create_client(
                "elbv2",
                region_name=listener.region,
                collector_name="CloudFrontAlbOriginProtectionReviewScanner",
            )
            try:
                raw_rules = collect_items(
                    client,
                    "describe_rules",
                    list_key="Rules",
                    item_key="Rules",
                    ListenerArn=listener.listener_arn,
                )
            except Exception as exc:  # noqa: BLE001
                msg = f"ALB listener-rule evidence unavailable for {listener.listener_arn}: {exc}"
                limitations.append(msg)
                coverage.append(OriginProtectionCoverageRecord(listener.listener_arn, "listener_rules", "unavailable", limitation=msg))
                continue
            coverage.append(
                OriginProtectionCoverageRecord(
                    listener.listener_arn,
                    "listener_rules",
                    "collected",
                    evidence_ref=f"elbv2-rules:{listener.listener_arn}",
                ),
            )
            for item in raw_rules:
                priority = str(item.get("Priority") or "")
                raw_conditions = item.get("Conditions")
                conditions: list[object] = list(raw_conditions) if isinstance(raw_conditions, list) else []
                actions = item.get("Actions")
                sanitized_actions = action_types(actions)
                host_values = condition_values(conditions, "host-header")
                http_headers = http_header_conditions(conditions)
                evidence_ref = f"elbv2-rule:{listener.region}:{item.get('RuleArn') or priority}"
                matching_origins = origins_by_alb.get(listener.load_balancer_arn, [])
                is_default = bool(item.get("IsDefault")) or priority == "default"
                rules.append(
                    AlbOriginListenerRuleRecord(
                        listener_arn=listener.listener_arn,
                        priority=priority,
                        action_types=sanitized_actions,
                        default_rule=is_default,
                        fixed_response_status=fixed_response_status(actions),
                        default_deny=is_default and is_default_deny(actions),
                        host_header_control_present=bool(host_values),
                        host_header_matches_origin=any(host_matches(origin.origin_domain_name, host_values) for origin in matching_origins),
                        http_header_control_names=tuple(sorted(name.casefold() for name in http_headers)),
                        evidence_ref=evidence_ref,
                    ),
                )
                for origin in matching_origins:
                    comparison = verifier.compare(transient_headers.get((origin.distribution_id, origin.origin_id), {}), http_headers)
                    for header_name, match_state in comparison:
                        verifications.append(
                            OriginHeaderVerificationRecord(
                                distribution_id=origin.distribution_id,
                                origin_id=origin.origin_id,
                                listener_arn=listener.listener_arn,
                                rule_priority=priority,
                                header_name=header_name,
                                control_present=True,
                                match_state=match_state,
                                forward_action="forward" in sanitized_actions,
                                evidence_ref=evidence_ref,
                            ),
                        )
        return rules, verifications
