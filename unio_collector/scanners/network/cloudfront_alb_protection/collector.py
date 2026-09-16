from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.network.cloudfront_alb_protection.collection_helpers import (
    action_types,
    chunks,
    collect_items,
    fixed_response_status,
    host_forwarding_states,
    is_default_deny,
    origin_source_restriction,
    selected_or_available_regions,
    to_int,
)
from unio_collector.scanners.network.cloudfront_alb_protection.coverage_record import (
    OriginProtectionCoverageRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.evidence import (
    AlbOriginListenerRecord,
    AlbOriginLoadBalancerRecord,
    AlbOriginSecurityGroupRuleRecord,
    AlbOriginWafAssociationRecord,
    CloudFrontAlbOriginProtectionEvidence,
    CloudFrontAlbOriginRecord,
)
from unio_collector.scanners.network.cloudfront_alb_protection.residual_collector import (
    ResidualOriginEvidenceCollector,
)
from unio_collector.scanners.network.cloudfront_alb_protection.security_group.rule_extractor import (
    SecurityGroupIngressRuleExtractor,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class CloudFrontAlbOriginProtectionReviewCollector(BaseUnioScanner):
    """Collect network evidence without running finding interpretation."""

    def collect(
        self,
        context: ScannerContext,
    ) -> CloudFrontAlbOriginProtectionEvidence:
        """Collect read-only evidence for CloudFront ALB origin reviews."""
        regions = tuple(selected_or_available_regions(context, "elbv2"))
        limitations: list[str] = []
        coverage: list[OriginProtectionCoverageRecord] = []
        cloudfront_origins, transient_headers = self._collect_cloudfront_origins(
            context,
            limitations,
            coverage,
        )
        residual_collector = ResidualOriginEvidenceCollector()
        vpc_origins = residual_collector.collect_vpc_origins(
            context,
            cloudfront_origins,
            limitations,
            coverage,
        )
        load_balancers = self._collect_load_balancers(context, regions, limitations)
        listeners = self._collect_listeners(context, load_balancers, limitations)
        try:
            listener_rules, header_verifications = residual_collector.collect_listener_rules(
                context,
                cloudfront_origins,
                vpc_origins,
                load_balancers,
                listeners,
                transient_headers,
                limitations,
                coverage,
            )
        finally:
            transient_headers.clear()
        collected_sg_ids, sg_rules = self._collect_security_group_rules(
            context,
            load_balancers,
            limitations,
            coverage,
        )
        waf_associations = self._collect_waf_associations(
            context,
            cloudfront_origins,
            load_balancers,
        )
        for limitation in limitations:
            context.warnings.add(limitation)
        return CloudFrontAlbOriginProtectionEvidence(
            account_id=context.security.account_id,
            regions=list(regions),
            collection_time=datetime.now(UTC).isoformat(),
            cloudfront_origins=tuple(cloudfront_origins),
            load_balancers=tuple(load_balancers),
            listeners=tuple(listeners),
            listener_rules=tuple(listener_rules),
            vpc_origins=tuple(vpc_origins),
            header_verifications=tuple(header_verifications),
            coverage=tuple(coverage),
            security_group_ids_collected=tuple(sorted(collected_sg_ids)),
            security_group_rules=tuple(sg_rules),
            waf_associations=tuple(waf_associations),
            limitations=tuple(dict.fromkeys(limitations)),
        )

    def _collect_cloudfront_origins(
        self,
        context: ScannerContext,
        limitations: list[str],
        coverage: list[OriginProtectionCoverageRecord],
    ) -> tuple[list[CloudFrontAlbOriginRecord], dict[tuple[str, str], dict[str, str]]]:
        client = context.security.create_client(
            "cloudfront",
            region_name="us-east-1",
            collector_name="CloudFrontAlbOriginProtectionReviewScanner",
        )
        try:
            distributions = collect_items(
                client,
                "list_distributions",
                list_key="DistributionList",
                item_key="Items",
            )
        except Exception as exc:  # noqa: BLE001
            limitations.append(f"CloudFront distribution evidence unavailable: {exc}")
            coverage.append(OriginProtectionCoverageRecord("global", "cloudfront_origins", "unavailable", limitation=str(exc)))
            return [], {}
        records: list[CloudFrontAlbOriginRecord] = []
        transient_headers: dict[tuple[str, str], dict[str, str]] = {}
        for distribution in distributions:
            host_states = host_forwarding_states(
                client,
                distribution,
                limitations,
                coverage,
            )
            origins = distribution.get("Origins", {})
            items = origins.get("Items", []) if isinstance(origins, dict) else []
            if not isinstance(items, list):
                continue
            for origin in items:
                if not isinstance(origin, dict):
                    continue
                domain_name = str(origin.get("DomainName") or "").lower()
                if not domain_name:
                    continue
                custom_headers = origin.get("CustomHeaders", {})
                header_items = custom_headers.get("Items", []) if isinstance(custom_headers, dict) else []
                header_names = tuple(
                    sorted(str(item.get("HeaderName")) for item in header_items if isinstance(item, dict) and item.get("HeaderName")),
                )
                distribution_id = str(distribution.get("Id") or "")
                origin_id = str(origin.get("Id") or domain_name)
                transient_headers[(distribution_id, origin_id)] = {
                    str(item.get("HeaderName")): str(item.get("HeaderValue"))
                    for item in header_items
                    if isinstance(item, dict) and item.get("HeaderName") and item.get("HeaderValue") is not None
                }
                custom_config = origin.get("CustomOriginConfig")
                custom_config = custom_config if isinstance(custom_config, dict) else {}
                vpc_config = origin.get("VpcOriginConfig")
                vpc_config = vpc_config if isinstance(vpc_config, dict) else {}
                records.append(
                    CloudFrontAlbOriginRecord(
                        distribution_id=distribution_id,
                        distribution_arn=str(distribution.get("ARN") or ""),
                        distribution_domain_name=str(
                            distribution.get("DomainName") or "",
                        ),
                        origin_id=origin_id,
                        origin_domain_name=domain_name,
                        enabled=bool(distribution.get("Enabled")),
                        web_acl_id=str(distribution.get("WebACLId") or ""),
                        origin_custom_header_names=header_names,
                        source_restriction=origin_source_restriction(origin),
                        evidence_ref=(f"cloudfront:{distribution.get('Id') or 'unknown'}:{origin.get('Id') or domain_name}"),
                        origin_kind="vpc" if vpc_config.get("VpcOriginId") else "custom",
                        vpc_origin_id=str(vpc_config.get("VpcOriginId") or ""),
                        http_port=to_int(custom_config.get("HTTPPort")),
                        https_port=to_int(custom_config.get("HTTPSPort")),
                        origin_protocol_policy=str(custom_config.get("OriginProtocolPolicy") or ""),
                        host_forwarding_state=host_states.get(origin_id, "origin_domain"),
                    ),
                )
        coverage.append(OriginProtectionCoverageRecord("global", "cloudfront_origins", "collected", evidence_ref="cloudfront:list-distributions"))
        return records, transient_headers

    def _collect_load_balancers(
        self,
        context: ScannerContext,
        regions: tuple[str, ...],
        limitations: list[str],
    ) -> list[AlbOriginLoadBalancerRecord]:
        records: list[AlbOriginLoadBalancerRecord] = []
        for region in regions:
            client = context.security.create_client(
                "elbv2",
                region_name=region,
                collector_name="CloudFrontAlbOriginProtectionReviewScanner",
            )
            try:
                load_balancers = collect_items(
                    client,
                    "describe_load_balancers",
                    list_key="LoadBalancers",
                    item_key="LoadBalancers",
                )
            except Exception as exc:  # noqa: BLE001
                limitations.append(f"ALB identity evidence unavailable in {region}: {exc}")
                continue
            for item in load_balancers:
                if str(item.get("Type") or "") != "application":
                    continue
                arn = str(item.get("LoadBalancerArn") or "")
                name = str(item.get("LoadBalancerName") or "")
                records.append(
                    AlbOriginLoadBalancerRecord(
                        arn=arn,
                        name=name,
                        dns_name=str(item.get("DNSName") or "").lower(),
                        region=region,
                        scheme=str(item.get("Scheme") or ""),
                        load_balancer_type=str(item.get("Type") or ""),
                        security_group_ids=tuple(str(group_id) for group_id in item.get("SecurityGroups", []) if group_id),
                        evidence_ref=f"elbv2:{region}:{arn or name}",
                    ),
                )
        return records

    def _collect_listeners(
        self,
        context: ScannerContext,
        load_balancers: list[AlbOriginLoadBalancerRecord],
        limitations: list[str],
    ) -> list[AlbOriginListenerRecord]:
        records: list[AlbOriginListenerRecord] = []
        for load_balancer in load_balancers:
            client = context.security.create_client(
                "elbv2",
                region_name=load_balancer.region,
                collector_name="CloudFrontAlbOriginProtectionReviewScanner",
            )
            try:
                response = client.describe_listeners(
                    LoadBalancerArn=load_balancer.arn,
                )
            except Exception as exc:  # noqa: BLE001
                limitations.append(
                    f"ALB listener evidence unavailable for {load_balancer.arn}: {exc}",
                )
                continue
            listeners = response.get("Listeners", [])
            if not isinstance(listeners, list):
                continue
            for listener in listeners:
                if not isinstance(listener, dict):
                    continue
                port = to_int(listener.get("Port"))
                if port is None:
                    continue
                records.append(
                    AlbOriginListenerRecord(
                        load_balancer_arn=load_balancer.arn,
                        region=load_balancer.region,
                        port=port,
                        protocol=str(listener.get("Protocol") or ""),
                        evidence_ref=(f"elbv2-listener:{load_balancer.region}:{listener.get('ListenerArn') or port}"),
                        listener_arn=str(listener.get("ListenerArn") or ""),
                        default_action_types=action_types(listener.get("DefaultActions")),
                        default_fixed_response_status=fixed_response_status(listener.get("DefaultActions")),
                        default_deny=is_default_deny(listener.get("DefaultActions")),
                    ),
                )
        return records

    def _collect_security_group_rules(
        self,
        context: ScannerContext,
        load_balancers: list[AlbOriginLoadBalancerRecord],
        limitations: list[str],
        coverage: list[OriginProtectionCoverageRecord],
    ) -> tuple[set[str], list[AlbOriginSecurityGroupRuleRecord]]:
        by_region: dict[str, set[str]] = {}
        for load_balancer in load_balancers:
            by_region.setdefault(load_balancer.region, set()).update(
                load_balancer.security_group_ids,
            )
        collected_ids: set[str] = set()
        records: list[AlbOriginSecurityGroupRuleRecord] = []
        for region, group_ids in sorted(by_region.items()):
            if not group_ids:
                continue
            client = context.security.create_client(
                "ec2",
                region_name=region,
                collector_name="CloudFrontAlbOriginProtectionReviewScanner",
            )
            verified_prefix_lists = self._collect_cloudfront_prefix_lists(
                client,
                region,
                limitations,
                coverage,
            )
            for batch in chunks(sorted(group_ids), size=50):
                try:
                    response = client.describe_security_groups(GroupIds=batch)
                except Exception as exc:  # noqa: BLE001
                    limitations.append(
                        f"Security-group ingress evidence unavailable in {region}: {exc}",
                    )
                    continue
                groups = response.get("SecurityGroups", [])
                if not isinstance(groups, list):
                    continue
                for group in groups:
                    if not isinstance(group, dict):
                        continue
                    group_id = str(group.get("GroupId") or "")
                    if not group_id:
                        continue
                    collected_ids.add(group_id)
                    records.extend(
                        SecurityGroupIngressRuleExtractor().build(
                            region,
                            group_id,
                            group,
                            verified_prefix_lists,
                        ),
                    )
        return collected_ids, records

    def _collect_cloudfront_prefix_lists(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        limitations: list[str],
        coverage: list[OriginProtectionCoverageRecord],
    ) -> set[str]:
        evidence_ref = f"ec2-managed-prefix-lists:{region}"
        try:
            response = client.describe_managed_prefix_lists(
                Filters=[
                    {"Name": "owner-id", "Values": ["AWS"]},
                    {"Name": "prefix-list-name", "Values": ["com.amazonaws.global.cloudfront.origin-facing"]},
                ],
            )
        except Exception as exc:  # noqa: BLE001
            msg = f"CloudFront managed prefix-list evidence unavailable in {region}: {exc}"
            limitations.append(msg)
            coverage.append(OriginProtectionCoverageRecord(region, "managed_prefix_lists", "unavailable", evidence_ref, msg))
            return set()
        items = response.get("PrefixLists", [])
        verified = (
            {
                str(item.get("PrefixListId"))
                for item in items
                if isinstance(item, dict)
                and item.get("OwnerId") == "AWS"
                and item.get("PrefixListName") == "com.amazonaws.global.cloudfront.origin-facing"
                and item.get("PrefixListId")
            }
            if isinstance(items, list)
            else set()
        )
        coverage.append(OriginProtectionCoverageRecord(region, "managed_prefix_lists", "collected", evidence_ref))
        return verified

    def _collect_waf_associations(
        self,
        context: ScannerContext,
        origins: list[CloudFrontAlbOriginRecord],
        load_balancers: list[AlbOriginLoadBalancerRecord],
    ) -> list[AlbOriginWafAssociationRecord]:
        records = [
            AlbOriginWafAssociationRecord(
                resource_id=origin.distribution_arn or origin.distribution_id,
                resource_type="CloudFront distribution",
                region="global",
                associated=bool(origin.web_acl_id),
                web_acl_id=origin.web_acl_id,
                evidence_ref=origin.evidence_ref,
            )
            for origin in origins
        ]
        by_region: dict[str, list[AlbOriginLoadBalancerRecord]] = {}
        for load_balancer in load_balancers:
            by_region.setdefault(load_balancer.region, []).append(load_balancer)
        for region, regional_load_balancers in sorted(by_region.items()):
            client = context.security.create_client(
                "wafv2",
                region_name=region,
                collector_name="CloudFrontAlbOriginProtectionReviewScanner",
            )
            records.extend(self._collect_alb_waf_association(client, load_balancer) for load_balancer in regional_load_balancers)
        return records

    def _collect_alb_waf_association(
        self,
        client: Any,  # noqa: ANN401
        load_balancer: AlbOriginLoadBalancerRecord,
    ) -> AlbOriginWafAssociationRecord:
        try:
            response = client.get_web_acl_for_resource(
                ResourceArn=load_balancer.arn,
            )
        except Exception as exc:  # noqa: BLE001
            text = str(exc)
            if "WAFNonexistentItemException" in text or "NotFound" in text:
                return AlbOriginWafAssociationRecord(
                    resource_id=load_balancer.arn,
                    resource_type="Application Load Balancer",
                    region=load_balancer.region,
                    associated=False,
                    evidence_ref=f"wafv2:{load_balancer.region}:{load_balancer.arn}",
                )
            return AlbOriginWafAssociationRecord(
                resource_id=load_balancer.arn,
                resource_type="Application Load Balancer",
                region=load_balancer.region,
                associated=False,
                evidence_ref=f"wafv2:{load_balancer.region}:{load_balancer.arn}",
                limitation=f"ALB WAF association evidence unavailable: {exc}",
            )
        web_acl = response.get("WebACL")
        associated = isinstance(web_acl, dict) and bool(web_acl)
        return AlbOriginWafAssociationRecord(
            resource_id=load_balancer.arn,
            resource_type="Application Load Balancer",
            region=load_balancer.region,
            associated=associated,
            web_acl_id=str(web_acl.get("ARN") or web_acl.get("Id") or "") if isinstance(web_acl, dict) else "",
            evidence_ref=f"wafv2:{load_balancer.region}:{load_balancer.arn}",
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="CloudFrontAlbOriginProtectionReviewScanner",
            implementation_module="unio_collector.scanners.network.cloudfront_alb_protection.scanner",
        )
