from __future__ import annotations  # noqa: D100

from collections.abc import Callable
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.taggable_resource_record import TaggableResourceRecord
from unio_collector.evidence.permission.planning import DegradationContext

if TYPE_CHECKING:
    from unio_collector.scanners.base import ScannerContext

type ApiDegradationRecorder = Callable[
    [str, DegradationContext, Exception],
    None,
]


def collect_load_balancer_taggable_records(  # noqa: D103
    context: ScannerContext,
    existing_records: list[TaggableResourceRecord],
    regions: list[str],
) -> list[TaggableResourceRecord]:
    records: list[TaggableResourceRecord] = []
    instance_records = {record.resource_id: record for record in existing_records if record.resource_type == "EC2 instance"}
    session = context.security.session
    if session is None:
        return records
    audit_context = context.security.create_audit_context(
        "TagAssociationLoadBalancerCollector",
    )

    def record_degradation(
        api_action: str,
        degradation_context: DegradationContext,
        error: Exception,
    ) -> None:
        code = aws_errors.get_aws_error_code(error) or error.__class__.__name__
        context.warnings.add_coverage_note(
            {
                "note_type": "api_degradation",
                "scanner_id": context.definition.scanner_id,
                "region": current_region,
                "api_action": api_action,
                **degradation_context.convert_to_dict(),
                "outcome": "partial",
                "error_classification": "partial_collection",
                "occurrence_count": 1,
            },
        )
        context.warnings.add(
            f"{degradation_context.resource_type or 'Resource'} association evidence was partial in {current_region} ({code}).",
        )

    for region in regions:
        current_region = region
        try:
            client = session.create_client(
                "elbv2",
                region_name=region,
                audit_context=audit_context,
            )
            records.extend(
                build_load_balancer_taggable_records(
                    client,
                    region=region,
                    account_id=context.security.account_id,
                    instance_records=instance_records,
                    record_degradation=record_degradation,
                ),
            )
        except Exception as exc:  # noqa: BLE001
            context.warnings.add(
                (f"Load balancer tag association evidence could not be collected in {region}: {exc}"),
            )
    return records


def build_load_balancer_taggable_records(  # noqa: D103
    client: Any,  # noqa: ANN401
    *,
    region: str,
    account_id: str,
    instance_records: dict[str, TaggableResourceRecord],
    record_degradation: ApiDegradationRecorder | None = None,
) -> list[TaggableResourceRecord]:
    records: list[TaggableResourceRecord] = []
    for load_balancer in collect_elbv2_load_balancers(client):
        arn = str(load_balancer.get("LoadBalancerArn") or "")
        if not arn:
            continue
        name = str(load_balancer.get("LoadBalancerName") or "")
        tags = collect_elbv2_tags(
            client,
            arn,
            resource_type="Load balancer",
            record_degradation=record_degradation,
        )
        records.append(
            TaggableResourceRecord(
                resource_id=arn,
                resource_type="Load balancer",
                service="Elastic Load Balancing",
                account_id=account_id,
                region=region,
                resource_name=name or None,
                arn=arn,
                tags=tags,
            ),
        )
        target_group_records = build_load_balancer_target_group_records(
            client,
            load_balancer_arn=arn,
            load_balancer_tags=tags,
            region=region,
            account_id=account_id,
            instance_records=instance_records,
            record_degradation=record_degradation,
        )
        records.extend(target_group_records)
        for target_record in target_group_records:
            if target_record.resource_type != "EC2 instance":
                continue
            records.append(
                replace(
                    target_record,
                    associated_resource_id=arn,
                    associated_resource_type="Load balancer",
                    associated_resource_tags=tags,
                    association_reason=("EC2 instance is registered as a target behind this load balancer."),
                ),
            )
    return records


def build_load_balancer_target_group_records(  # noqa: D103
    client: Any,  # noqa: ANN401
    *,
    load_balancer_arn: str,
    load_balancer_tags: dict[str, str],
    region: str,
    account_id: str,
    instance_records: dict[str, TaggableResourceRecord],
    record_degradation: ApiDegradationRecorder | None = None,
) -> list[TaggableResourceRecord]:
    records: list[TaggableResourceRecord] = []
    for target_group in collect_elbv2_target_groups(
        client,
        load_balancer_arn,
        record_degradation=record_degradation,
    ):
        target_group_arn = str(target_group.get("TargetGroupArn") or "")
        if not target_group_arn:
            continue
        target_group_name = str(target_group.get("TargetGroupName") or "")
        target_group_tags = collect_elbv2_tags(
            client,
            target_group_arn,
            resource_type="Target group",
            record_degradation=record_degradation,
        )
        records.append(
            TaggableResourceRecord(
                resource_id=target_group_arn,
                resource_type="Target group",
                service="Elastic Load Balancing",
                account_id=account_id,
                region=region,
                resource_name=target_group_name or None,
                arn=target_group_arn,
                tags=target_group_tags,
                associated_resource_id=load_balancer_arn,
                associated_resource_type="Load balancer",
                associated_resource_tags=load_balancer_tags,
                association_reason=("Target group is attached to this load balancer."),
            ),
        )
        for target_id in collect_elbv2_target_ids_for_target_group(
            client,
            target_group_arn,
            record_degradation=record_degradation,
        ):
            instance_record = instance_records.get(target_id)
            if not instance_record:
                continue
            records.append(
                replace(
                    instance_record,
                    associated_resource_id=target_group_arn,
                    associated_resource_type="Target group",
                    associated_resource_tags=target_group_tags or load_balancer_tags,
                    association_reason=("EC2 instance is registered as a target in this load balancer target group."),
                ),
            )
    return records


def collect_auto_scaling_taggable_records(  # noqa: D103
    context: ScannerContext,
    existing_records: list[TaggableResourceRecord],
    regions: list[str],
) -> list[TaggableResourceRecord]:
    records: list[TaggableResourceRecord] = []
    instance_records = {record.resource_id: record for record in existing_records if record.resource_type == "EC2 instance"}
    session = context.security.session
    if session is None:
        return records
    audit_context = context.security.create_audit_context(
        "TagAssociationAutoScalingCollector",
    )
    for region in regions:
        try:
            client = session.create_client(
                "autoscaling",
                region_name=region,
                audit_context=audit_context,
            )
            for group in collect_auto_scaling_groups(client):
                records.extend(
                    build_auto_scaling_group_taggable_records(
                        group,
                        account_id=context.security.account_id,
                        region=region,
                        instance_records=instance_records,
                    ),
                )
        except Exception as exc:  # noqa: BLE001
            context.warnings.add(
                (f"Auto Scaling tag association evidence could not be collected in {region}: {exc}"),
            )
    return records


def build_auto_scaling_group_taggable_records(  # noqa: D103
    group: dict[str, Any],
    *,
    account_id: str,
    region: str,
    instance_records: dict[str, TaggableResourceRecord],
) -> list[TaggableResourceRecord]:
    records: list[TaggableResourceRecord] = []
    group_name = str(group.get("AutoScalingGroupName") or "")
    if not group_name:
        return records
    group_arn = str(group.get("AutoScalingGroupARN") or group_name)
    tags = autoscaling_tags_to_dict(group.get("Tags", []))
    records.append(
        TaggableResourceRecord(
            resource_id=group_arn,
            resource_type="Auto Scaling group",
            service="Amazon EC2 Auto Scaling",
            account_id=account_id,
            region=region,
            resource_name=group_name,
            arn=group_arn if group_arn.startswith("arn:") else None,
            tags=tags,
        ),
    )
    for instance in group.get("Instances", []):
        instance_id = str(instance.get("InstanceId") or "")
        instance_record = instance_records.get(instance_id)
        if not instance_record:
            continue
        records.append(
            replace(
                instance_record,
                associated_resource_id=group_arn,
                associated_resource_type="Auto Scaling group",
                associated_resource_tags=tags,
                association_reason=("EC2 instance is a member of this Auto Scaling group."),
            ),
        )
    return records


def collect_elbv2_load_balancers(client: Any) -> list[dict[str, Any]]:  # noqa: ANN401, D103
    items: list[dict[str, Any]] = []
    marker: str | None = None
    while True:
        request: dict[str, Any] = {"PageSize": 400}
        if marker:
            request["Marker"] = marker
        response = client.describe_load_balancers(**request)
        items.extend(item for item in response.get("LoadBalancers", []) if isinstance(item, dict))
        marker = response.get("NextMarker")
        if not marker:
            return items


def collect_elbv2_tags(  # noqa: D103
    client: Any,  # noqa: ANN401
    arn: str,
    *,
    resource_type: str = "ELBv2 resource",
    record_degradation: ApiDegradationRecorder | None = None,
) -> dict[str, str]:
    try:
        response = client.describe_tags(ResourceArns=[arn])
    except Exception as exc:  # noqa: BLE001
        if record_degradation is not None:
            record_degradation(
                "elbv2:DescribeTags",
                DegradationContext(
                    resource_type=resource_type,
                    resource_id=arn,
                    affected_fields=("tags",),
                    evidence_categories=("tag association",),
                ),
                exc,
            )
        return {}
    descriptions = response.get("TagDescriptions", [])
    if not descriptions:
        return {}
    return {str(tag.get("Key")): str(tag.get("Value")) for tag in descriptions[0].get("Tags", []) if tag.get("Key")}


def collect_elbv2_target_ids(client: Any, load_balancer_arn: str) -> list[str]:  # noqa: ANN401, D103
    return collect_elbv2_target_ids_for_load_balancer(client, load_balancer_arn)


def collect_elbv2_target_groups(  # noqa: D103
    client: Any,  # noqa: ANN401
    load_balancer_arn: str,
    *,
    record_degradation: ApiDegradationRecorder | None = None,
) -> list[dict[str, Any]]:
    _validate_load_balancer_arn(load_balancer_arn)
    items: list[dict[str, Any]] = []
    marker: str | None = None
    try:
        while True:
            request: dict[str, Any] = {"LoadBalancerArn": load_balancer_arn}
            if marker:
                request["Marker"] = marker
            response = client.describe_target_groups(**request)
            items.extend(item for item in response.get("TargetGroups", []) if isinstance(item, dict))
            marker = response.get("NextMarker")
            if not marker:
                return items
    except Exception as exc:  # noqa: BLE001
        if record_degradation is not None:
            record_degradation(
                "elbv2:DescribeTargetGroups",
                DegradationContext(
                    resource_type="Load balancer",
                    resource_id=load_balancer_arn,
                    affected_fields=("target_groups",),
                    evidence_categories=("resource association",),
                ),
                exc,
            )
        return []


def collect_elbv2_target_ids_for_load_balancer(  # noqa: D103
    client: Any,  # noqa: ANN401
    load_balancer_arn: str,
    *,
    record_degradation: ApiDegradationRecorder | None = None,
) -> list[str]:
    target_ids: list[str] = []
    for target_group in collect_elbv2_target_groups(
        client,
        load_balancer_arn,
        record_degradation=record_degradation,
    ):
        target_group_arn = target_group.get("TargetGroupArn")
        if not target_group_arn:
            continue
        target_ids.extend(
            collect_elbv2_target_ids_for_target_group(
                client,
                str(target_group_arn),
                record_degradation=record_degradation,
            ),
        )
    return sorted(set(target_ids))


def collect_elbv2_target_ids_for_target_group(  # noqa: D103
    client: Any,  # noqa: ANN401
    target_group_arn: str,
    *,
    record_degradation: ApiDegradationRecorder | None = None,
) -> list[str]:
    target_ids: list[str] = []
    try:
        response = client.describe_target_health(TargetGroupArn=target_group_arn)
    except Exception as exc:  # noqa: BLE001
        if record_degradation is not None:
            record_degradation(
                "elbv2:DescribeTargetHealth",
                DegradationContext(
                    resource_type="Target group",
                    resource_id=target_group_arn,
                    affected_fields=("target_health",),
                    evidence_categories=("resource association",),
                ),
                exc,
            )
        return target_ids
    for description in response.get("TargetHealthDescriptions", []):
        target_id = description.get("Target", {}).get("Id")
        if target_id:
            target_ids.append(str(target_id))
    return sorted(set(target_ids))


def _validate_load_balancer_arn(load_balancer_arn: str) -> None:
    if ":loadbalancer/" in load_balancer_arn:
        return
    message = "DescribeTargetGroups LoadBalancerArn must be an ELBv2 load-balancer ARN."
    raise ValueError(message)


def collect_auto_scaling_groups(client: Any) -> list[dict[str, Any]]:  # noqa: ANN401, D103
    groups: list[dict[str, Any]] = []
    token: str | None = None
    while True:
        request: dict[str, Any] = {"MaxRecords": 100}
        if token:
            request["NextToken"] = token
        response = client.describe_auto_scaling_groups(**request)
        groups.extend(item for item in response.get("AutoScalingGroups", []) if isinstance(item, dict))
        token = response.get("NextToken")
        if not token:
            return groups


def autoscaling_tags_to_dict(tags: list[dict[str, Any]]) -> dict[str, str]:  # noqa: D103
    return {str(tag.get("Key")): str(tag.get("Value")) for tag in tags if tag.get("Key") and tag.get("Value") is not None}
