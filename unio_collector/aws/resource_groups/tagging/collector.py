from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.collection import AwsCollectionExecutor, AwsCollectionTask
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.resource_groups.tagging.helpers import (
    DEFAULT_RESOURCE_TYPE_FILTERS,
    describe_supported_resource_type,
    describe_supported_service,
    parse_resource_arn,
    tags_to_dict,
)
from unio_collector.aws.resource_groups.tagging.result import (
    ResourceGroupsTaggingCollectionResult,
)
from unio_collector.aws.taggable_resource_record import TaggableResourceRecord

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext


class ResourceGroupsTaggingCollector:
    """Read-only collector for optional Resource Groups Tagging API inventory."""

    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        selected_regions: list[str],
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.selected_regions = list(selected_regions)
        self._pagination = AwsPaginationHelper()

    def collect_taggable_resources(  # noqa: D102
        self,
        *,
        resource_type_filters: tuple[str, ...] = DEFAULT_RESOURCE_TYPE_FILTERS,
    ) -> ResourceGroupsTaggingCollectionResult:
        tasks = [
            AwsCollectionTask(
                name=(f"ResourceGroupsTaggingCollector:resourcegroupstaggingapi:GetResources:{region}"),
                scanner_id=self.audit_context.scanner_id,
                collector_id="ResourceGroupsTaggingCollector",
                account_id=self.account_id,
                region=region,
                service="resourcegroupstaggingapi",
                operation="GetResources",
                collect=lambda region=region: self.collect_resources_in_region(
                    region,
                    resource_type_filters=resource_type_filters,
                ),
            )
            for region in self.selected_regions
        ]
        results = AwsCollectionExecutor(
            max_workers=self.session.runtime_config.max_workers,
        ).run(tasks)

        records: list[TaggableResourceRecord] = []
        regions_scanned: list[str] = []
        errors: list[str] = []
        permission_errors = 0
        for result in results:
            if result.status == "completed":
                regions_scanned.append(str(result.task.region or "aws-global"))
                records.extend(result.value or [])
                continue
            if result.status == "permission_denied":
                permission_errors += 1
            detail = result.error_code or result.error_message or result.status
            errors.append(
                f"{result.task.region or 'aws-global'}: {result.status}: {detail}",
            )

        return ResourceGroupsTaggingCollectionResult(
            records=records,
            regions_scanned=sorted(regions_scanned),
            status=self.get_collection_status(
                region_count=len(self.selected_regions),
                successful_region_count=len(regions_scanned),
                permission_error_count=permission_errors,
                error_count=len(errors),
            ),
            errors=errors,
            limitations=self.build_limitations(
                permission_error_count=permission_errors,
                error_count=len(errors),
            ),
        )

    def collect_resources_in_region(  # noqa: D102
        self,
        region: str,
        *,
        resource_type_filters: tuple[str, ...],
    ) -> list[TaggableResourceRecord]:
        client = self.session.create_client(
            "resourcegroupstaggingapi",
            region_name=region,
            audit_context=self.audit_context,
        )
        pages = self._pagination.collect_token_pages(
            client,
            "get_resources",
            result_key="ResourceTagMappingList",
            request_parameters={
                "ResourcesPerPage": 100,
                "ResourceTypeFilters": list(resource_type_filters),
            },
            request_cursor_key="PaginationToken",
            response_cursor_keys=("PaginationToken",),
        ).pages
        records: list[TaggableResourceRecord] = []
        for page in pages:
            for mapping in page.get("ResourceTagMappingList", []):
                record = self.convert_mapping_to_record(mapping, fallback_region=region)
                if record is not None:
                    records.append(record)
        return records

    def convert_mapping_to_record(  # noqa: D102
        self,
        mapping: dict[str, Any],
        *,
        fallback_region: str,
    ) -> TaggableResourceRecord | None:
        arn = str(mapping.get("ResourceARN") or "")
        parsed = parse_resource_arn(arn)
        if parsed is None:
            return None
        resource_type = describe_supported_resource_type(parsed)
        if resource_type is None:
            return None
        tags = tags_to_dict(mapping.get("Tags", []))
        service_name = describe_supported_service(resource_type)
        return TaggableResourceRecord(
            resource_id=parsed.resource_id,
            resource_type=resource_type,
            service=service_name,
            account_id=parsed.account_id or self.account_id,
            region=parsed.region or fallback_region,
            resource_name=tags.get("Name"),
            arn=arn,
            tags=tags,
        )

    def get_collection_status(  # noqa: D102
        self,
        *,
        region_count: int,
        successful_region_count: int,
        permission_error_count: int,
        error_count: int,
    ) -> str:
        if region_count == 0:
            return "unavailable"
        if successful_region_count == region_count:
            return "completed"
        if successful_region_count > 0:
            return "partial"
        if permission_error_count:
            return "permission_denied"
        if error_count:
            return "unavailable"
        return "completed"

    def build_limitations(  # noqa: D102
        self,
        *,
        permission_error_count: int,
        error_count: int,
    ) -> list[str]:
        limitations = [
            (
                "Resource Groups Tagging API only enriches tagged-resource "
                "discovery. Direct EC2 inventory remains the source for untagged "
                "resources and attachment evidence."
            ),
        ]
        if permission_error_count:
            limitations.append(
                "At least one region could not use tag:GetResources due to permissions.",
            )
        elif error_count:
            limitations.append(
                "At least one regional Resource Groups Tagging API lookup failed.",
            )
        return limitations
