from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.scanners.scanner.implementation import ScannerImplementation
from unio_collector.scanners.service.coverage.collector import ServiceCoverageCollector
from unio_collector.scanners.service.coverage.evidence import ServiceCoverageEvidence
from unio_collector.scanners.service.coverage.record import ServiceCoverageRecord

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class StepFunctionsCostGovernanceReviewCollector(ServiceCoverageCollector):
    """Collect service evidence independently of private finding interpretation."""

    collector_name = "StepFunctionsCostGovernanceCollector"

    def collect(self, context: ScannerContext) -> ServiceCoverageEvidence:  # noqa: D102
        records: list[ServiceCoverageRecord] = []
        warnings: list[str] = []
        detail_warnings: list[str] = []
        regions = self.get_regions(context)
        for region in regions:
            client = self.create_client(context, "stepfunctions", region)
            try:
                state_machines = self.collect_items(
                    client,
                    "list_state_machines",
                    "stateMachines",
                )
                records.extend(self._build_state_machine_record(client, region, state_machine, detail_warnings) for state_machine in state_machines)
                activities = self.collect_items(
                    client,
                    "list_activities",
                    "activities",
                )
                records.extend(self._build_activity_records(region, activities))
            except Exception as exc:  # noqa: BLE001
                self.add_warning(context, warnings, "Step Functions", region, exc)
        for warning in detail_warnings:
            context.warnings.add(warning)
        return ServiceCoverageEvidence(
            records=records,
            regions=regions,
            warnings=[*warnings, *detail_warnings],
            account_id=context.security.account_id,
            metadata={
                "state_machine_count": sum(1 for record in records if record.resource_type == "State machine"),
                "activity_count": sum(1 for record in records if record.resource_type == "Activity"),
            },
        )

    def _build_state_machine_record(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        state_machine: dict[str, Any],
        warnings: list[str] | None = None,
    ) -> ServiceCoverageRecord:
        arn = str(state_machine.get("stateMachineArn") or "")
        status = "complete"
        try:
            tags = self._get_tags(client, arn)
        except Exception as exc:  # noqa: BLE001
            tags = {}
            status = "unavailable"
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            if warnings is not None:
                warnings.append(f"Step Functions state machine tags were unavailable in {region} ({code}).")
        return ServiceCoverageRecord(
            service="AWS Step Functions",
            region=region,
            resource_type="State machine",
            resource_id=arn,
            resource_name=str(state_machine.get("name") or ""),
            arn=arn,
            tags=tags,
            attributes={
                "state_machine_type": state_machine.get("type"),
                "creation_date": str(state_machine.get("creationDate") or ""),
                "tags_collection_status": status,
            },
        )

    def _build_activity_records(
        self,
        region: str,
        activities: list[dict[str, Any]],
    ) -> list[ServiceCoverageRecord]:
        return [
            ServiceCoverageRecord(
                service="AWS Step Functions",
                region=region,
                resource_type="Activity",
                resource_id=str(activity.get("activityArn") or ""),
                resource_name=str(activity.get("name") or ""),
                arn=str(activity.get("activityArn") or ""),
                attributes={
                    "creation_date": str(activity.get("creationDate") or ""),
                },
            )
            for activity in activities
        ]

    def _get_tags(self, client: Any, arn: str) -> dict[str, str]:  # noqa: ANN401
        if not arn:
            msg = "Step Functions state machine ARN is missing."
            raise ValueError(msg)
        response = client.list_tags_for_resource(resourceArn=arn)
        tags = response.get("tags")
        if not isinstance(tags, list) or any(not isinstance(tag, dict) or not tag.get("key") for tag in tags):
            msg = "Step Functions tags is missing or malformed."
            raise ValueError(msg)
        return {str(tag.get("key")): str(tag.get("value") or "") for tag in tags}

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="StepFunctionsCostGovernanceReviewScanner",
            implementation_module="unio_collector.scanners.step_functions.cost_governance",
        )
