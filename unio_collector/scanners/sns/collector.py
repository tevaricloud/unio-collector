from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.scanners.scanner.implementation import ScannerImplementation
from unio_collector.scanners.service.coverage.collector import ServiceCoverageCollector
from unio_collector.scanners.service.coverage.evidence import ServiceCoverageEvidence
from unio_collector.scanners.service.coverage.record import ServiceCoverageRecord

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class SnsCostGovernanceReviewCollector(ServiceCoverageCollector):
    """Collect service evidence independently of private finding interpretation."""

    collector_name = "SnsCostGovernanceCollector"

    def collect(self, context: ScannerContext) -> ServiceCoverageEvidence:  # noqa: D102
        records: list[ServiceCoverageRecord] = []
        warnings: list[str] = []
        detail_warnings: list[str] = []
        regions = self.get_regions(context)
        for region in regions:
            client = self.create_client(context, "sns", region)
            try:
                topics = self.collect_items(client, "list_topics", "Topics")
                records.extend(self._build_topic_record(client, region, topic, detail_warnings) for topic in topics)
            except Exception as exc:  # noqa: BLE001
                self.add_warning(context, warnings, "SNS", region, exc)
        for warning in detail_warnings:
            context.warnings.add(warning)
        return ServiceCoverageEvidence(
            records=records,
            regions=regions,
            warnings=[*warnings, *detail_warnings],
            account_id=context.security.account_id,
            metadata={"topic_count": len(records)},
        )

    def _build_topic_record(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        topic: dict[str, Any],
        warnings: list[str] | None = None,
    ) -> ServiceCoverageRecord:
        arn = str(topic.get("TopicArn") or "")
        warnings = warnings if warnings is not None else []
        statuses: dict[str, str] = {}
        try:
            attributes = self._get_topic_attributes(client, arn)
        except Exception as exc:  # noqa: BLE001
            attributes = {}
            statuses["attributes_collection_status"] = "unavailable"
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            warnings.append(f"SNS topic attributes were unavailable in {region} ({code}).")
        subscription_count = attributes.get("SubscriptionsConfirmed")
        if not str(subscription_count).isascii() or not str(subscription_count).isdecimal():
            statuses["subscription_count_status"] = "unavailable"
            warnings.append(f"SNS confirmed subscription count was missing or malformed in {region}.")
        try:
            tags = self._get_topic_tags(client, arn)
        except Exception as exc:  # noqa: BLE001
            tags = {}
            statuses["tags_collection_status"] = "unavailable"
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            warnings.append(f"SNS topic tags were unavailable in {region} ({code}).")
        return ServiceCoverageRecord(
            service="Amazon Simple Notification Service",
            region=region,
            resource_type="SNS topic",
            resource_id=arn,
            resource_name=arn.rsplit(":", 1)[-1] if arn else "",
            arn=arn,
            tags=tags,
            attributes={
                "subscription_count": subscription_count,
                "kms_master_key_id": attributes.get("KmsMasterKeyId"),
                "fifo_topic": attributes.get("FifoTopic"),
                **statuses,
            },
        )

    def _get_topic_attributes(self, client: Any, arn: str) -> dict[str, Any]:  # noqa: ANN401
        if not arn:
            msg = "SNS topic ARN is missing."
            raise ValueError(msg)
        response = client.get_topic_attributes(TopicArn=arn)
        attrs = response.get("Attributes")
        if not isinstance(attrs, dict):
            msg = "SNS Attributes is missing or malformed."
            raise ValueError(msg)
        return attrs

    def _get_topic_tags(self, client: Any, arn: str) -> dict[str, str]:  # noqa: ANN401
        if not arn:
            msg = "SNS topic ARN is missing."
            raise ValueError(msg)
        response = client.list_tags_for_resource(ResourceArn=arn)
        tags = response.get("Tags")
        if not isinstance(tags, list) or any(not isinstance(tag, dict) or not tag.get("Key") for tag in tags):
            msg = "SNS Tags is missing or malformed."
            raise ValueError(msg)
        return {str(tag.get("Key")): str(tag.get("Value") or "") for tag in tags}

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="SnsCostGovernanceReviewScanner",
            implementation_module="unio_collector.scanners.sns.cost_governance",
        )
