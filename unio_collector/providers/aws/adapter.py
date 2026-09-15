from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, cast

from unio_collector.providers.aws.identity import AWS_PROVIDER
from unio_collector.providers.capability import ProviderScannerCapability
from unio_collector.providers.finding import ProviderFindingMetadata
from unio_collector.providers.location import ProviderLocation
from unio_collector.providers.resource import ProviderResourceIdentity
from unio_collector.providers.scope import ProviderAccountScope
from unio_collector.scanners.pillars import DEFAULT_SCANNER_PILLAR_POLICY

if TYPE_CHECKING:
    from collections.abc import Mapping

    from unio_collector.aws.parsed_resource_arn import ParsedResourceArn
    from unio_collector.providers.finding_source import FindingSource as Finding
    from unio_collector.providers.types import ProviderPillarId
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class AwsProviderAdapter:
    """Convert existing AWS metadata into provider-neutral contracts."""

    def build_scope(  # noqa: D102
        self,
        account_id: str,
        *,
        display_label: str = "",
    ) -> ProviderAccountScope:
        return ProviderAccountScope(
            provider_id=AWS_PROVIDER.provider_id,
            scope_id=account_id,
            scope_type="account",
            display_label=display_label,
        )

    def build_scope_from_account_context(  # noqa: D102
        self,
        account_context: Mapping[str, object],
    ) -> ProviderAccountScope | None:
        account_id = self._clean_text(account_context.get("account_id"))
        if not account_id:
            return None
        return self.build_scope(
            account_id,
            display_label=self._clean_text(account_context.get("account_alias")),
        )

    def build_location(self, region: str | None) -> ProviderLocation:  # noqa: D102
        location_id = (region or "global").strip() or "global"
        location_type = "global" if location_id == "global" else "region"
        return ProviderLocation(
            provider_id=AWS_PROVIDER.provider_id,
            location_id=location_id,
            display_name=location_id,
            location_type=location_type,
        )

    def build_resource_from_arn(  # noqa: D102
        self,
        arn: ParsedResourceArn,
        *,
        resource_name: str | None = None,
        tags: tuple[tuple[str, str], ...] = (),
    ) -> ProviderResourceIdentity:
        return ProviderResourceIdentity(
            provider_id=AWS_PROVIDER.provider_id,
            scope=self.build_scope(arn.account_id),
            location=self.build_location(arn.region),
            service_name=arn.service,
            canonical_resource_type=arn.resource_type or "resource",
            native_resource_type=arn.resource_type,
            resource_id=arn.resource_id,
            resource_name=resource_name,
            tags=tags,
        )

    def build_resource_from_finding(  # noqa: D102
        self,
        finding: Finding,
    ) -> ProviderResourceIdentity:
        account_id = finding.account_id or "unknown"
        region = finding.region or "global"
        resource_type = finding.resource_type or "resource"
        resource_id = finding.resource_id or finding.arn or finding.id
        return ProviderResourceIdentity(
            provider_id=AWS_PROVIDER.provider_id,
            scope=self.build_scope(account_id),
            location=self.build_location(region),
            service_name=finding.service,
            canonical_resource_type=resource_type,
            native_resource_type=resource_type,
            resource_id=resource_id,
            resource_name=finding.resource_name,
            tags=tuple(finding.tags.items()),
        )

    def build_finding_metadata(  # noqa: D102
        self,
        finding: Finding,
        *,
        fallback_scope: ProviderAccountScope,
    ) -> ProviderFindingMetadata:
        scope = self.build_scope(finding.account_id) if finding.account_id else fallback_scope
        native_metadata: tuple[tuple[str, object], ...] = (
            ("finding_id", finding.id),
            ("finding_type", finding.finding_type),
        )
        if finding.scanner_id:
            native_metadata = (*native_metadata, ("scanner_id", finding.scanner_id))
        return ProviderFindingMetadata(
            provider_id=AWS_PROVIDER.provider_id,
            scope=scope,
            location=self.build_location(finding.region),
            service_name=finding.service,
            native_resource_type=finding.resource_type or "",
            native_resource_id=finding.resource_id or finding.arn or finding.id,
            native_metadata=native_metadata,
        )

    def build_scanner_capability(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> ProviderScannerCapability:
        return ProviderScannerCapability(
            scanner_id=definition.scanner_id,
            provider_ids=(AWS_PROVIDER.provider_id,),
            pillars=cast(
                "tuple[ProviderPillarId, ...]",
                DEFAULT_SCANNER_PILLAR_POLICY.get_pillars(definition.scanner_id),
            ),
            required_permissions=definition.required_iam_actions,
            evidence_domains=definition.aws_services,
            output_finding_types=definition.output_finding_types,
            scope_types=("account",),
            location_types=("region", "global") if definition.supports_regions else ("global",),
            api_domains=definition.aws_api_calls,
            maturity=definition.maturity,
            limitations=definition.limitations,
            offline_fixture_supported=True,
            live_runtime_required=True,
        )

    def _clean_text(self, value: object) -> str:
        return str(value).strip() if value is not None else ""
