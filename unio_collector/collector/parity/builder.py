from __future__ import annotations  # noqa: D100

import inspect
from dataclasses import fields
from importlib import import_module
from typing import TYPE_CHECKING, Any, cast

from unio_collector.collector.bundle.schema import (
    BUNDLE_SCHEMA_VERSION,
    PROTECTED_BUNDLE_SCHEMA_VERSION,
)
from unio_collector.collector.config.runtime import CollectorRuntimeConfig
from unio_collector.collector.organization.constants import (
    ORGANIZATION_ENVELOPE_SCHEMA_VERSION,
)
from unio_collector.collector.parity.model import AwsCollectionCapabilityModel, AwsCollectionRuntimePath
from unio_collector.collector.parity.operation import AwsOperationCapability
from unio_collector.collector.parity.scanner import AwsScannerCapability
from unio_collector.evidence.permission.planning.builder import (
    PERMISSION_PLAN_SCHEMA_VERSION,
)
from unio_collector.scanners.scanner.evidence_serializer import (
    SCANNER_EVIDENCE_PAYLOAD_SCHEMA_VERSION,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from unio_collector.scanners.scanner.definition import ScannerDefinition


class AwsCollectionCapabilityModelBuilder:
    """Derive AWS collection parity metadata from authoritative runtime owners."""

    def build(
        self,
        runtime_path: AwsCollectionRuntimePath = "collector",
    ) -> AwsCollectionCapabilityModel:
        """Build a core or collector projection without live AWS access."""
        if runtime_path != "collector":
            msg = "Core parity projection requires the private core model builder."
            raise ValueError(msg)
        module = import_module("unio_collector.scanners.collection.class_paths")
        paths = dict(module.COLLECTOR_SCANNER_CLASS_PATHS)
        factory_module = import_module(
            "unio_collector.scanners.collection.path_factory",
        )
        return self.build_from_owners(
            runtime_path="collector",
            implementation_paths=paths,
            scanner_factory=(factory_module.build_scanner_from_collector_factory_path),
        )

    def build_from_owners(
        self,
        *,
        runtime_path: AwsCollectionRuntimePath,
        implementation_paths: Mapping[str, str],
        scanner_factory: Callable[[str, ScannerDefinition], Any],
    ) -> AwsCollectionCapabilityModel:
        """Project metadata from explicitly supplied authoritative owners."""
        registry = import_module("unio_collector.scanners.registry.definitions")
        definitions = cast("Mapping[str, ScannerDefinition]", registry.SCANNERS)
        sources = tuple(registry.BUILT_IN_SCANNER_DEFINITION_SOURCES)
        source_ids = {scanner_id: source.source_id for source in sources for scanner_id in source.definitions}
        scanners = tuple(
            self._build_scanner(
                definition=definitions[scanner_id],
                source_id=source_ids[scanner_id],
                implementation_path=implementation_paths[scanner_id],
                runtime_path=runtime_path,
                scanner_factory=scanner_factory,
            )
            for scanner_id in sorted(definitions)
        )
        return AwsCollectionCapabilityModel(
            runtime_path=runtime_path,
            scanners=scanners,
            configuration_fields=tuple(sorted(field.name for field in fields(CollectorRuntimeConfig))),
            execution_contract=self._execution_contract(),
        )

    def _build_scanner(
        self,
        *,
        definition: ScannerDefinition,
        source_id: str,
        implementation_path: str,
        runtime_path: AwsCollectionRuntimePath,
        scanner_factory: Callable[[str, ScannerDefinition], Any],
    ) -> AwsScannerCapability:
        scanner = scanner_factory(definition.scanner_id, definition)
        implementation = scanner.describe_implementation().convert_to_dict()
        collect_method = type(scanner).collect
        return AwsScannerCapability(
            scanner_id=definition.scanner_id,
            definition_source_id=source_id,
            factory_path=(definition.collector_factory_path if runtime_path == "collector" else "unio_collector.scanners.builders:build_scanner"),
            implementation_path=implementation_path,
            implementation_identity=tuple(sorted(implementation.items())),
            collection_callable=(f"{collect_method.__module__}:{collect_method.__qualname__}"),
            evidence_return_annotation=self._return_annotation(collect_method),
            default_enabled=definition.default_enabled,
            supports_regions=definition.supports_regions,
            execution_phase=definition.execution_phase,
            dependencies=tuple(definition.depends_on_scanner_ids),
            operations=self._operations(definition),
            permissions=self._permissions(definition),
            may_incur_charges=definition.may_incur_charges,
            chargeable_reason=definition.chargeable_reason,
            output_finding_types=tuple(definition.output_finding_types),
        )

    def _operations(
        self,
        definition: ScannerDefinition,
    ) -> tuple[AwsOperationCapability, ...]:
        requirements_by_action: dict[str, list[Any]] = {}
        for requirement in definition.iam_requirements or ():
            requirements_by_action.setdefault(requirement.api_action, []).append(
                requirement,
            )
        rows = []
        for action in sorted(set(definition.aws_api_calls)):
            service, _, operation = action.partition(":")
            requirements = requirements_by_action.get(action, [])
            requirement_types = tuple(
                sorted({item.requirement_type for item in requirements}),
            )
            rows.append(
                AwsOperationCapability(
                    service=service,
                    operation=operation,
                    requirement_types=requirement_types,
                    conditional=bool(requirement_types and "required" not in requirement_types),
                    chargeable=any(item.chargeable for item in requirements),
                ),
            )
        return tuple(rows)

    def _permissions(
        self,
        definition: ScannerDefinition,
    ) -> tuple[dict[str, Any], ...]:
        requirements: Iterable[Any] = definition.iam_requirements or ()
        return tuple(
            sorted(
                (
                    {
                        "api_action": item.api_action,
                        "requirement_type": item.requirement_type,
                        "conditional_on": item.conditional_on,
                        "chargeable": item.chargeable,
                        "evidence_categories": list(item.evidence_categories),
                        "resource_scope": item.resource_scope,
                    }
                    for item in requirements
                ),
                key=lambda item: (
                    str(item["api_action"]),
                    str(item["requirement_type"]),
                ),
            ),
        )

    def _return_annotation(self, collect_method: Any) -> str:  # noqa: ANN401
        annotation = inspect.signature(collect_method).return_annotation
        if annotation is inspect.Signature.empty:
            return "unannotated"
        if isinstance(annotation, str):
            return annotation
        return getattr(annotation, "__qualname__", str(annotation))

    def _execution_contract(self) -> dict[str, Any]:
        return {
            "provider_id": "aws",
            "permission_plan_schema_version": PERMISSION_PLAN_SCHEMA_VERSION,
            "scanner_evidence_schema_version": (SCANNER_EVIDENCE_PAYLOAD_SCHEMA_VERSION),
            "scanner_evidence_serialization_format": ("json-compatible-python-object"),
            "scanner_evidence_required_members": [
                "bundle_schema_version",
                "evidence_module",
                "evidence_type",
                "limitations",
                "payload",
                "scanner_id",
                "serialization_format",
                "serialization_status",
            ],
            "bundle_schema_versions": [
                BUNDLE_SCHEMA_VERSION,
                PROTECTED_BUNDLE_SCHEMA_VERSION,
            ],
            "organization_envelope_schema_version": (ORGANIZATION_ENVELOPE_SCHEMA_VERSION),
            "scanner_failure_statuses": [
                "completed_with_warnings",
                "failed",
                "permission_denied",
                "skipped",
                "unavailable",
            ],
            "scope": {
                "account_identity": "sts:GetCallerIdentity",
                "billing_region_derivation": True,
                "global_service_scope": True,
                "organization_management_account": True,
                "organization_member_accounts": True,
                "organization_partial_failure": True,
                "regional_selection": True,
            },
            "privacy": {
                "identity_transformation_boundary": ("unio_collector.collector.transformation.identity:IdentityEvidenceTransformationPolicy"),
                "minimisation_supported": True,
                "protected_bundle_supported": True,
            },
            "organization_collection_owner": ("unio_collector.scan_workflow.organization.collection.coordinator:OrganizationCollectionCoordinator"),
            "provider_collection_owner": ("unio_collector.providers.aws.collection.executor:AwsProviderCollectionExecutor"),
        }
