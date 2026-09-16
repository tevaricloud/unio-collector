from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.permission import ScannerIamRequirement


@dataclass(frozen=True)
class ScannerIamMetadataDeclaration:
    """Registry-owned scanner IAM metadata declaration."""

    iam_requirements: tuple[ScannerIamRequirement, ...]

    @property
    def required_actions(self) -> tuple[str, ...]:
        """Return required actions for compatibility with legacy registry fields."""
        return tuple(item.api_action for item in self.iam_requirements if item.requirement_type == "required")

    @property
    def conditional_actions(self) -> tuple[str, ...]:
        """Return conditional actions for compatibility with legacy registry fields."""
        return tuple(item.api_action for item in self.iam_requirements if item.requirement_type == "conditional")

    @property
    def optional_enrichment_actions(self) -> tuple[str, ...]:
        """Return optional enrichment actions for compatibility with legacy registry fields."""
        return tuple(item.api_action for item in self.iam_requirements if item.requirement_type == "optional_enrichment")

    @property
    def chargeable_actions(self) -> tuple[str, ...]:
        """Return chargeable actions for compatibility with legacy registry fields."""
        return tuple(item.api_action for item in self.iam_requirements if item.chargeable)


def attach_explicit_scanner_iam_requirements(
    definitions: dict[str, ScannerDefinition],
) -> dict[str, ScannerDefinition]:
    """Attach explicit registry IAM metadata to discovered scanner definitions."""
    missing = sorted(set(definitions) - set(EXPLICIT_SCANNER_IAM_METADATA))
    if missing:
        msg = "Missing explicit IAM metadata for scanner(s): " + ", ".join(missing)
        raise ValueError(msg)
    stale = sorted(set(EXPLICIT_SCANNER_IAM_METADATA) - set(definitions))
    if stale:
        msg = "Explicit IAM metadata references unknown scanner(s): " + ", ".join(stale)
        raise ValueError(msg)
    for scanner_id, definition in definitions.items():
        _validate_declaration(definition, EXPLICIT_SCANNER_IAM_METADATA[scanner_id])
    return {
        scanner_id: replace(
            definition,
            iam_requirements=EXPLICIT_SCANNER_IAM_METADATA[scanner_id].iam_requirements,
        )
        for scanner_id, definition in definitions.items()
    }


def _build_explicit_scanner_iam_metadata() -> dict[str, ScannerIamMetadataDeclaration]:
    from unio_collector.scanners.registry.iam_requirement_sources.analytics_ai import (  # noqa: PLC0415
        ANALYTICS_AI_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.audit_cost import (  # noqa: PLC0415
        AUDIT_COST_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.aws_native_recommendations import (  # noqa: PLC0415
        AWS_NATIVE_RECOMMENDATIONS_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.cost import (  # noqa: PLC0415
        COST_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.dynamodb import (  # noqa: PLC0415
        DYNAMODB_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.ec2 import (  # noqa: PLC0415
        EC2_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.network import (  # noqa: PLC0415
        NETWORK_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.observability import (  # noqa: PLC0415
        OBSERVABILITY_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.platform import (  # noqa: PLC0415
        PLATFORM_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.security_governance import (  # noqa: PLC0415
        SECURITY_GOVERNANCE_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.serverless import (  # noqa: PLC0415
        SERVERLESS_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.service.coverage import (  # noqa: PLC0415
        SERVICE_COVERAGE_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.service.quotas import (  # noqa: PLC0415
        SERVICE_QUOTAS_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.storage import (  # noqa: PLC0415
        STORAGE_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.tagging import (  # noqa: PLC0415
        TAGGING_IAM_METADATA,
    )
    from unio_collector.scanners.registry.iam_requirement_sources.utilization import (  # noqa: PLC0415
        UTILIZATION_IAM_METADATA,
    )

    return _merge_metadata_sources(
        (
            ANALYTICS_AI_IAM_METADATA,
            AUDIT_COST_IAM_METADATA,
            AWS_NATIVE_RECOMMENDATIONS_IAM_METADATA,
            COST_IAM_METADATA,
            DYNAMODB_IAM_METADATA,
            EC2_IAM_METADATA,
            NETWORK_IAM_METADATA,
            OBSERVABILITY_IAM_METADATA,
            PLATFORM_IAM_METADATA,
            SECURITY_GOVERNANCE_IAM_METADATA,
            SERVERLESS_IAM_METADATA,
            SERVICE_COVERAGE_IAM_METADATA,
            SERVICE_QUOTAS_IAM_METADATA,
            STORAGE_IAM_METADATA,
            TAGGING_IAM_METADATA,
            UTILIZATION_IAM_METADATA,
        ),
    )


def _merge_metadata_sources(
    sources: tuple[Mapping[str, ScannerIamMetadataDeclaration], ...],
) -> dict[str, ScannerIamMetadataDeclaration]:
    merged: dict[str, ScannerIamMetadataDeclaration] = {}
    for source in sources:
        duplicate_ids = sorted(set(merged) & set(source))
        if duplicate_ids:
            msg = "Duplicate explicit IAM metadata for scanner(s): " + ", ".join(duplicate_ids)
            raise ValueError(msg)
        merged.update(source)
    return merged


def _validate_declaration_parity(
    definition: ScannerDefinition,
    declaration: ScannerIamMetadataDeclaration,
) -> None:
    declared_conditional = {
        *declaration.conditional_actions,
        *declaration.optional_enrichment_actions,
    }
    if set(declaration.required_actions) != set(definition.required_iam_actions):
        msg = f"Explicit IAM metadata for {definition.scanner_id} does not match required_iam_actions."
        raise ValueError(msg)
    if declared_conditional != set(definition.conditional_iam_actions):
        msg = f"Explicit IAM metadata for {definition.scanner_id} does not match conditional_iam_actions."
        raise ValueError(msg)
    unknown_chargeable = set(declaration.chargeable_actions) - set(declaration.required_actions) - declared_conditional
    if unknown_chargeable:
        msg = f"Explicit IAM metadata for {definition.scanner_id} marks unknown chargeable action(s): {sorted(unknown_chargeable)}"
        raise ValueError(msg)


def _validate_declaration(
    definition: ScannerDefinition,
    declaration: ScannerIamMetadataDeclaration,
) -> None:
    _validate_declaration_parity(definition, declaration)
    seen_actions: set[tuple[str, str]] = set()
    for requirement in declaration.iam_requirements:
        key = (requirement.api_action, requirement.requirement_type)
        if key in seen_actions:
            msg = f"Explicit IAM metadata for {definition.scanner_id} duplicates {requirement.api_action} as {requirement.requirement_type}."
            raise ValueError(msg)
        seen_actions.add(key)
        _validate_requirement(definition, requirement)


def _validate_requirement(
    definition: ScannerDefinition,
    requirement: ScannerIamRequirement,
) -> None:
    from unio_collector.scanners.permission_classifier import is_read_only_iam_action  # noqa: PLC0415

    if not requirement.api_action.strip():
        msg = f"Explicit IAM metadata for {definition.scanner_id} has an empty IAM action declaration."
        raise ValueError(msg)
    if not requirement.reason.strip():
        msg = f"Explicit IAM metadata for {definition.scanner_id} action {requirement.api_action} has no IAM reason."
        raise ValueError(msg)
    if requirement.requirement_type != "required" and not (requirement.conditional_on or "").strip():
        msg = f"Explicit IAM metadata for {definition.scanner_id} action {requirement.api_action} has no IAM condition."
        raise ValueError(msg)
    if not requirement.evidence_categories:
        msg = f"Explicit IAM metadata for {definition.scanner_id} action {requirement.api_action} has no evidence categories."
        raise ValueError(msg)
    if not requirement.resource_scope:
        msg = f"Explicit IAM metadata for {definition.scanner_id} action {requirement.api_action} has no resource scope."
        raise ValueError(msg)
    if not requirement.resource_scope_reason.strip():
        msg = f"Explicit IAM metadata for {definition.scanner_id} action {requirement.api_action} has no resource-scope rationale."
        raise ValueError(msg)
    if not is_read_only_iam_action(requirement.api_action):
        msg = f"Explicit IAM metadata for {definition.scanner_id} action {requirement.api_action} is not approved as read-only."
        raise ValueError(msg)
    _validate_authorization_scope(definition, requirement)


def _validate_authorization_scope(
    definition: ScannerDefinition,
    requirement: ScannerIamRequirement,
) -> None:
    from unio_collector.aws.iam import get_aws_iam_action_scope  # noqa: PLC0415

    authorization = get_aws_iam_action_scope(requirement.api_action)
    if not authorization.variants:
        msg = f"Explicit IAM metadata for {definition.scanner_id} action {requirement.api_action} has no authorization-scope variants."
        raise ValueError(msg)
    for variant in authorization.variants:
        if not variant.rationale.strip() or not variant.authorization_references:
            msg = f"Explicit IAM metadata for {definition.scanner_id} action {requirement.api_action} has incomplete authorization provenance."
            raise ValueError(msg)
        if variant.wildcard_required and variant.arn_templates != ("*",):
            msg = f"Explicit IAM metadata for {definition.scanner_id} action {requirement.api_action} has an invalid wildcard authorization variant."
            raise ValueError(msg)
        if variant.unresolved and variant.wildcard_required:
            msg = f"Explicit IAM metadata for {definition.scanner_id} action {requirement.api_action} conflates unresolved and wildcard scope."
            raise ValueError(msg)


EXPLICIT_SCANNER_IAM_METADATA = _build_explicit_scanner_iam_metadata()
