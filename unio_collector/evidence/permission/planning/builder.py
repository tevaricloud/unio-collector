from __future__ import annotations  # noqa: D100

from dataclasses import replace
from typing import TYPE_CHECKING

from unio_collector.aws.iam import (
    AWS_IAM_SCOPE_CATALOG_SCHEMA_VERSION,
    get_aws_iam_action_scope,
)
from unio_collector.evidence.permission.planning.aws_scope import AwsPolicyExecutionScope
from unio_collector.evidence.permission.planning.plan import PermissionPlan
from unio_collector.evidence.permission.planning.provenance import (
    ScannerPermissionProvenance,
)
from unio_collector.evidence.permission.planning.requirement import (
    PermissionRequirement,
)
from unio_collector.evidence.permission.planning.scope_resolver import (
    AwsAuthorizationScopeResolver,
)
from unio_collector.scanners.permission_classifier import classify_iam_actions, is_read_only_iam_action
from unio_collector.scanners.registry.definitions import SCANNERS
from unio_collector.scanners.registry.scope_bindings import (
    build_scanner_iam_scope_bindings,
)

if TYPE_CHECKING:
    from unio_collector.evidence.permission.planning.requirement_type import RequirementType
    from unio_collector.scanners.scanner.definition import ScannerDefinition
    from unio_collector.scanners.scanner.permission import ScannerIamRequirement
    from unio_collector.scanners.scanner.selection import ScannerSelection

PERMISSION_PLAN_SCHEMA_VERSION = "2026-07"
REQUIREMENT_TYPE_PRECEDENCE = {
    "required": 0,
    "conditional": 1,
    "optional_enrichment": 2,
    "optional": 3,
    "unknown": 4,
}
SCANNER_IAM_SCOPE_BINDINGS = build_scanner_iam_scope_bindings(SCANNERS)
AWS_AUTHORIZATION_SCOPE_RESOLVER = AwsAuthorizationScopeResolver()


class PermissionPlanBuilder:
    """Build collector-safe permission plans from scanner metadata."""

    def build(
        self,
        *,
        provider_id: str,
        selection: ScannerSelection,
        include_platform_billing_baseline: bool = False,
        include_organization_role_assumption: bool = False,
        aws_scope: AwsPolicyExecutionScope | None = None,
    ) -> PermissionPlan:
        """Return permission requirements for the selected scanner scope."""
        resolved_scope = aws_scope or AwsPolicyExecutionScope()
        enabled_requirements = self._build_requirements(
            provider_id=provider_id,
            scanner_ids=selection.enabled_ids,
            excluded=False,
            aws_scope=resolved_scope,
        )
        if provider_id == "aws" and include_platform_billing_baseline and not any(item.api_action == "ce:GetCostAndUsage" for item in enabled_requirements):
            enabled_requirements = (
                *enabled_requirements,
                self._build_platform_billing_baseline_requirement(),
            )
        blocked_ids = tuple(block.scanner_id for block in selection.chargeable_blocks)
        excluded_requirements = self._build_requirements(
            provider_id=provider_id,
            scanner_ids=blocked_ids,
            excluded=True,
            aws_scope=resolved_scope,
        )
        included_actions = tuple(sorted({item.api_action for item in enabled_requirements}))
        classification = classify_iam_actions(included_actions)
        wildcard_justifications = tuple(
            {
                "action": item.api_action,
                "justification": item.wildcard_justification,
                "resource_scope": item.resource_scope,
            }
            for item in enabled_requirements
            if item.resource_scope == "wildcard_required"
        )
        unresolved_actions = tuple(
            sorted(item.api_action for item in enabled_requirements if item.scope_status == "unresolved"),
        )
        contains_wildcard = any(item.scope_status == "wildcard_required" for item in enabled_requirements)
        policy_status = "unresolved_policy_plan" if unresolved_actions else "valid_wildcard_policy" if contains_wildcard else "exact_scoped_policy"
        return PermissionPlan(
            schema_version=PERMISSION_PLAN_SCHEMA_VERSION,
            provider_id=provider_id,
            selected_scanner_ids=selection.enabled_ids,
            requirements=enabled_requirements,
            excluded_chargeable_requirements=excluded_requirements,
            read_only_actions=tuple(classification["read_only"]),
            rejected_actions=tuple(classification["rejected"]),
            wildcard_justifications=wildcard_justifications,
            warnings=self._build_warnings(selection),
            limitations=self._build_limitations(),
            aws_scope={
                "account_id": resolved_scope.account_id,
                "partition": resolved_scope.partition,
                "regions": list(resolved_scope.regions),
                "account_source": resolved_scope.account_source,
                "partition_source": resolved_scope.partition_source,
                "region_source": resolved_scope.region_source,
                "authenticated": resolved_scope.authenticated,
            },
            policy_status=policy_status,
            deployable=not unresolved_actions,
            unresolved_actions=unresolved_actions,
            authorization_catalogue_version=(AWS_IAM_SCOPE_CATALOG_SCHEMA_VERSION),
            credential_delegation_actions=(("sts:AssumeRole",) if include_organization_role_assumption else ()),
        )

    def _build_platform_billing_baseline_requirement(
        self,
    ) -> PermissionRequirement:
        action = "ce:GetCostAndUsage"
        return PermissionRequirement(
            requirement_id="aws:ce:GetCostAndUsage:required:platform-billing-baseline",
            provider_id="aws",
            service="ce",
            api_action=action,
            requirement_type="required",
            chargeable=False,
            resource_scope="wildcard_required",
            scanner_ids=(),
            scanner_provenance=(),
            evidence_categories=("billing",),
            expected_error_codes=("AccessDenied", "UnauthorizedOperation"),
            client_explanation=("The normal live AWS workflow uses ce:GetCostAndUsage to collect the last completed month billing baseline."),
            review_notes="Read-only platform billing evidence collection.",
            wildcard_justification=(
                "ce:GetCostAndUsage requires Resource='*' because AWS Cost Explorer does not support resource-level IAM constraints for this operation."
            ),
            authorization_scope_variant_ids=("ce-getcostandusage-default",),
            resource_arn_templates=("*",),
            resolved_resources=("*",),
            authorization_references=("https://docs.aws.amazon.com/service-authorization/latest/reference/",),
            scope_status="wildcard_required",
        )

    def _build_requirements(
        self,
        *,
        provider_id: str,
        scanner_ids: tuple[str, ...],
        excluded: bool,
        aws_scope: AwsPolicyExecutionScope,
    ) -> tuple[PermissionRequirement, ...]:
        requirements: dict[tuple[str, str, str], PermissionRequirement] = {}
        for scanner_id in scanner_ids:
            definition = SCANNERS[scanner_id]
            for requirement in self._requirements_for_definition(
                provider_id=provider_id,
                definition=definition,
                excluded=excluded,
                aws_scope=aws_scope,
            ):
                key = (
                    requirement.provider_id,
                    requirement.api_action,
                    requirement.resource_scope,
                )
                existing = requirements.get(key)
                requirements[key] = requirement if existing is None else self._merge_requirements(existing, requirement)
        return tuple(
            sorted(
                requirements.values(),
                key=lambda item: (
                    item.provider_id,
                    item.service,
                    item.api_action,
                    item.requirement_type,
                    item.scanner_ids,
                ),
            ),
        )

    def _merge_requirements(
        self,
        left: PermissionRequirement,
        right: PermissionRequirement,
    ) -> PermissionRequirement:
        scanner_ids = tuple(sorted({*left.scanner_ids, *right.scanner_ids}))
        provenance = tuple(
            sorted(
                {
                    *left.scanner_provenance,
                    *right.scanner_provenance,
                },
                key=lambda item: (item.scanner_id, item.requirement_type, item.reason),
            ),
        )
        evidence_categories = tuple(sorted({*left.evidence_categories, *right.evidence_categories}))
        variant_ids = tuple(
            sorted(
                {
                    *left.authorization_scope_variant_ids,
                    *right.authorization_scope_variant_ids,
                },
            ),
        )
        conditional_values = tuple(
            sorted(
                {value for value in (left.conditional_on, right.conditional_on) if value},
            ),
        )
        wildcard_values = tuple(
            sorted(
                {
                    value
                    for value in (
                        left.wildcard_justification,
                        right.wildcard_justification,
                    )
                    if value
                },
            ),
        )
        diagnostic_values = tuple(
            sorted(
                {value for value in (left.diagnostic_context, right.diagnostic_context) if value},
            ),
        )
        requirement_type = self._promote_requirement_type(left, right)
        conditional_on = None
        if requirement_type != "required":
            conditional_on = "; ".join(conditional_values) if conditional_values else None
        return replace(
            left,
            requirement_id=f"{left.provider_id}:{left.api_action}:{requirement_type}",
            requirement_type=requirement_type,
            chargeable=left.chargeable or right.chargeable,
            scanner_ids=scanner_ids,
            scanner_provenance=provenance,
            evidence_categories=evidence_categories,
            conditional_on=conditional_on,
            diagnostic_context="; ".join(diagnostic_values),
            client_explanation=(f"{left.api_action} is required by {len(scanner_ids)} scanner(s): " + ", ".join(scanner_ids) + "."),
            wildcard_justification="; ".join(wildcard_values),
            authorization_scope_variant_ids=variant_ids,
            resource_arn_templates=tuple(
                sorted({*left.resource_arn_templates, *right.resource_arn_templates}),
            ),
            resolved_resources=tuple(
                sorted({*left.resolved_resources, *right.resolved_resources}),
            ),
            iam_conditions=_merge_conditions(
                left.iam_conditions,
                right.iam_conditions,
            ),
            unresolved_variables=tuple(
                sorted({*left.unresolved_variables, *right.unresolved_variables}),
            ),
            authorization_references=tuple(
                sorted({*left.authorization_references, *right.authorization_references}),
            ),
            scope_status=(
                "unresolved"
                if "unresolved" in {left.scope_status, right.scope_status}
                else "wildcard_required"
                if "wildcard_required" in {left.scope_status, right.scope_status}
                else "resource_scoped"
            ),
        )

    def _promote_requirement_type(
        self,
        left: PermissionRequirement,
        right: PermissionRequirement,
    ) -> RequirementType:
        return min(
            (left.requirement_type, right.requirement_type),
            key=lambda item: REQUIREMENT_TYPE_PRECEDENCE[item],
        )

    def _requirements_for_definition(
        self,
        *,
        provider_id: str,
        definition: ScannerDefinition,
        excluded: bool,
        aws_scope: AwsPolicyExecutionScope,
    ) -> list[PermissionRequirement]:
        self._validate_definition_permission_metadata(definition)
        requirements = [
            self._build_requirement(
                provider_id=provider_id,
                definition=definition,
                metadata=metadata,
                aws_scope=aws_scope,
            )
            for metadata in definition.iam_requirements or ()
        ]
        if not excluded:
            return requirements
        return [
            replace(
                requirement,
                diagnostic_context="Excluded because chargeable scanners are disabled.",
            )
            for requirement in requirements
        ]

    def _validate_definition_permission_metadata(
        self,
        definition: ScannerDefinition,
    ) -> None:
        iam_requirements = definition.iam_requirements or ()
        if not iam_requirements:
            msg = f"Scanner {definition.scanner_id} has no declared IAM permission metadata."
            raise ValueError(msg)
        declared_required = {item.api_action for item in iam_requirements if item.requirement_type == "required"}
        declared_conditional = {item.api_action for item in iam_requirements if item.requirement_type in {"conditional", "optional_enrichment"}}
        if declared_required != set(definition.required_iam_actions):
            msg = f"Scanner {definition.scanner_id} IAM metadata does not match required_iam_actions."
            raise ValueError(msg)
        if declared_conditional != set(definition.conditional_iam_actions):
            msg = f"Scanner {definition.scanner_id} IAM metadata does not match conditional_iam_actions."
            raise ValueError(msg)
        for item in iam_requirements:
            self._validate_requirement_metadata(definition, item)

    def _validate_requirement_metadata(
        self,
        definition: ScannerDefinition,
        metadata: ScannerIamRequirement,
    ) -> None:
        if not metadata.api_action.strip():
            msg = f"Scanner {definition.scanner_id} has an empty IAM action declaration."
            raise ValueError(msg)
        if not metadata.reason.strip():
            msg = f"Scanner {definition.scanner_id} action {metadata.api_action} has no IAM reason."
            raise ValueError(msg)
        if not is_read_only_iam_action(metadata.api_action):
            msg = f"Scanner {definition.scanner_id} action {metadata.api_action} is not approved as read-only."
            raise ValueError(msg)
        if metadata.resource_scope == "wildcard_required" and not metadata.resource_scope_reason.strip():
            msg = f"Scanner {definition.scanner_id} action {metadata.api_action} has no wildcard resource-scope rationale."
            raise ValueError(msg)
        if not metadata.resource_scope:
            msg = f"Scanner {definition.scanner_id} action {metadata.api_action} has no resource scope."
            raise ValueError(msg)
        if not metadata.evidence_categories:
            msg = f"Scanner {definition.scanner_id} action {metadata.api_action} has no evidence categories."
            raise ValueError(msg)
        if metadata.requirement_type != "required" and not (metadata.conditional_on or "").strip():
            msg = f"Scanner {definition.scanner_id} action {metadata.api_action} has no IAM condition."
            raise ValueError(msg)

    def _build_requirement(
        self,
        *,
        provider_id: str,
        definition: ScannerDefinition,
        metadata: ScannerIamRequirement,
        aws_scope: AwsPolicyExecutionScope,
    ) -> PermissionRequirement:
        api_action = metadata.api_action
        requirement_type: RequirementType = metadata.requirement_type
        service = api_action.split(":", maxsplit=1)[0] if ":" in api_action else "unknown"
        variant_ids = SCANNER_IAM_SCOPE_BINDINGS.get(
            (definition.scanner_id, api_action),
            (),
        )
        if not variant_ids:
            msg = f"Scanner {definition.scanner_id} action {api_action} has no AWS authorization-scope binding."
            raise ValueError(msg)
        authorization = get_aws_iam_action_scope(api_action)
        variants = tuple(authorization.get_variant(variant_id) for variant_id in variant_ids)
        resolved = AWS_AUTHORIZATION_SCOPE_RESOLVER.resolve(variants, aws_scope)
        provenance = ScannerPermissionProvenance(
            scanner_id=definition.scanner_id,
            reason=metadata.reason,
            requirement_type=requirement_type,
            chargeable=metadata.chargeable,
            conditional_on=metadata.conditional_on,
            evidence_categories=metadata.evidence_categories,
            authorization_scope_variant_ids=variant_ids,
        )
        return PermissionRequirement(
            requirement_id=f"{provider_id}:{api_action}:{requirement_type}:{definition.scanner_id}",
            provider_id=provider_id,
            service=service,
            api_action=api_action,
            requirement_type=requirement_type,
            chargeable=metadata.chargeable,
            resource_scope=(
                "wildcard_required"
                if resolved["scope_status"] == "wildcard_required"
                else "resource_scoped_supported"
                if resolved["scope_status"] == "resource_scoped"
                else "unknown"
            ),
            scanner_ids=(definition.scanner_id,),
            scanner_provenance=(provenance,),
            evidence_categories=metadata.evidence_categories,
            conditional_on=metadata.conditional_on,
            expected_error_codes=("AccessDenied", "UnauthorizedOperation"),
            client_explanation=metadata.reason,
            diagnostic_context=definition.chargeable_reason if definition.may_incur_charges else "",
            review_notes="Review AWS resource and condition constraints before deployment.",
            wildcard_justification=str(resolved["wildcard_justification"]),
            authorization_scope_variant_ids=variant_ids,
            resource_arn_templates=resolved["resource_arn_templates"],
            resolved_resources=resolved["resolved_resources"],
            iam_conditions=resolved["iam_conditions"],
            unresolved_variables=resolved["unresolved_variables"],
            authorization_references=resolved["authorization_references"],
            scope_status=str(resolved["scope_status"]),
        )

    def _build_warnings(
        self,
        selection: ScannerSelection,
    ) -> tuple[dict[str, str], ...]:
        return tuple(
            {
                "code": "chargeable_scanner_excluded",
                "scanner_id": block.scanner_id,
                "message": ("Chargeable scanner actions are excluded by default and require explicit opt-in."),
                "reason": block.reason,
            }
            for block in selection.chargeable_blocks
        )

    def _build_limitations(self) -> tuple[str, ...]:
        return (
            "This plan is derived from Unio Collector scanner metadata and is not a live AWS permission simulation.",
            (
                "AWS effective permissions can be affected by identity policies, "
                "resource policies, permissions boundaries, SCPs, session "
                "policies, conditions, and service behavior."
            ),
            ("Wildcard resources are included only for audited catalogue variants where AWS does not support a narrower resource scope."),
        )


def _merge_conditions(
    left: tuple[dict[str, object], ...],
    right: tuple[dict[str, object], ...],
) -> tuple[dict[str, object], ...]:
    by_key: dict[tuple[str, str], set[str]] = {}
    for item in (*left, *right):
        key = (str(item.get("operator") or ""), str(item.get("key") or ""))
        values = item.get("values")
        if isinstance(values, list | tuple):
            by_key.setdefault(key, set()).update(str(value) for value in values)
    return tuple(
        {
            "operator": operator,
            "key": key,
            "values": sorted(values),
        }
        for (operator, key), values in sorted(by_key.items())
    )
