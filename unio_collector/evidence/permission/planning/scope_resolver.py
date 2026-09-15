from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.iam import (
        AwsIamConditionSpecification,
        AwsIamScopeVariant,
    )
    from unio_collector.evidence.permission.planning.aws_scope import (
        AwsPolicyExecutionScope,
    )
    from unio_collector.evidence.permission.planning.resolved_scope import (
        ResolvedAuthorizationScope,
    )


class AwsAuthorizationScopeResolver:
    """Resolve one bound AWS action-scope variant without broadening."""

    def resolve(
        self,
        variants: tuple[AwsIamScopeVariant, ...],
        aws_scope: AwsPolicyExecutionScope,
    ) -> ResolvedAuthorizationScope:
        """Return exact, wildcard-required, or unresolved scope."""
        if len(variants) != 1:
            return self._ambiguous(variants)
        variant = variants[0]
        variables = aws_scope.variables()
        unresolved = {name for name in variant.required_variables if variant.unresolved or not variables.get(name)}
        resources: set[str] = set()
        conditions: tuple[dict[str, object], ...] = ()
        if not variant.unresolved:
            conditions, condition_unresolved = self._resolve_conditions(
                variant.conditions,
                aws_scope,
            )
            unresolved.update(condition_unresolved)
            if not unresolved:
                for template in variant.arn_templates:
                    resources.update(self._resolve_template(template, aws_scope))
        scope_status = "unresolved" if unresolved else "wildcard_required" if variant.wildcard_required else "resource_scoped"
        return {
            "resource_arn_templates": tuple(sorted(variant.arn_templates)),
            "resolved_resources": tuple(sorted(resources)),
            "iam_conditions": conditions,
            "unresolved_variables": tuple(sorted(unresolved)),
            "authorization_references": tuple(
                sorted(variant.authorization_references),
            ),
            "wildcard_justification": (variant.rationale if variant.wildcard_required else ""),
            "scope_status": scope_status,
        }

    def _resolve_conditions(
        self,
        specifications: tuple[AwsIamConditionSpecification, ...],
        aws_scope: AwsPolicyExecutionScope,
    ) -> tuple[tuple[dict[str, object], ...], set[str]]:
        rendered: list[dict[str, object]] = []
        unresolved: set[str] = set()
        variables = aws_scope.variables()
        for condition in specifications:
            missing = {name for name in condition.required_variables if not variables.get(name)}
            unresolved.update(missing)
            if missing:
                continue
            values: list[str] = []
            for template in condition.value_templates:
                if template == "{regions}":
                    values.extend(aws_scope.regions)
                else:
                    values.append(
                        template.format(
                            account_id=aws_scope.account_id,
                            partition=aws_scope.partition,
                        ),
                    )
            rendered.append(
                {
                    "operator": condition.operator,
                    "key": condition.key,
                    "values": sorted(dict.fromkeys(values)),
                },
            )
        return (
            tuple(
                sorted(
                    rendered,
                    key=lambda item: (
                        str(item["operator"]),
                        str(item["key"]),
                    ),
                ),
            ),
            unresolved,
        )

    def _ambiguous(
        self,
        variants: tuple[AwsIamScopeVariant, ...],
    ) -> ResolvedAuthorizationScope:
        return {
            "resource_arn_templates": tuple(
                sorted(
                    {template for variant in variants for template in variant.arn_templates},
                ),
            ),
            "resolved_resources": (),
            "iam_conditions": (),
            "unresolved_variables": ("authorization_scope_variant",),
            "authorization_references": tuple(
                sorted(
                    {reference for variant in variants for reference in variant.authorization_references},
                ),
            ),
            "wildcard_justification": "",
            "scope_status": "unresolved",
        }

    def _resolve_template(
        self,
        template: str,
        aws_scope: AwsPolicyExecutionScope,
    ) -> tuple[str, ...]:
        regions: tuple[str | None, ...] = tuple(aws_scope.regions) if "{region}" in template else (None,)
        return tuple(
            template.format(
                account_id=aws_scope.account_id,
                partition=aws_scope.partition,
                region=region,
            )
            for region in regions
        )


__all__ = ["AwsAuthorizationScopeResolver"]
