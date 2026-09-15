"""Scanner-to-AWS-authorization-scope bindings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.aws.iam import get_aws_iam_action_scope

_VARIANT_OVERRIDES = {
    ("cur-data-export-attribution", "s3:GetObject"): ("s3-getobject-object",),
}

if TYPE_CHECKING:
    from collections.abc import Mapping

    from unio_collector.scanners.scanner.definition import ScannerDefinition


def build_scanner_iam_scope_bindings(
    definitions: Mapping[str, ScannerDefinition],
) -> dict[tuple[str, str], tuple[str, ...]]:
    """Bind every scanner action to shared authorization variants."""
    bindings: dict[tuple[str, str], tuple[str, ...]] = {}
    for scanner_id, definition in definitions.items():
        for requirement in definition.iam_requirements or ():
            scope = get_aws_iam_action_scope(requirement.api_action)
            key = (scanner_id, requirement.api_action)
            variant_ids = _VARIANT_OVERRIDES.get(key)
            if variant_ids is None and len(scope.variants) == 1:
                variant_ids = (scope.variants[0].variant_id,)
            bindings[key] = variant_ids or ()
    return bindings


__all__ = ["build_scanner_iam_scope_bindings"]
