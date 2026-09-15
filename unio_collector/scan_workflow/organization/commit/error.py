"""Historical account failure contract retaining an authoritative child bundle."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scan_workflow.organization.model.bundle import PerAccountBundleResult


class OrganizationAccountReportError(RuntimeError):
    """Preserve the historical exception name for a failed post-commit operation."""

    def __init__(
        self,
        bundle_result: PerAccountBundleResult,
        role_audit: dict[str, object],
        code: str,
    ) -> None:
        """Retain the committed account artifacts with the failure."""
        super().__init__(code)
        self.bundle_result = bundle_result
        self.role_audit = role_audit
        self.code = code


__all__ = ["OrganizationAccountReportError"]
