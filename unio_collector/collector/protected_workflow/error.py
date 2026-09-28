"""Stable failure contract for integrated protected collection."""

from __future__ import annotations


class ProtectedCollectionWorkflowError(RuntimeError):
    """Report the failed stage without exposing protected artifact content."""

    def __init__(
        self,
        message: str,
        *,
        failed_stage: str,
        stages: dict[str, str],
        cleanup: dict[str, object],
    ) -> None:
        """Store safe workflow diagnostics."""
        super().__init__(message)
        self.failed_stage = failed_stage
        self.stages = dict(stages)
        self.cleanup = dict(cleanup)

    def convert_to_dict(self) -> dict[str, object]:
        """Return a stable non-secret failure payload."""
        return {
            "status": "failed",
            "workflow": "collect-protected",
            "workflow_version": 1,
            "failed_stage": self.failed_stage,
            "stages": dict(self.stages),
            "cleanup": dict(self.cleanup),
            "error": str(self),
        }


__all__ = ["ProtectedCollectionWorkflowError"]
