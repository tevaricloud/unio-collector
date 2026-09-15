"""Organization account cancellation failure."""


class OrganizationAttemptCancelledError(RuntimeError):
    """The parent revoked the attempt after user cancellation."""


__all__ = ["OrganizationAttemptCancelledError"]
