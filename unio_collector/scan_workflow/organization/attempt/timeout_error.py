"""Organization account timeout failure."""


class OrganizationAttemptTimeoutError(TimeoutError):
    """The child exceeded its physical execution boundary."""


__all__ = ["OrganizationAttemptTimeoutError"]
