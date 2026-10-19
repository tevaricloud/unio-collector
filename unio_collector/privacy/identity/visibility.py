"""Static closed field binding for the actual IAM visibility callback."""

from typing import ClassVar

from unio_collector.privacy.identity.notes import CENTER, IdentityNoteContract


class VisibilityNoteContract(IdentityNoteContract):
    """Keep the callback schema static and isolated from parallel operations."""

    fields: ClassVar = CENTER
