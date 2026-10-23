"""Static closed field binding for the actual IAM password callback."""

from typing import ClassVar

from unio_collector.privacy.identity.notes import PASSWORD, IdentityNoteContract


class PasswordNoteContract(IdentityNoteContract):
    """Keep the callback schema static and isolated from parallel operations."""

    fields: ClassVar = PASSWORD
