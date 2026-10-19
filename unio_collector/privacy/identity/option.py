"""Static closed field binding for the actual IAM option callback."""

from typing import ClassVar

from unio_collector.privacy.identity.notes import OPTION, IdentityNoteContract


class OptionNoteContract(IdentityNoteContract):
    """Keep the callback schema static and isolated from parallel operations."""

    fields: ClassVar = OPTION
