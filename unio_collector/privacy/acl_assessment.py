from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from unio_collector.privacy.security_warning import SecurityWarning

WindowsAclState = Literal[
    "secure",
    "confirmed_broad",
    "inheritance_enabled",
    "known_acl_unsupported",
    "required_access_missing",
    "indeterminate",
]
WINDOWS_ACL_SECURE: WindowsAclState = "secure"
WINDOWS_ACL_CONFIRMED_BROAD: WindowsAclState = "confirmed_broad"
WINDOWS_ACL_INHERITANCE_ENABLED: WindowsAclState = "inheritance_enabled"
WINDOWS_ACL_KNOWN_UNSUPPORTED: WindowsAclState = "known_acl_unsupported"
WINDOWS_ACL_REQUIRED_ACCESS_MISSING: WindowsAclState = "required_access_missing"
WINDOWS_ACL_INDETERMINATE: WindowsAclState = "indeterminate"


@dataclass(frozen=True)
class WindowsAclAssessment:
    """Typed Windows ACL result with non-secret structured warnings."""

    state: WindowsAclState
    warnings: tuple[SecurityWarning, ...] = ()
