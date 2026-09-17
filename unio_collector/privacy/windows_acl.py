from __future__ import annotations  # noqa: D100

# ruff: noqa: ANN401,EM101,TRY003
import ctypes
import os
import sys
from typing import TYPE_CHECKING, Any

from unio_collector.privacy.acl_assessment import (
    WINDOWS_ACL_CONFIRMED_BROAD,
    WINDOWS_ACL_INDETERMINATE,
    WINDOWS_ACL_INHERITANCE_ENABLED,
    WINDOWS_ACL_KNOWN_UNSUPPORTED,
    WINDOWS_ACL_REQUIRED_ACCESS_MISSING,
    WINDOWS_ACL_SECURE,
    WindowsAclAssessment,
    WindowsAclState,
)
from unio_collector.privacy.native_security_api import advapi32 as _advapi32
from unio_collector.privacy.native_security_api import windows_error as _windows_error
from unio_collector.privacy.security_warning import SecurityWarning

if TYPE_CHECKING:
    from pathlib import Path

_ACCESS_ALLOWED_ACE_TYPE = 0x00
_ACCESS_DENIED_ACE_TYPE = 0x01
_ACL_SIZE_INFORMATION_CLASS = 2
_DACL_SECURITY_INFORMATION = 0x00000004
_ERROR_INVALID_FUNCTION = 1
_ERROR_NOT_SUPPORTED = 50
_FILE_ALL_ACCESS = 0x001F01FF
_INHERIT_ONLY_ACE = 0x08
_MIN_STANDARD_ACE_SIZE = 12
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_SDDL_REVISION_1 = 1
_SE_DACL_PROTECTED = 0x1000
_SE_FILE_OBJECT = 1
_SYSTEM_SID = "S-1-5-18"
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_UNSUPPORTED_ACL_ERRORS = {_ERROR_INVALID_FUNCTION, _ERROR_NOT_SUPPORTED}


_AceRecord = tuple[int, int, int, str]
_ACE_TYPE_INDEX = 0
_ACE_FLAGS_INDEX = 1
_ACE_MASK_INDEX = 2
_ACE_TRUSTEE_INDEX = 3


def secure_private_windows_acl(
    descriptor: int,
    path: Path,
    *,
    artifact: str,
) -> WindowsAclAssessment:
    """Apply and inspect a protected private DACL through an open file handle."""
    if os.name != "nt":
        return WindowsAclAssessment(WINDOWS_ACL_SECURE)
    apply_warning = _apply_private_windows_acl_path(path, artifact=artifact)
    if apply_warning is not None and apply_warning.code.endswith("acl_unsupported"):
        return WindowsAclAssessment(
            WINDOWS_ACL_KNOWN_UNSUPPORTED,
            (apply_warning,),
        )
    assessment = inspect_private_windows_acl_handle(descriptor, artifact=artifact)
    if apply_warning is None:
        return assessment
    return WindowsAclAssessment(
        assessment.state,
        (apply_warning, *assessment.warnings),
    )


def inspect_private_windows_acl_handle(
    descriptor: int,
    *,
    artifact: str,
) -> WindowsAclAssessment:
    """Inspect a private artifact through an open descriptor."""
    if os.name != "nt":
        return WindowsAclAssessment(WINDOWS_ACL_SECURE)
    try:
        security_descriptor, dacl = _security_descriptor_for_handle(descriptor)
        try:
            if not dacl:
                return _assessment(
                    WINDOWS_ACL_CONFIRMED_BROAD,
                    code="private_artifact.windows_acl_broad",
                    artifact=artifact,
                    message="Windows ACL inspection found a null DACL that permits broad access.",
                )
            protected = _dacl_is_protected(security_descriptor)
            records = _enumerate_aces(dacl)
            return _assess_ace_records(
                records,
                protected=protected,
                user_sid=_current_user_sid(),
                artifact=artifact,
            )
        finally:
            _local_free(security_descriptor)
    except OSError as exc:
        if getattr(exc, "winerror", None) in _UNSUPPORTED_ACL_ERRORS:
            return _assessment(
                WINDOWS_ACL_KNOWN_UNSUPPORTED,
                code="private_artifact.windows_acl_unsupported",
                artifact=artifact,
                message="The destination filesystem does not support the required Windows ACL policy.",
            )
        return _inspection_unavailable(artifact, exc)
    except (RuntimeError, ValueError) as exc:
        return _inspection_unavailable(artifact, exc)
    return WindowsAclAssessment(WINDOWS_ACL_SECURE)


def _assess_ace_records(
    records: tuple[_AceRecord, ...],
    *,
    protected: bool,
    user_sid: str,
    artifact: str,
) -> WindowsAclAssessment:
    allowed = {_SYSTEM_SID, user_sid}
    if any(
        record[_ACE_TYPE_INDEX] == _ACCESS_ALLOWED_ACE_TYPE
        and not record[_ACE_FLAGS_INDEX] & _INHERIT_ONLY_ACE
        and record[_ACE_MASK_INDEX]
        and record[_ACE_TRUSTEE_INDEX] not in allowed
        for record in records
    ):
        return _assessment(
            WINDOWS_ACL_CONFIRMED_BROAD,
            code="private_artifact.windows_acl_broad",
            artifact=artifact,
            message="Windows ACL inspection found access grants beyond the current user and SYSTEM.",
        )
    if any(record[_ACE_TYPE_INDEX] not in {_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_DENIED_ACE_TYPE} for record in records):
        return _assessment(
            WINDOWS_ACL_INDETERMINATE,
            code="private_artifact.windows_acl_inspection_unavailable",
            artifact=artifact,
            message="Windows ACL inspection found an unsupported ACE type and was inconclusive.",
        )
    granted = {
        record[_ACE_TRUSTEE_INDEX]
        for record in records
        if record[_ACE_TYPE_INDEX] == _ACCESS_ALLOWED_ACE_TYPE
        and not record[_ACE_FLAGS_INDEX] & _INHERIT_ONLY_ACE
        and record[_ACE_MASK_INDEX] & _FILE_ALL_ACCESS == _FILE_ALL_ACCESS
    }
    if not allowed <= granted:
        return _assessment(
            WINDOWS_ACL_REQUIRED_ACCESS_MISSING,
            code="private_artifact.windows_acl_required_access_missing",
            artifact=artifact,
            message="Windows ACL inspection did not confirm full access for the current user and SYSTEM.",
        )
    if not protected:
        return _assessment(
            WINDOWS_ACL_INHERITANCE_ENABLED,
            code="private_artifact.windows_acl_inheritance_enabled",
            artifact=artifact,
            message="Windows ACL inspection found an unprotected DACL with inheritance enabled.",
        )
    return WindowsAclAssessment(WINDOWS_ACL_SECURE)


def inspect_private_windows_acl(
    path: Path,
    *,
    artifact: str,
) -> tuple[SecurityWarning, ...]:
    """Inspect a private artifact DACL without exposing its local path."""
    return assess_private_windows_acl(path, artifact=artifact).warnings


def assess_private_windows_acl(
    path: Path,
    *,
    artifact: str,
) -> WindowsAclAssessment:
    """Return a typed assessment for an existing private file."""
    if os.name != "nt":
        return WindowsAclAssessment(WINDOWS_ACL_SECURE)
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            return inspect_private_windows_acl_handle(descriptor, artifact=artifact)
        finally:
            os.close(descriptor)
    except OSError as exc:
        return _inspection_unavailable(artifact, exc)


def _apply_private_windows_acl_path(
    path: Path,
    *,
    artifact: str,
) -> SecurityWarning | None:
    security_descriptor = ctypes.c_void_p()
    try:
        security_descriptor = _descriptor_from_sddl(
            f"D:P(A;;FA;;;SY)(A;;FA;;;{_current_user_sid()})",
        )
        dacl = _dacl_from_descriptor(security_descriptor)
        error = _advapi32().SetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        if error:
            if error in _UNSUPPORTED_ACL_ERRORS:
                return _permission_warning(
                    code="private_artifact.windows_acl_unsupported",
                    artifact=artifact,
                    message="The destination filesystem does not support the required Windows ACL policy.",
                )
            raise _windows_error(error)
    except (OSError, RuntimeError, ValueError) as exc:
        return _permission_warning(
            code="private_artifact.windows_acl_apply_failed",
            artifact=artifact,
            message=f"Could not apply a restrictive Windows ACL: {type(exc).__name__}.",
        )
    finally:
        _local_free(security_descriptor)
    return None


def _security_descriptor_for_handle(descriptor: int) -> tuple[ctypes.c_void_p, ctypes.c_void_p]:
    security_descriptor = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    error = _advapi32().GetSecurityInfo(
        _windows_handle(descriptor),
        _SE_FILE_OBJECT,
        _DACL_SECURITY_INFORMATION,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(security_descriptor),
    )
    if error:
        raise _windows_error(error)
    if not security_descriptor:
        raise RuntimeError("Windows ACL inspection returned no security descriptor.")
    return security_descriptor, dacl


def _dacl_from_descriptor(security_descriptor: ctypes.c_void_p) -> ctypes.c_void_p:
    present = ctypes.c_int()
    defaulted = ctypes.c_int()
    dacl = ctypes.c_void_p()
    if not _advapi32().GetSecurityDescriptorDacl(
        security_descriptor,
        ctypes.byref(present),
        ctypes.byref(dacl),
        ctypes.byref(defaulted),
    ):
        raise _windows_error()
    if not present.value or not dacl:
        raise RuntimeError("Generated Windows private DACL is missing.")
    return dacl


def _dacl_is_protected(security_descriptor: ctypes.c_void_p) -> bool:
    control = ctypes.c_ushort()
    revision = ctypes.c_uint32()
    if not _advapi32().GetSecurityDescriptorControl(
        security_descriptor,
        ctypes.byref(control),
        ctypes.byref(revision),
    ):
        raise _windows_error()
    return bool(control.value & _SE_DACL_PROTECTED)


def _enumerate_aces(dacl: ctypes.c_void_p) -> tuple[_AceRecord, ...]:
    information = (ctypes.c_uint32 * 3)()
    advapi32 = _advapi32()
    if not advapi32.GetAclInformation(
        dacl,
        ctypes.byref(information),
        ctypes.sizeof(information),
        _ACL_SIZE_INFORMATION_CLASS,
    ):
        raise _windows_error()
    records: list[_AceRecord] = []
    for index in range(information[0]):
        ace = ctypes.c_void_p()
        if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
            raise _windows_error()
        ace_address = ace.value
        if ace_address is None:
            raise RuntimeError("Windows ACL inspection returned an empty ACE pointer.")
        ace_type = ctypes.c_ubyte.from_address(ace_address).value
        ace_flags = ctypes.c_ubyte.from_address(ace_address + 1).value
        ace_size = ctypes.c_ushort.from_address(ace_address + 2).value
        if ace_size < _MIN_STANDARD_ACE_SIZE:
            raise ValueError("Windows ACL inspection found an invalid ACE size.")
        if ace_type not in {
            _ACCESS_ALLOWED_ACE_TYPE,
            _ACCESS_DENIED_ACE_TYPE,
        }:
            records.append(
                (ace_type, ace_flags, 0, ""),
            )
            continue
        mask = ctypes.c_uint32.from_address(ace_address + 4).value
        trustee = _sid_to_string(ctypes.c_void_p(ace_address + 8))
        records.append(
            (ace_type, ace_flags, mask, trustee),
        )
    return tuple(records)


def _sid_to_string(sid: ctypes.c_void_p) -> str:
    sid_text = ctypes.c_wchar_p()
    if not _advapi32().ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
        raise _windows_error()
    try:
        if not sid_text.value:
            raise RuntimeError("Windows SID conversion returned no value.")
        return sid_text.value
    finally:
        _local_free(sid_text)


def _assessment(
    state: WindowsAclState,
    *,
    code: str,
    artifact: str,
    message: str,
) -> WindowsAclAssessment:
    return WindowsAclAssessment(
        state,
        (_permission_warning(code=code, artifact=artifact, message=message),),
    )


def _inspection_unavailable(
    artifact: str,
    exc: BaseException,
) -> WindowsAclAssessment:
    return _assessment(
        WINDOWS_ACL_INDETERMINATE,
        code="private_artifact.windows_acl_inspection_unavailable",
        artifact=artifact,
        message=f"Windows ACL inspection was inconclusive: {type(exc).__name__}.",
    )


def _permission_warning(
    *,
    code: str,
    artifact: str,
    message: str,
) -> SecurityWarning:
    return SecurityWarning(
        code=code,
        category="permission",
        artifact=artifact,
        message=message,
    )


def _kernel32() -> Any:
    if sys.platform != "win32":
        raise OSError("Windows kernel APIs are unavailable on this platform.")
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.GetCurrentProcess.restype = ctypes.c_void_p
    library.CloseHandle.argtypes = [ctypes.c_void_p]
    library.CloseHandle.restype = ctypes.c_int
    library.LocalFree.argtypes = [ctypes.c_void_p]
    library.LocalFree.restype = ctypes.c_void_p
    return library


def _windows_handle(descriptor: int) -> ctypes.c_void_p:
    if sys.platform != "win32":
        raise OSError("Windows file handles are unavailable on this platform.")
    import msvcrt  # noqa: PLC0415

    handle = msvcrt.get_osfhandle(descriptor)
    if handle == -1:
        raise OSError("Could not resolve the Windows private-file handle.")
    return ctypes.c_void_p(handle)


def _current_user_sid() -> str:
    advapi32 = _advapi32()
    kernel32 = _kernel32()
    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        _TOKEN_QUERY,
        ctypes.byref(token),
    ):
        raise _windows_error()
    try:
        needed = ctypes.c_uint32()
        advapi32.GetTokenInformation(
            token,
            _TOKEN_USER,
            None,
            0,
            ctypes.byref(needed),
        )
        if not needed.value:
            raise _windows_error()
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token,
            _TOKEN_USER,
            buffer,
            needed,
            ctypes.byref(needed),
        ):
            raise _windows_error()
        sid_pointer = ctypes.c_void_p.from_buffer(buffer).value
        return _sid_to_string(ctypes.c_void_p(sid_pointer))
    finally:
        kernel32.CloseHandle(token)


def _descriptor_from_sddl(sddl: str) -> ctypes.c_void_p:
    descriptor = ctypes.c_void_p()
    size = ctypes.c_uint32()
    if not _advapi32().ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        ctypes.byref(size),
    ):
        raise _windows_error()
    return descriptor


def _local_free(pointer: Any) -> None:
    if pointer:
        _kernel32().LocalFree(pointer)
