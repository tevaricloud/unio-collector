from __future__ import annotations  # noqa: D100

# ruff: noqa: ANN401
import ctypes
import sys
from typing import Any


def advapi32() -> Any:
    """Return the configured Windows authorization API library."""
    if sys.platform != "win32":
        message = "Windows authorization APIs are unavailable on this platform."
        raise OSError(message)
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    library.OpenProcessToken.restype = ctypes.c_int
    library.GetTokenInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.GetTokenInformation.restype = ctypes.c_int
    library.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    library.ConvertSidToStringSidW.restype = ctypes.c_int
    library.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    library.SetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    library.SetNamedSecurityInfoW.restype = ctypes.c_uint32
    library.GetSecurityInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.GetSecurityInfo.restype = ctypes.c_uint32
    library.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_int),
    ]
    library.GetSecurityDescriptorDacl.restype = ctypes.c_int
    library.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ushort),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.GetSecurityDescriptorControl.restype = ctypes.c_int
    library.GetAclInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    library.GetAclInformation.restype = ctypes.c_int
    library.GetAce.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.GetAce.restype = ctypes.c_int
    return library


def windows_error(error: int | None = None) -> OSError:
    """Create a Windows error from an explicit code or ctypes' saved last error."""
    if sys.platform == "win32":
        if error is None:
            error = ctypes.get_last_error()
        return ctypes.WinError(error)
    message = "Windows error APIs are unavailable on this platform."
    raise OSError(message)
