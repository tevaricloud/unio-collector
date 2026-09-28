"""Shared evidence contract for collector wheel platform validation."""

VALIDATION_SCHEMA_VERSION = "2026-09-collector-wheel-installed-validation-v2"
SUPPORTED_VALIDATION_TARGETS = {
    "linux-x86_64": ("linux", "x86_64"),
    "macos-arm64": ("macos", "arm64"),
    "macos-x86_64": ("macos", "x86_64"),
    "windows-x86_64": ("windows", "x86_64"),
}
