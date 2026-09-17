from __future__ import annotations  # noqa: D100

import ipaddress
import re
from typing import TYPE_CHECKING
from zipfile import ZipFile

from unio_collector.privacy.leak.finding import LeakFinding
from unio_collector.privacy.leak.result import LeakScanResult

if TYPE_CHECKING:
    from pathlib import Path

ACCOUNT_RE = re.compile(r"(?<![A-Za-z0-9.])\d{12}(?![A-Za-z0-9.])")
ARN_RE = re.compile(r"\barn:aws(?:-[a-z]+)?:[^:\s]+:[^:\s]*:\d{12}:", re.IGNORECASE)
ARN_FILENAME_RE = re.compile(r"\barn[-_:]aws(?:[-_:][a-z]+)?[-_:][a-z0-9-]+[-_:][a-z0-9-]*[-_:]\d{12}[-_:]", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
PRIVATE_KEY_RE = re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FILENAME_ACCOUNT_RE = re.compile(r"(?<![A-Za-z0-9])\d{12}(?![A-Za-z0-9])")
IPV4_VERSION = 4
PROTECTED_TOKEN_RE = re.compile(
    r"\b(?:ACCOUNT|RESOURCE|ROLE|IPV4|IPV6|CIDR|DNS|EMAIL|BUCKET|ARN|TAG)-[A-Z2-7]{16}\b",
)
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)

TEXT_SUFFIXES = (".json", ".jsonl", ".md", ".txt", ".csv", ".html", ".htm", ".svg", ".xml")
MINIMUM_FILENAME_ORIGINAL_LENGTH = 4
PRIVATE_MATERIAL_FILENAME_MARKERS = (
    "client-root-key",
    "client_root_key",
    "decrypted-vault",
    "decrypted_vault",
    "encrypted-root-key",
    "encrypted_root_key",
    "identity-vault",
    "identity_vault",
    "passphrase",
    "private-key",
    "private_key",
    "recovery",
    "root-key",
    "root_key",
    "vault",
    "wrapped-root-key",
    "wrapped_root_key",
)


class ProtectedArchiveLeakScanner:
    """Defence-in-depth leak scanner for final protected archives."""

    def scan_zip_bytes(
        self,
        *,
        archive_path: Path,
        known_original_values: set[str],
    ) -> LeakScanResult:
        """Scan a protected ZIP archive for obvious plaintext leaks."""
        result = LeakScanResult()
        with ZipFile(archive_path, "r") as archive:
            for name in sorted(archive.namelist()):
                self._scan_filename(name, known_original_values, result)
                if not name.lower().endswith(TEXT_SUFFIXES):
                    continue
                result.files_scanned += 1
                content = archive.read(name).decode("utf-8", errors="replace")
                self._scan_content(name, content, known_original_values, result)
        return result

    def scan_text(
        self,
        *,
        path: str,
        content: str,
        known_original_values: set[str],
    ) -> LeakScanResult:
        """Scan one text payload such as protected report package JSON."""
        result = LeakScanResult(files_scanned=1)
        self._scan_filename(path, known_original_values, result)
        self._scan_content(path, content, known_original_values, result)
        return result

    def _scan_filename(
        self,
        path: str,
        known_original_values: set[str],
        result: LeakScanResult,
    ) -> None:
        normalised = path.replace("\\", "/")
        candidates = [normalised, *[segment for segment in normalised.split("/") if segment]]
        for candidate in candidates:
            scan_candidate = self._strip_safe_filename_tokens(candidate)
            lower_candidate = scan_candidate.casefold()
            if any(marker in lower_candidate for marker in PRIVATE_MATERIAL_FILENAME_MARKERS):
                result.findings.append(
                    LeakFinding(path=path, category="private_material_filename"),
                )
                return
            if self._contains_known_original_filename_value(
                scan_candidate,
                known_original_values,
            ):
                result.findings.append(
                    LeakFinding(path=path, category="known_original_value_filename"),
                )
                return
            if ARN_FILENAME_RE.search(scan_candidate) or ("arn-aws" in lower_candidate and FILENAME_ACCOUNT_RE.search(scan_candidate)):
                result.findings.append(LeakFinding(path=path, category="aws_arn_filename"))
                return
            for category, pattern in (
                ("aws_account_id_filename", FILENAME_ACCOUNT_RE),
                ("email_filename", EMAIL_RE),
                ("aws_access_key_id_filename", ACCESS_KEY_RE),
            ):
                if pattern.search(scan_candidate):
                    result.findings.append(LeakFinding(path=path, category=category))
                    return
            if self._contains_public_ipv4(scan_candidate):
                result.findings.append(LeakFinding(path=path, category="public_ipv4_filename"))
                return

    def _strip_safe_filename_tokens(self, value: str) -> str:
        stripped = SHA256_RE.sub("", UUID_RE.sub("", value))
        return PROTECTED_TOKEN_RE.sub("", stripped)

    def _contains_known_original_filename_value(
        self,
        value: str,
        known_original_values: set[str],
    ) -> bool:
        lower_value = value.casefold()
        for original in sorted(known_original_values, key=len, reverse=True):
            if len(original) < MINIMUM_FILENAME_ORIGINAL_LENGTH:
                continue
            if original.casefold() in lower_value:
                return True
        return False

    def _scan_content(
        self,
        path: str,
        content: str,
        known_original_values: set[str],
        result: LeakScanResult,
    ) -> None:
        for original in sorted(known_original_values, key=len, reverse=True):
            if original and original in content:
                result.findings.append(
                    LeakFinding(path=path, category="known_original_value"),
                )
                break
        pattern_content = SHA256_RE.sub("", UUID_RE.sub("", content))
        pattern_content = PROTECTED_TOKEN_RE.sub("", pattern_content)
        for category, pattern in (
            ("aws_account_id", ACCOUNT_RE),
            ("aws_arn", ARN_RE),
            ("email", EMAIL_RE),
            ("aws_access_key_id", ACCESS_KEY_RE),
            ("private_key", PRIVATE_KEY_RE),
        ):
            if pattern.search(pattern_content):
                result.findings.append(LeakFinding(path=path, category=category))
        for match in IPV4_RE.finditer(pattern_content):
            if self._is_public_ipv4(match.group(0)):
                result.findings.append(LeakFinding(path=path, category="public_ipv4"))
                break

    def _contains_public_ipv4(self, value: str) -> bool:
        return any(self._is_public_ipv4(match.group(0)) for match in IPV4_RE.finditer(value))

    def _is_public_ipv4(self, value: str) -> bool:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return False
        return parsed.version == IPV4_VERSION and not (
            parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified
        )
