from __future__ import annotations  # noqa: D100

import base64
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from unio_collector.protected_reports.constants import (
    PROTECTED_REPORT_PACKAGE_SIGNATURE_ALGORITHM,
    PROTECTED_REPORT_PACKAGE_SIGNED_PAYLOAD,
    PROTECTED_REPORT_PACKAGE_SIGNED_STATUS,
)
from unio_collector.protected_reports.key_fingerprint import fingerprint_public_key
from unio_collector.protected_reports.signature.payload import canonical_signed_payload

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.protected_reports.verification_options import (
        ProtectedReportVerificationOptions,
    )


class ProtectedReportPackageVerifier:
    """Verify protected report package Ed25519 signatures."""

    def verify(
        self,
        package: dict[str, Any],
        options: ProtectedReportVerificationOptions,
    ) -> bool:
        """Return true when the package signature verifies."""
        public_key = self._load_public_key(options.public_key_path)
        signature = package.get("signature")
        if not isinstance(signature, dict):
            return False
        if signature.get("status") != PROTECTED_REPORT_PACKAGE_SIGNED_STATUS:
            return False
        if signature.get("signature_algorithm") != PROTECTED_REPORT_PACKAGE_SIGNATURE_ALGORITHM:
            return False
        if signature.get("signed_payload") != PROTECTED_REPORT_PACKAGE_SIGNED_PAYLOAD:
            return False
        if options.expected_key_id is not None and signature.get("key_id") != options.expected_key_id:
            return False
        if signature.get("public_key_fingerprint") != fingerprint_public_key(public_key):
            return False
        signature_value = signature.get("signature")
        if not isinstance(signature_value, str):
            return False
        try:
            public_key.verify(
                base64.b64decode(signature_value.encode("ascii"), validate=True),
                canonical_signed_payload(package),
            )
        except (InvalidSignature, ValueError):
            return False
        return True

    def _load_public_key(self, path: Path) -> Ed25519PublicKey:
        key = serialization.load_pem_public_key(path.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            msg = "Protected report verification key must be an Ed25519 public key."
            raise ValueError(msg)
        return key
