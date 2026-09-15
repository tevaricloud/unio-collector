from __future__ import annotations  # noqa: D100

import base64
import hashlib
import hmac
import json
from typing import TYPE_CHECKING, Any

from unio_collector.privacy.constants import TOKEN_FORMAT_VERSION

TOKEN_PREFIXES = {
    "aws_account_id": "ACCOUNT",
    "arn": "ARN",
    "resource_id": "RESOURCE",
    "resource_name": "RESOURCE",
    "iam_role": "ROLE",
    "ipv4": "IPV4",
    "ipv6": "IPV6",
    "cidr": "CIDR",
    "dns_name": "DNS",
    "hostname": "DNS",
    "email": "EMAIL",
    "bucket_name": "BUCKET",
    "tag_key": "TAG",
    "tag_value": "TAG",
    "free_text": "RESOURCE",
    "url": "DNS",
}

if TYPE_CHECKING:
    from unio_collector.privacy.canonicalization import CanonicalValue
    from unio_collector.privacy.token.domain import TokenDomain


class TokenV1Codec:
    """Encode the stable token-v1 HMAC contract."""

    def candidate(
        self,
        *,
        token_key: bytes,
        provider: str,
        domain: TokenDomain,
        canonical: CanonicalValue,
        collision_index: int,
        suffix_bytes: int,
    ) -> str:
        """Return a typed token while preserving the historical wire payload."""
        payload: dict[str, Any] = {
            "token_format_version": TOKEN_FORMAT_VERSION,
            "provider": provider,
            "category": canonical.category,
            "token_scope": domain.token_scope,
            "engagement_id": domain.scope_boundary_id,
            "canonicalization_version": canonical.version,
            "canonical_value": canonical.value,
            "collision_index": collision_index,
        }
        digest = hmac.new(
            token_key,
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        suffix = base64.b32encode(digest[:suffix_bytes]).decode("ascii").rstrip("=")
        return f"{TOKEN_PREFIXES.get(canonical.category, 'RESOURCE')}-{suffix}"
