"""Normalize observed S3 public access response fields without finding policy."""

from __future__ import annotations

PUBLIC_ACCESS_BLOCK_KEYS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

PUBLIC_ACL_GROUP_URIS = frozenset({"http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"})


def normalize_public_access_block(value: object) -> dict[str, bool] | None:
    """Keep complete boolean settings; malformed or missing values are unknown."""
    if not isinstance(value, dict) or any(not isinstance(value.get(key), bool) for key in PUBLIC_ACCESS_BLOCK_KEYS):
        return None
    return {key: value[key] for key in PUBLIC_ACCESS_BLOCK_KEYS}


def is_public_acl_grant(grant: object) -> bool:
    """Identify the provider's public ACL group URIs."""
    if not isinstance(grant, dict):
        return False
    grantee = grant.get("Grantee", {})
    if not isinstance(grantee, dict):
        return False
    uri = grantee.get("URI")
    return isinstance(uri, str) and uri in PUBLIC_ACL_GROUP_URIS


def observed_public_acl_grant(grant: object) -> bool | None:
    """Distinguish known public grants, known nonpublic grants and missing facts."""
    if not isinstance(grant, dict):
        return None
    permission = grant.get("Permission")
    if not isinstance(permission, str) or permission not in {"FULL_CONTROL", "WRITE", "WRITE_ACP", "READ", "READ_ACP"}:
        return None
    grantee = grant.get("Grantee")
    if not isinstance(grantee, dict):
        return None
    kind = grantee.get("Type")
    if kind == "Group":
        uri = grantee.get("URI")
        if not isinstance(uri, str):
            return None
        if uri in PUBLIC_ACL_GROUP_URIS:
            return True
        return False if uri == "http://acs.amazonaws.com/groups/s3/LogDelivery" else None
    identity_key = "ID" if kind == "CanonicalUser" else "EmailAddress" if kind == "AmazonCustomerByEmail" else None
    identity = grantee.get(identity_key) if identity_key is not None else None
    return False if isinstance(identity, str) and identity else None
