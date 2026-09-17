from __future__ import annotations  # noqa: D100


def replace_schema_versions(payload: object, schema_version: str) -> object:
    """Replace nested bundle_schema_version fields in JSON-like payloads."""
    if isinstance(payload, dict):
        return {key: (schema_version if key == "bundle_schema_version" else replace_schema_versions(value, schema_version)) for key, value in payload.items()}
    if isinstance(payload, list):
        return [replace_schema_versions(item, schema_version) for item in payload]
    return payload
