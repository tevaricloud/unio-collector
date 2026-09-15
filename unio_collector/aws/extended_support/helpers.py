from __future__ import annotations  # noqa: D100


def optional_str(value: object) -> str | None:  # noqa: D103
    if value in (None, ""):
        return None
    return str(value)


def build_ec2_arn(  # noqa: D103
    region: str,
    account_id: str,
    resource_type: str,
    resource_id: str,
) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:{resource_type}/{resource_id}"


def chunk_values(values: list[str], size: int) -> list[list[str]]:  # noqa: D103
    return [values[index : index + size] for index in range(0, len(values), size)]
