from __future__ import annotations  # noqa: D100

from pydantic import BaseModel, ConfigDict


class UnioBaseModel(BaseModel):
    """Base pydantic model for strict structured Unio data."""

    model_config = ConfigDict(
        extra="forbid",
    )
