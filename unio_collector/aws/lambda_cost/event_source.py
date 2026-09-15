from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class LambdaEventSourceRecord:  # noqa: D101
    source_type: str
    source_arn: str | None
    uuid: str | None
    state: str | None
    batch_size: int | None

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            "source_type": self.source_type,
            "source_arn": self.source_arn,
            "uuid": self.uuid,
            "state": self.state,
            "batch_size": self.batch_size,
        }
