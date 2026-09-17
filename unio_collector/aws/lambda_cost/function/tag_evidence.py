from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LambdaTagEvidence:  # noqa: D101
    state: str
    tags: dict[str, str] = field(default_factory=dict)
    limitation: str | None = None

    def __post_init__(self) -> None:
        """Validate and normalize the explicit collection state."""
        if self.state not in {"known", "unavailable", "not_collected"}:
            msg = f"Unsupported Lambda tag evidence state: {self.state}"
            raise ValueError(msg)
        normalized_tags = {str(key): str(value) for key, value in self.tags.items()}
        if self.state != "known" and normalized_tags:
            msg = "Unavailable or uncollected Lambda tag evidence cannot contain tags."
            raise ValueError(msg)
        object.__setattr__(self, "tags", normalized_tags)

    def convert_to_dict(self) -> dict[str, object]:  # noqa: D102
        return {
            "state": self.state,
            "tags": dict(self.tags),
            "limitation": self.limitation,
        }


__all__ = ["LambdaTagEvidence"]
