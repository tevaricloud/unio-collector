from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class CollectorForbiddenImport:
    """Actionable forbidden import discovered in the collector closure."""

    importing_module: str
    importing_file: str
    prohibited_module: str
    prohibited_prefix: str
    import_chain: tuple[str, ...]

    def convert_to_dict(self) -> dict[str, object]:
        """Return the JSON package-plan representation."""
        return {
            "importing_module": self.importing_module,
            "importing_file": self.importing_file,
            "prohibited_module": self.prohibited_module,
            "prohibited_prefix": self.prohibited_prefix,
            "import_chain": list(self.import_chain),
        }

    def format_message(self) -> str:
        """Return a deterministic validation error."""
        chain = " -> ".join(self.import_chain)
        return (
            "Forbidden collector import: "
            f"{self.importing_module} ({self.importing_file}) imports "
            f"{self.prohibited_module} matched by {self.prohibited_prefix}; "
            f"chain: {chain}"
        )
