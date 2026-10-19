"""Partition only fully admitted shared callbacks from family-specific note checks."""

from __future__ import annotations

from unio_collector.privacy.cache.notes import CacheNoteContract


class CacheNotePreflight:
    """Validate shared notes first while leaving every malformed note in normal checks."""

    @classmethod
    def partition(cls, value: object, member: str, failures: list[str]) -> object:
        """Return an isolated preflight view; never mutate actual producer inputs."""
        if member != "scan-result/scanner-results.json" or not isinstance(value, dict) or not isinstance(value.get("scanner_results"), list):
            return value
        rows = [cls._row(row, member, failures) for row in value["scanner_results"]]
        return {**value, "scanner_results": rows}

    @staticmethod
    def _row(row: object, member: str, failures: list[str]) -> object:
        """Exclude only known, complete, parent-bound callbacks already admitted."""
        if not isinstance(row, dict) or not isinstance(row.get("coverage_notes"), list):
            return row
        remaining = []
        for note in row["coverage_notes"]:
            selected = CacheNoteContract.for_note(note) if isinstance(note, dict) else None
            if selected is None:
                remaining.append(note)
                continue
            contract = CacheNoteContract.for_parent(note, row.get("scanner_id"), row.get("provider_id", "aws"))
            errors = contract.unknown_paths(note, member) if contract is not None else [member + CacheNoteContract.prefix[1:] + ".identity"]
            failures.extend(errors)
            if errors:
                remaining.append(note)
        return {**row, "coverage_notes": remaining}
