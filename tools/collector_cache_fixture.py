"""Actual shared cache/deadline callback producers with synthetic local inputs."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from unio_collector.scan_workflow.evidence.service import EvidenceCollectionBase
from unio_collector.scan_workflow.scanner.runtime.cancellation_error import ScannerDeadlineExceededError


def actual_cache_notes(scanner: str, kind: str = "hit") -> list[dict[str, Any]]:
    """Invoke the unchanged exported producer, not a rewritten note DTO."""
    if kind not in {"loaded", "hit", "waited", "deadline"}:
        message = "Unsupported synthetic cache callback variant."
        raise ValueError(message)
    notes: list[dict[str, Any]] = []
    runner: Any = SimpleNamespace(
        add_scanner_coverage_note=lambda _scanner, note: notes.append(note), cancellation_token=SimpleNamespace(is_cancelled=lambda: kind == "deadline")
    )
    producer = EvidenceCollectionBase(runner)
    if kind == "deadline":
        try:
            producer.raise_if_deadline_expired(scanner, namespace="lambda_function_inventory", label="Lambda function inventory")
        except ScannerDeadlineExceededError:
            pass
        else:
            message = "Actual deadline producer did not abort the synthetic request."
            raise AssertionError(message)
    else:
        producer.add_cached_evidence_note_for_scanner(scanner, namespace="lambda_function_inventory", label="Lambda function inventory", access_status=kind)
    return notes


def add_cache_producer_notes(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Exercise actual shared callback kinds in the same packaged producer input."""
    member = "scan-result/scanner-results.json"
    value = json.loads(files[member])
    found = set()
    for row in value["scanner_results"]:
        scanner = row["scanner_id"]
        if scanner not in {"athena-query-efficiency-review", "ecs-cost-governance-review"}:
            continue
        found.add(scanner)
        notes = [note for kind in ("hit", "waited", "deadline") for note in actual_cache_notes(scanner, kind)]
        if unknown:
            notes[0]["unknown_cache_control"] = None
        row["coverage_notes"].extend(notes)
    if found != {"athena-query-efficiency-review", "ecs-cost-governance-review"}:
        message = "Packaged cache fixture lost its actual collector parents."
        raise ValueError(message)
    files[member] = json.dumps(value, indent=2, sort_keys=True).encode()
