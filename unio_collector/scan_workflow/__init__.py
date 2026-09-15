"""Scan workflow package wayfinding.

owns: scan orchestration, cached evidence runtime, scanner execution state, pricing enrichment, and progress/scope helpers.
must not import: CLI modules.
protects: scanner runtime contracts, read-only evidence flow, and workflow state boundaries.
start here: docs/scan-workflow.md, builder.py, aws/scan/, scanner/, and runner/.
focused tests: tests/scan_workflow and tests/architecture/test_scan_workflow_*.
"""
