"""Scanners package wayfinding.

owns: scanner classes, registry, built-in definitions, packs, options, permission summaries, and scanner helpers.
must not import: report renderers, redaction writers, CLI modules, or sales/report prose layers.
protects: deterministic findings/evidence, scanner IDs, registry metadata, and read-only scanner behavior.
start here: docs/scanner-authoring.md, registry/definitions/, scanner/module/catalog.py, and relevant scanner family packages.
focused tests: scanner-marked tests and scanner architecture tests.
"""
