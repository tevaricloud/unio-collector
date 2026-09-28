# Contributing

This repository is a generated projection of Tevari Cloud's authoritative private
source. Its pull requests are reserved for the controlled publication pipeline;
direct source-changing pull requests and commits are not accepted here. Use the
issue forms for non-sensitive bugs and feature requests, and use the private route
in SECURITY.md for vulnerabilities.

Maintainers validate every generated publication candidate with the standalone
commands in the README. Before materialization, the private publication pipeline
checks the exact generated tree with Tevari's customer-data disclosure policy and
Gitleaks as separate mandatory controls. It also runs Ruff formatting and lint,
Pyright, the bounded public suite, wheel construction and an isolated installation.
Use documented synthetic example namespaces; never add customer or internal
identifiers to fixtures. Build, cache and test output directories remain external.

If this repository later accepts direct human commits, external pull requests, or
other source changes outside the controlled publication pipeline, public Git-history
scanning must be enabled before the first such change is accepted. Any future
contribution remains subject to maintainer review and the terms in
[LICENSE](LICENSE); this file does not introduce contribution licence terms.

Export provenance describes the originating source snapshot. Do not rewrite it
to claim that edited code matches an original export. Manifest and provenance
verification establishes content identity; it does not authorize publication,
mirroring or release.
