# Contributing

Use synthetic fixtures and offline tests. Do not add live AWS calls to tests or
change collection into a mutation workflow. Preserve command names, bundle
schemas and provider boundaries unless a change is explicitly reviewed.

Run the standalone validation command in the README. It checks Ruff formatting
and lint, Pyright, the bounded public suite, wheel construction and an isolated
installation. Choose external build, cache and test output directories.

Keep changes small and explain behaviour and validation in the pull request.
Report security issues through the private process in SECURITY.md. Contributions
are subject to maintainer review and the contribution terms in [LICENSE](LICENSE); this file
does not introduce contribution licence terms.

Export provenance describes the originating source snapshot. Do not rewrite it
to claim that edited code matches an original export. Manifest and provenance
verification establishes content identity; it does not authorize publication,
mirroring or release.
