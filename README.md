# Unio Collector

Unio Collector is Tevari Cloud's local, read-only evidence collector. The current
operational provider is AWS. It produces local evidence bundles for the separate
Unio analysis and reporting service. It does not perform automated remediation
or upload your evidence automatically.

The distribution and command are `unio-collector`; Python imports use
`unio_collector`. Install the collector in its own environment.

## Install and build

Use Python 3.12 or later. Native dependency locks target Python 3.12.10.
From this directory, create a virtual environment **outside** the source tree
and activate it. Then install the collector:

```console
python -m pip install . -c requirements/dev-constraints.txt
unio-collector --version
unio-collector --help
unio-collector package-plan --output ../collector-package-plan.json
```

To build the standalone wheel, install development dependencies into that
external environment and choose an output directory outside the source:

```console
python -m pip install ".[dev]" -c requirements/dev-constraints.txt
python -B -m tools.build_collector_wheel --output ../unio-collector-wheel
```

The wheel is built from the collector package plan. Its only console entrypoint
is `unio-collector`. Package installation may fetch public Python
dependencies; collection tests do not contact AWS.

The package plan distinguishes runtime imports from explicit public typing
contracts. Shared interfaces describe supplied metadata and collection hooks;
private finding, report and analysis implementations are not distributed.
Standalone package-facade interfaces expose only supported collector aliases.
Pyright checks those interfaces and all implementation modules. Its exclusions
apply only to the corresponding forwarding facades, whose unchanged runtime
files retain supported shared interfaces for the separate Unio application.

## Linux container

The reviewed public source also builds a CLI-only image for Linux amd64 and
arm64. Its Dockerfile uses a digest-pinned Python 3.12 Bookworm base, the
standalone collector wheel, and the hash-locked runtime dependencies in
`requirements/container-runtime.lock`. Build from an exact reviewed public
`v<version>` tag; set `COLLECTOR_VERSION`, `PUBLIC_SOURCE_SHA`, and
`PUBLIC_SOURCE_TAG` to that checkout's identity. A source clone can build
without private repository access. The Docker Hub release name is
`tevaricloud/unio-collector:v<version>`; published digest verification is
required before treating a tag as a release.

The image runs `unio-collector` as UID/GID `10001:10001`, with `/home/unio`
as home and `/work` as the working directory. Mount a host directory writable
by that UID for output. A read-only root filesystem is supported with a bounded
writable `/tmp` mount. For example, after verifying the image digest:

```console
docker run --rm --read-only --tmpfs /tmp:rw,nosuid,nodev,size=256m -v /example/output:/work:rw tevaricloud/unio-collector:v0.1.0 --version
```

For AWS collection, bind-mount `/example/aws` to the image user's `.aws` directory read-only
and select an existing profile with `--profile`. Standard boto3 environment,
temporary-session, web-identity, and container credential providers retain
their normal behavior. Environment credentials can be inspected by local
container/process administrators; they are not inherently more private than
mounted files. Offline fixture, bundle, privacy, version, and package-plan
commands need no AWS credentials.

Pass explicit mounted paths for `--config`, `--fixture`,
`--environment-alias-file`, and `--passphrase-file`. Keep protected bundles
and receipts in a transferable output mount; keep vault and recovery material
in a separate client-held private mount. Raw bundles are sensitive and should
be retained only through an explicit mounted output path. Temporary protected
collection state belongs on a bounded writable `/tmp` or an explicit
`--temporary-directory` mount. The existing privacy warnings and file
permission requirements also apply to mounted filesystems. Docker Desktop can
run the Linux CLI image on Windows or macOS; it is separate from the native
applications and has no GUI. SBOM and provenance attestations are release
evidence for the exact image digest, alongside container vulnerability scans.

## Collect evidence

For AWS collection, configure your own local AWS profile or role using your
normal credential process. Use least-privilege read access. Consult
`unio-collector collect --help`, `unio-collector doctor --help` and
`unio-collector policy aws --help` for supported profile, region, role and
permission options. Run doctor before collection. Never send AWS credentials to
Tevari Cloud.

This deterministic fixture example requires no AWS credentials:

```console
unio-collector collect --fixture tests/standalone/fixtures/cost.json --output ../fixture-bundle.zip --quiet
unio-collector validate-bundle ../fixture-bundle.zip
```

The fixture demonstrates service-cost evidence; it does not represent a complete
AWS inventory. Missing evidence and permission restrictions are limitations,
not clean results. Collection produces a local ZIP bundle with structured
evidence, coverage and integrity metadata. Private analysis and report generation
are separate services.

## Privacy

Use `unio-collector privacy --help` to preview and protect evidence before
sharing it. Protection is pseudonymisation, not a promise of anonymity. Costs,
utilisation and structural relationships can remain visible. Keep vaults,
passphrases, recovery material and restored output local; do not send them to
Tevari Cloud. Loss of required recovery material can make restoration impossible.

## Test and verify

```console
python -B -m tools.collector_repository verify --root .
python -B -m tools.collector_repository validate --root . --output ../unio-collector-validation
python -B -m tools.collector_repository native --root . --output ../unio-collector-native
```

Each validation output must be a fresh external directory. Validation creates
and removes isolated environments, checks source, builds the wheel and tests a
clean installation. Native validation additionally repeat-builds the payload,
checks its contents and launcher, creates the installer and requires malware
scanning. Windows needs WiX v5 and Defender; Linux needs Tcl/Tk, Xvfb, Debian
packaging tools and ClamAV; macOS needs Tcl/Tk, platform packaging tools and
ClamAV. Native builds are unsigned and require the matching operating system
and architecture. No production signing or notarisation is performed.

The manifest hashes the actual transformed public bytes. Publication applies
versioned path, Python token and reviewed terminology mappings to the approved
private source closure, then uses the reviewed Ruff pin for import/export ordering
and formatting before testing and building. Public files do not claim
byte identity with private source. Provenance records the originating commit,
source policy and transformation identity. Identical inputs produce identical
public contents; different source line endings can change the public digest.

`verify` checks an unchanged export, ignoring only root Git administrative
metadata. Edited development checkouts can still run `validate`, but cannot
claim pristine export identity. The manifest and provenance establish content
identity, not a digital signature or a licence grant.

This repository is a generated projection of Tevari Cloud's authoritative private
source, not an independently maintained source tree. Every publication candidate
must first pass Tevari's separate disclosure policy over the exact generated tree.
That gate blocks customer, organisation, AWS-resource, internal-network and local
workstation identifiers even when they are not credentials; its diagnostics retain
only a rule, relative location, redacted type and fingerprint. Public CI and every
publication candidate also pass Gitleaks over the complete current tree, including
generated metadata and transformed source. Historical-secret scanning is owned by
the authoritative source repository while all public source changes use the
controlled publication pipeline. If this repository later accepts direct human
commits, external pull requests, or any source change that bypasses that pipeline,
public Git-history scanning must be enabled before the first such change is
accepted.

## Licence and contributions

Unio Collector is source-available software under the
[Tevari Cloud Unio Collector Source-Available License, Version 1.0](LICENSE).
It is not open-source software. The exact terms are in `LICENSE`.
Export provenance records `licence_status: approved`, indicating that the
licence is approved for inclusion in this distribution; it does not assert
professional legal review.
Third-party dependencies retain their own licences. See
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) for the separate dependency evidence
and native-build notice contract.

See [CONTRIBUTING](CONTRIBUTING.md) and [SECURITY](SECURITY.md). Report security
vulnerabilities through the private route described in SECURITY. Native builds
are currently unsigned, and production signing or notarisation is not performed.
Tevari Cloud manages signing and release infrastructure separately where
applicable. Visit [Tevari Cloud](https://tevaricloud.com/) or use the
[contact page](https://tevaricloud.com/contact) for ordinary enquiries.

## Reproduce public CI

Python CI runs `python -B -m tools.collector_repository validate --root . --output <external-output>`.
It owns Ruff lint/format, Pyright, offline pytest, wheel build/install and the
mandatory Gitleaks control. Native CI runs the declared platform matrix,
installer and Defender/ClamAV validation; it also provisions Gitleaks first.

The separate security workflow runs
`python -B -m tools.collector_repository security --root . --output <external-output>`.
It owns Bandit, separate runtime and development/security pip-audit checks,
actionlint and offline/anonymous zizmor over every workflow. No AWS credentials,
private source or repository secrets are required. Dependency advisory lookup
requires network access and must succeed; vulnerabilities have no blanket waiver.
Security tools are validation-only, not collector runtime dependencies.

`requirements/ci-tools.json` records exact tool versions, reviewed release
SHA-256 digests, immutable action commits and narrow Bandit approvals. Before
validation, run `python -B -m tools.collector_repository provision --root . --output <external-bin-directory> --tools gitleaks actionlint`
and add that directory to PATH. Provisioning verifies release bytes before
extracting the one executable and rejects wrong versions. Scans do not download
binaries. Then run `python -B -m tools.collector_repository bootstrap --root .`;
it installs only the exact PyYAML pin from `requirements/dev-constraints.txt`
needed to load the validators. Gitleaks is pinned to 8.30.1 and uses
`requirements/secret-scanning.toml`. Security validation also runs that cheap
secret guard before other tools to protect independent-job diagnostics; it does
not repeat Python typing, tests or wheel builds.

Bandit includes source, tooling and tests, with medium-or-higher severity and
confidence; inline nosec is ignored. Three exact source-hash/rule/line approvals
cover authenticated release downloads, the signed-metadata HTTPS reader and
a temporary-path rejection literal.
Unused or changed approvals fail closed. Zizmor rejects medium-or-higher findings
at medium-or-higher confidence, without project config suppressions. Actionlint
checks every workflow; optional external ShellCheck/Pyflakes integrations are
disabled to avoid runner-dependent unpinned tools (Ruff owns Python lint).
All security failures are fatal. Scanner source snippets are not uploaded;
Gitleaks retains only its safe summary. CI retains bounded Python and native
diagnostics without broad artifact paths or AI review services.
