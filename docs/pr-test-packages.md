# Approved unsigned PR test packages

This is test distribution only. It does not sign, publish, install, execute or
promote packages into the production release workflow. Existing dispatch output
names and gates remain unchanged. Forks, draft PRs, bot contexts and PRs without
the opt-in label never enter this retention path.

## Configuration prerequisites (operator action; not performed by implementation)

Read-only inspection on 2026-10-22 found no environments in the public collector
repository. The private production environment has no required reviewer rule and
allows administrator bypass; it is unsuitable and must not be reused. The public
repository has one admin and one write-role collaborator. The implementation
requires a configured individual with maintain or admin permission. A sole
maintainer may author, trigger and explicitly approve this unsigned test flow.
This is single-maintainer authorisation, not independent two-person review.

An administrator must configure the following in the PUBLIC collector repository:

1. Review and make available an immutable public control commit containing this
   exact native workflow and all `tools/test_packages/*.py` modules. This bootstrap
   publication is separate work and is not authorised by a local implementation.
   There is no workflow bootstrap cycle: after the required source/export review,
   make the reviewed public projection available on a branch without opening an
   opted-in PR, then configure its full public SHA before the next authorised PR
   run. This native workflow has no push trigger. The control commit must contain
   the current controller and matching workflow, not an older control revision.
2. Set repository Actions variable `UNIO_TEST_RETENTION_CONTROL_SHA` to that full
   public commit SHA. It is not a branch or the private source SHA. Each request
   and approval job checks out this pin, disables persisted checkout credentials,
   and executes its absolute CLI with `python -I -B`. The local selector checks
   the control modules and workflow against its own explicitly reviewed source.
3. Create environment `unsigned-pr-test-packages`. Add explicit individual User
   reviewers with maintain/admin permission, including the sole maintainer.
   For sole-maintainer operation, configure **Prevent self-review** OFF in this
   dedicated test environment and disable **Allow administrators to bypass
   configured protection rules**. Existing stricter GitHub protections are still
   honoured: a true self-review restriction is recorded and never bypassed by
   this tool; it may require another eligible reviewer to approve the deployment.
   Configure no environment secrets. Do not attach production signing identities,
   production environments or write permissions. Permit the PR merge ref to use
   this environment (no branch restriction is acceptable for this secret-free
   gate; the code independently restricts eligible PR contexts).
4. Allow the workflow's read-only contents, Actions and pull-request metadata
   permissions and normal artifact upload/download actions. Ensure the operator's
   existing `gh` authentication can read repository, environment/review history,
   collaborator permissions, run/job/artifact metadata and exact source blobs.
5. Verify the environment API reports a nonempty `required_reviewers` rule,
   an explicit boolean `prevent_self_review` (false for sole-maintainer use) and
   `can_admins_bypass: false`. Missing, inaccessible or inadequate configuration
   fails closed. No live setting is changed by the tooling.

The authenticated approver must be an eligible configured maintainer, and may
also be the PR author, original run actor or rerun actor. Approval remains a
separate deliberate action quoting the fresh challenge; a label or merely
starting a run is insufficient. This sacrifices independent scrutiny, not exact
identity binding or automated acceptance. Production environments, reviewer rules,
signing and release approval remain unchanged. The opt-in label
`retain-unsigned-test` is only a request.
Add it BEFORE the next otherwise-required PR validation run. Adding a label does
not dispatch a workflow or recover bytes already discarded by an older run.

## Approval and job dependencies

`source` remains the existing exhaustive eight-shard matrix. A separate hosted
`retention-request` job runs only for opted-in eligible PRs, verifies configuration
and candidate metadata, and retains a seven-day `request.json`. Its fresh random
challenge covers repository, run/attempt, PR head/base, actual merge checkout and
Git tree, execution workflow revision/hash, immutable control SHA, private source,
projection, application version and configured reviewer identities.

`retention-approval` depends on that request and references the protected
`unsigned-pr-test-packages` environment. GitHub holds this job server-side for
review; no packaging runner is allocated while waiting. Review the exact context
in the request job summary and paste its full `UNIO-TEST-APPROVE <digest>` line
into the deployment approval comment. Clicking Approve without the exact comment
fails the subsequent API check. The history API is run-scoped, so the fresh
unpredictable challenge and current-attempt request artifact are essential;
review history alone does not prove approval of a particular rerun.

The four `native` jobs depend on source, request and approval, retain their
`always()` source-failure guard, and do not request an environment themselves.
Ordinary non-opted-in PRs and dispatches skip both retention jobs, so normal
validation does not wait for approval. For opted-in PRs a pending protected
approval holds all four native jobs before runner allocation; source validation
and separate Python/security workflows can continue. After a terminal request or
approval failure/rejection, `native: always()` still runs the existing validation
and packaging if source validation succeeded. Every PR retention step additionally
requires the verified `approved=true` output, so a failed/rejected approval cannot
retain packages. Failed approval jobs are not ignored: the overall workflow fails
and the selector rejects it even if all native validation jobs pass.

Candidate head/base, control pin or reviewer configuration changes invalidate
approval. Reruns require a new request/challenge and all source/native jobs from
one new attempt. Partial-job reruns cannot assemble eligible evidence from prior
attempts. No `pull_request_target`, `workflow_run`, signing secret or privileged
cross-run execution is introduced.

## Exact-byte retention

After existing source-transfer, installed-wheel, repeated native build, smoke,
installer and required malware checks pass, an approved PR job COPIES the existing
manifest-listed packages and structured proofs into a packet. It never rebuilds,
repackages or changes an installer. Manifest membership includes platform
portable formats such as `.tar.gz`, not just Windows ZIP/MSI files.

Artifact names are `unsigned-test-request-<run>-<attempt>` and
`unsigned-test-<target>-<run>-<attempt>`, with seven-day retention. Each target
packet contains both original source-shard proofs/summaries/wheels, the aggregate
source proof, terminal native/wheel results, lock evidence, installer metadata,
malware evidence and every manifest-listed asset. These copies remain available
for seven days even after intermediate three-day transfer/diagnostic artifacts
expire. Optional timing diagnostics retain their separate existing contract.
No raw success logs are added to these packets.

Artifact upload failure is an evidence/distribution failure, not permission to
skip checks or issue a verification receipt. Expired, missing or incomplete
packets require a new otherwise-authorised validation; there is no silent rebuild,
substitute artifact, tree-only reuse or production promotion fallback.

## Trusted local selection

Use a reviewed, clean regular local checkout at an explicitly selected full SHA.
Run on Windows with existing dependencies, Git, authenticated `gh` and host
PowerShell. The selector independently reads the actual MSI database in read-only
OpenDatabase mode 0; it never runs Windows Installer installation APIs. The
absolute isolated script excludes CWD, PYTHONPATH and user-site imports. Host
executables are resolved from absolute host PATH entries, excluding CWD and the
source tree; downloaded binaries are never used as tools.

```powershell
& '<existing-python>' -I -B '<reviewed-checkout>/tools/test_packages/__main__.py' select `
  --repository '<owner>/<public-repository>' --trusted-source-sha '<reviewed-local-sha>' `
  --run-id <native-run> --attempt <attempt> `
  --python-run-id <python-run> --security-run-id <security-run> `
  --output-parent '<external-manual-test-parent>'
```

The selector authenticates metadata through read-only GET requests using existing
`gh` credentials. It requires the complete four-platform native/source matrix and
explicit successful Python/security runs for the same PR head/base. It rechecks
live candidate and approval metadata, binds each packet's job ID to the current
attempt's actual jobs, verifies GitHub artifact IDs/digests/expiry, and compares
reviewed workflow/control code, projection, hash lock and installer policy bytes.
Packet assertions remain claims until those independent comparisons succeed.

Every outer ZIP is completely streamed through safe-name, duplicate, link,
encryption, CRC/hash and size checks BEFORE extraction. Exact admissible membership
is checked from the finite packet contract; no artifact module is imported.
Limits are 2 GiB compressed download, 4 GiB expanded packet, 12,000 files, 512 MiB
per member and a 500:1 per-member compression ratio. Unsupported/oversized input
fails closed. Extraction and inspection use labelled external disposable state.

Only a complete successful selection creates
`UNSIGNED-TEST-<version>-<private-sha-prefix>-run<id>-attempt<n>`, including all
four verified packets, `VERIFICATION-RECEIPT.json` and `READ-ME-FIRST.txt`. Existing
destinations are preserved. Receipt generation occurs after read-only MSI metadata
comparison and copied-file verification. Hashes, ProductCode, PackageCode and
reviewed test revision remain those of the ORIGINAL installer. A newly built
candidate needs an explicitly reviewed unused test revision before its first
build; selecting the same bytes must not manufacture new identities. The stable
UpgradeCode and existing rollback/equal-version/downgrade rules remain required.

## One combined acceptance boundary

The implementation starts at the committed native smoke optimisation. Its focused
evidence is retained, but its broader acceptance is still pending. Once this
combined tree and source-bound export metadata are stable, inspect `dev affected`
and execute its deduplicated applicable source-stability/owning/domain checks,
including collector/native and one canonical full-clean at the final identity.
Do not run a separate broad cycle merely to accept the smoke optimisation first;
do not manually waive classifier or release requirements.

Prerequisites: reviewed control commit, repository variable, secret-free protected
environment and eligible maintainer (self-review permitted for this test flow).
Minimum hosted proof is one
explicitly authorised opted-in same-repository PR run completing all eight source
shards and four native targets, plus its applicable Python/security results.
Retain and select its original bytes without another build. Demonstrate the
non-opted/fork guard and stale-challenge rejection without executing untrusted
packages. Local synthetic tests do not establish GitHub's deployment scheduling,
permission availability, transport layout or the end-to-end saved build cycle.
Hosted/security/publication, native platform and installed/manual lifecycle gates
remain distinct. The existing failed frozen run remains historical evidence.
