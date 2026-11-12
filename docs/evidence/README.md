# Real-world workflow examples

This directory applies SameByte to release pipelines of public projects. It
shows what the tool can establish in workflows it was not written for, and how
to read a report whose coverage is incomplete. Most of these pipelines are
larger than the analysis supports, so expect `unknown` results and many coverage
notices; that is the point of the examples.

The collection contains nine workflows from five repositories, each pinned to
the commit linked in its section. Analysis is local and static: upstream
workflows, actions, scripts, builds, and deployments are never executed. For
small workflows with fully proven lineage, see the fixtures in
[`tests/fixtures`](../../tests/fixtures).

## Files and report layout

Each repository directory contains:

- `provenance.json`: repository, full commit, source URLs, and SHA-256 checksums.
- `upstream/`: unchanged workflow files and related composite action metadata.

`reports/` contains the saved results of the current analyzer. Each workflow has
a JSON report with the command that produced it and its exit code, plus `check`
and `explain` text output. `reports/summary.json` lists operation identities,
deployments, findings, errors, and the number of coverage notices for every
workflow. A test compares the saved reports with a fresh replay, so they always
match the code in this repository.

Notice counts are not percentages and do not count hidden operations. Exit code
`0` does not prove that an entire release pipeline was verified.

Composite action files provide context for the dependency maps below. The CLI
analyzes workflows, not standalone action metadata. A caller is followed one
level into a local reusable workflow stored next to it under
`upstream/.github/workflows`; remote and nested calls are not expanded. Each
workflow file is also replayed by itself, and analyzing a callee separately does
not connect its operations to a caller.

## Reproduce the reports

From a repository checkout with Node.js 22 or later and installed dependencies:

```sh
npm run build
node docs/evidence/replay.mjs /tmp/samebyte-reports
diff -r docs/evidence/reports /tmp/samebyte-reports
```

The replay tool validates every saved source checksum, then invokes SameByte for
each workflow. It writes only to the output directory and executes no upstream
code. Reports normalize checkout prefixes and file-dependent symbolic namespaces
so that they can be compared across machines. Inputs and identity relationships
are unchanged by this normalization.

An optional second argument selects a different CLI bundle, for example one
built from another revision. To analyze a single workflow directly:

```sh
node dist/cli.js docs/evidence/nvidia-aicr/upstream/.github/workflows/on-tag.yaml --format json
```

## Reading the examples

The dependency maps come from the saved YAML and describe declared commands and
execution gates. They do not assert runtime success or inspect registry contents.
SameByte results describe only detected operations. A manually visible operation
inside an opaque script or composite can remain absent from the analyzed graph;
its boundary notice explains that limitation.

## NVIDIA/aicr

Commit [bd1414f070e9711e23db29f43ab66b9dfbd1bf19](https://github.com/NVIDIA/aicr/tree/bd1414f070e9711e23db29f43ab66b9dfbd1bf19).
Inputs: `on-tag.yaml`, `qualification.yaml`, `attest-images.yaml` and four relevant
local composite action files, all listed in provenance. No `deploy.yaml` exists
at this revision, so the observed release/promotion chain is evaluated instead
of inventing a cluster deployment.

Manual operation and execution map, from the inspected YAML and action bodies:

```text
detect -> candidate tag (shell outputs)
tests -> qualification.yaml
         -> go-test (make test), lint, CLI e2e, e2e, security actions
         -> e2e action builds separate local ko/Docker images, then runs a script
[detect, tests] -> build-ko (go-build-release -> make release)
[detect, tests] -> build-docker (phase x architecture build-push template)
[detect, tests] -> build-gate (architecture build-push template)
[detect, build-docker, build-gate] -> docker-manifest (imagetools index creation)
[detect, build-ko, docker-manifest] -> resolve-candidates (script -> JSON digest map)
resolve-candidates -> image-vuln-scan (image x platform matrix, fromJSON lookup)
[detect, image-vuln-scan, resolve-candidates] -> attest-images.yaml
   -> validate-inputs -> attestation matrix -> attest-image-from-tag composite
   -> validates expected index digest; resolves separate platform digests
   -> invokes sbom-and-attest (nested action, not inspected here)
[resolve-candidates, image-vuln-scan, attest] -> release-check (always(), shell gate)
[detect, resolve-candidates, release-check] -> promote-images (preflight/promote scripts)
[detect, promote-images] -> publish (publication script)
```

This map records calls and commands, not runtime success. The `always()` release
check explicitly rejects non-success dependency results in shell; SameByte does
not evaluate that script as an unconditional execution gate. E2E-built images
are not proven identical to later release images. Index and per-platform digest
resolution are separate operations in the inspected attestation composite.
The implementation and behavior of nested actions and release scripts have not
been inferred from their names.

`on-tag.yaml`: **3 operations**, all identity `unknown`: build templates at
lines 413 and 534, and the Anchore scan template at line 729. No deployments,
findings, or errors; exit `0`. Separately analyzed qualification and attestation
workflows each yield zero operations, deployments, findings, and errors.

Both local calls are expanded, so the 19 boundaries inside the callees (14 in
qualification, 5 in attestation) are reported with their callee location and
call site. `on-tag.yaml` has **97 boundary notices**: 34 local action calls, 28 other opaque actions, 4 strategy
boundaries, 27 complex shell boundaries, and 4 uninterpreted command boundaries.
Analyzed alone, qualification has **14** notices and attestation **5**.
These are boundary counts, not missing-operation counts or coverage percentages.

Expansion does not add an operation here. The `tests` call passes no inputs, so
the callee's three inputs take their declared defaults; its jobs only run local
composite actions. The `attest` call passes `candidate_tag` and `digest_map`,
both unknown because the caller writes them from complex shell; the callee
validates them in shell, fans out over a matrix, and attests through a local
composite. Neither callee declares workflow outputs.

The coverage notices identify these limits: local composites hide producers and
consumers; matrix instances are not expanded; digest-map construction,
`fromJSON`, dynamic indexing, registry inspection, manifest assembly, shell
gates, and promotion remain unsupported. The analyzed caller therefore has no
proven consumer identity or recognized deployment for this release chain.

## prebid/salesagent

Commit [08e3d8c16f627ce1299bdfb7d0a6bf3976e4448e](https://github.com/prebid/salesagent/tree/08e3d8c16f627ce1299bdfb7d0a6bf3976e4448e).
Input: `.github/workflows/release-please.yml`.

Manual operation and execution map:

```text
release-please -> release_created/version outputs (opaque release action)
release_created condition -> build-and-push:
  external CI run queried in shell (source revision gate, cross-run)
  SOURCE_DATE_EPOCH computed in shell
  amd64 preliminary build -> Trivy on local amd64 tag (exit-code 1)
  arm64 preliminary build -> Trivy on local arm64 tag (exit-code 1)
  separate multi-platform publication build -> job image_digest output
[release-please, build-and-push] + release_created condition -> sign-and-attest:
  cosign signing loop -> bundle upload -> two provenance attestations
  -> scan published digest (exit-code 0, reporting rather than vulnerability gate)
```

Result: **8 operations**. Three builds (lines 115, 137, 161) have
unknown identity because the job is conditional; the last also builds multiple
platforms. Two pre-push scans (128, 150) use mutable local tags. Two attestations
(238, 243) and the published scan (248) have unknown identities. Inputs such as
`github.repository`, secrets, metadata action outputs, and the guarded build
output are unresolved. No supported deployments, findings, or errors; exit `0`.
There are **17 notices** (13 opaque action calls, 4 complex shell
boundaries), and each unknown operation carries its explanation.

The pre-push builds are distinct producers from the publication build. Their
byte relationship is unknown, even with shared build arguments or caches; there
is no concrete unequal-digest evidence. The reporting scan is not a guaranteed
vulnerability policy gate. The scan adapter tracks artifact identity, not vulnerability policy.
Cross-run CI evidence, signing scripts, metadata, and platform-manifest selection
remain outside scope. The absence of a deployment in this release workflow is
distinct from an unresolved detected deployment and is not a pipeline violation.

## liatrio/demo-autogov-hello-world-app

Commit [57bf1b1498271c6d97d4c68d7258b9e7a402f8d1](https://github.com/liatrio/demo-autogov-hello-world-app/tree/57bf1b1498271c6d97d4c68d7258b9e7a402f8d1).
Inputs: `cw-build-image.yaml` and `.github/actions/build-image/action.yaml`.

Manual map: caller job `attest-image-hp` calls the pinned remote
`liatrio/demo-gh-autogov-workflows/.../rw-hp-build-image.yaml`. The local composite
contains conditional semantic versioning, metadata, QEMU/Buildx/login setup,
and a two-platform build-push producer. Its `image-digest` output forwards
`steps.build-image.outputs.digest`; it also writes an OCI archive. The caller
does not directly invoke the composite. The route from the remote callee to
that composite cannot be established from the inspected files alone. The
composite's description describes the intended route, not executed evidence.

Result: **0 operations**, deployments, findings, and errors; exit `0`, with
**1 reusable-workflow boundary** carrying the exact remote call target and its
line 21. The composite producer is manually
observed but remains outside the analyzed workflow graph. It is not fabricated
as a detected caller build. The remote call and composite are separate coverage
boundaries. Multi-platform runtime identity also requires manifest evidence
that is absent from the saved workflow files.

## music-assistant/server

Commit [a737359e2651fd02fbfc5b3862b8bfcd5bde3edb](https://github.com/music-assistant/server/tree/a737359e2651fd02fbfc5b3862b8bfcd5bde3edb),
pinned in provenance.
Inputs: `.github/workflows/release.yml` and `test.yml`.

The call relationship is simpler than NVIDIA's digest-map/attestation chain:
`resolve -> preflight (local test.yml, ref input) -> build_artifacts -> prepare_draft
-> exact_image`. Preflight is conditional on the release not already being
published; the release workflow also has explicit published-release recovery
paths. The callee performs lint and pytest in a pinned **base** container, with
dynamic shard selection and a final status check. That base container is not the
published application image. `exact_image` conditionally builds the application
for two platforms; further manifest checks and promotion are shell/script logic.
This is a source-test gate, not an OCI test of the publication output.

Result: release has **1 unknown build** (line 914); test workflow has zero
supported operations. Both have zero supported deployments, findings, and
errors, and exit `0`. Release has **94 notices**: the preflight call is
expanded, so the 19 notices of the callee test workflow appear next to 75 in
the caller, including a local release-notes
action. Both passed inputs (`ref`, `base_image_version`) are unknown because the
caller derives them in complex shell. Analyzed alone, the test workflow has
**19** notices.
The preflight job tests source code in a base container rather than the published
application image. Its script execution, recovery paths, and conditional
multi-platform build do not establish an OCI test of the publication output.

## falcosecurity/falcoctl

Commit [eb5bf8b132ef047e7f3e830866a16dfb759470aa](https://github.com/falcosecurity/falcoctl/tree/eb5bf8b132ef047e7f3e830866a16dfb759470aa),
the head of `main` when the case was added.
Inputs: `.github/workflows/release.yaml` and its local callee `docker-image.yaml`.

This is a small caller/callee pair that returns an OCI digest through a
workflow output:

```text
docker-configure -> release, commit, build_date (shell outputs)
docker-configure -> docker-image (local docker-image.yaml; four scalar inputs)
   -> docker/build-push-action, linux/amd64 + linux/arm64
   -> job output digest -> workflow output digest
   -> optional cosign signing in shell (inputs.sign)
[docker-configure, docker-image] -> two remote SLSA container generator calls,
   each with digest: needs.docker-image.outputs.digest
```

`release.yaml`: **1 operation**, the build inside the callee at
`docker-image.yaml` line 79, reported as job `docker-image / docker-image` with
call site `release.yaml` line 111. The call is expanded. `sign` resolves to the
literal `true`; `release`, `commit`, and `build_date` are unknown because the
caller writes them in a shell step outside the supported interpreter. The workflow output `digest`
is traced `steps.build-and-push.outputs.digest` -> job output `digest` ->
`jobs.docker-image.outputs.digest` (`docker-image.yaml` line 21) ->
`needs.docker-image.outputs.digest` in the caller.

The value on that path is unknown, and the report says why: the build is
multi-platform, so the digest names an index and the child manifest is not
tracked. No supported deployments, findings, or errors; exit `0`. There are
**24 notices**: 15 in the caller, including the three remote reusable calls and
the unresolved `secrets: inherit`, and 9 inside the callee (8 opaque actions and
the signing shell step). The remote generator calls that consume the digest stay
opaque, so no attestation operation is detected. Analyzed alone,
`docker-image.yaml` has the same build with unknown inputs and 9 notices.

A complete chain with proven test, scan, and attestation through a callee is
covered by the controlled fixtures under `tests/fixtures/reusable/`, not by this
upstream example.

## Analysis limits

Local reusable workflow calls are expanded one level; remote and nested calls
remain boundaries. In these examples, expansion makes the boundaries inside the
callees visible but leaves composite actions, shell logic, dynamic expressions,
matrix instances, and platform selection unresolved.

Independent builds are not proven to produce different bytes. A multi-platform
index is not proof that a particular runtime manifest was tested. Conditional
checks, ignored failures, and opaque shell gates do not establish unconditional
verification. These limitations describe the available evidence, not defects in
the upstream projects.

The examples do not verify registry contents, upstream runtime success,
cross-run lineage, signatures, vulnerability policy, or cluster deployment.
They complement the regression tests, which also cover proven supported chains,
concrete mismatches, annotations, output formats, and analysis errors. Run
`npm test` from the repository root to validate these behaviors and the saved
source checksums.
