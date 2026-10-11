# Real-world workflow examples

These examples show what SameByte can establish from GitHub Actions release
pipelines and how to interpret incomplete coverage. The collection contains
seven workflows from four repositories, pinned to the commits linked below.
Analysis is local and static: upstream workflows, actions, scripts, builds, and
deployments are never executed by the replay tool.

## Files and report layout

Each repository directory contains:

- `provenance.json`: repository, full commit, source URLs, and SHA-256 checksums.
- `upstream/`: unchanged workflow files and related composite action metadata.

`baseline/` contains results from SameByte commit
`e28803445e42bfe32a5cb8e90436cbd5eb868708` (version `0.1.0`). `updated/` contains
results for the analysis behavior described in this documentation. Each workflow
has a JSON report with its invocation and exit code, plus `check` and `explain`
text output. Each set also has a `summary.json` with operation identities,
deployments, findings, errors, and, when available, coverage boundaries.

The comparison illustrates a reporting change: supported operation identities
are preserved while unsupported boundaries become visible. Boundary counts are
not percentages and do not count hidden operations. Exit code `0` does not prove
that an entire release pipeline was verified.

Composite action files provide context for the dependency maps below. The CLI
analyzes workflows, not standalone action metadata, and does not expand local or
remote reusable workflows. Analyzing a callee separately does not connect its
operations to the caller.

## Reproduce the reports

From a repository checkout with Node.js 22 or later and installed dependencies:

```sh
npm run build
node docs/evidence/replay.mjs /tmp/samebyte-updated
diff -r docs/evidence/updated /tmp/samebyte-updated
```

The replay tool validates every saved source checksum, then invokes SameByte for
each workflow. It writes only to the output directory and executes no upstream
code. Reports normalize checkout prefixes and file-dependent symbolic namespaces
so that they can be compared across machines. Inputs and identity relationships
are unchanged by this normalization.

An optional second argument selects a different CLI bundle. To reproduce the
baseline without changing your checkout or Git index:

```sh
baseline_dir=$(mktemp -d /tmp/samebyte-baseline.XXXXXX)
git archive e28803445e42bfe32a5cb8e90436cbd5eb868708 src | tar -x -C "$baseline_dir"
NODE_PATH="$PWD/node_modules" node_modules/.bin/esbuild "$baseline_dir/src/cli.ts" \
  --bundle --external:yaml --platform=node --format=esm --target=node22 \
  --outfile=dist/evidence-baseline.js
node docs/evidence/replay.mjs /tmp/samebyte-baseline-replay dist/evidence-baseline.js
diff -r docs/evidence/baseline /tmp/samebyte-baseline-replay
rm dist/evidence-baseline.js
```

The baseline JSON invocation refers to `dist/evidence-baseline.js`; rebuild that
bundle with the commands above before running an individual baseline invocation.
For a single workflow with the current CLI:

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

Baseline `on-tag.yaml`: **3 operations**, all identity `unknown`: build templates
at lines 413 and 534, and the Anchore scan template at line 729. No deployments,
findings, or errors; exit `0`. Separately analyzed qualification and attestation
workflows each yield zero operations, deployments, findings, and errors.

Updated results preserve those operations and states. `on-tag.yaml` has **80
boundary notices**: 2 reusable calls, 23 local action calls, 22 other opaque
actions, 3 strategy boundaries, 26 complex shell boundaries, and 4 uninterpreted
command boundaries. Qualification has **14** notices; attestation has **5**.
These are boundary counts, not missing-operation counts or coverage percentages.

The coverage notices identify these limits: local reusable calls hide qualification and
attestation; local composites hide producers and consumers; matrix instances are
not expanded; digest-map construction, `fromJSON`, dynamic indexing, registry
inspection, manifest assembly, shell gates, and promotion remain unsupported.
Analyzing callee files independently does not join their operations, inputs, or
outputs to the caller. The analyzed caller therefore has no proven consumer
identity or recognized deployment for this release chain.

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

Baseline and updated: **8 operations**. Three builds (lines 115, 137, 161) have
unknown identity because the job is conditional; the last also builds multiple
platforms. Two pre-push scans (128, 150) use mutable local tags. Two attestations
(238, 243) and the published scan (248) have unknown identities. Inputs such as
`github.repository`, secrets, metadata action outputs, and the guarded build
output are unresolved. No supported deployments, findings, or errors; exit `0`.
Updated output adds **17 notices** (13 opaque action calls, 4 complex shell
boundaries), alongside explicit unknown-operation explanations.

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

Baseline caller: **0 operations**, deployments, findings, and errors; exit `0`.
Updated caller: the same results with **1 reusable-workflow boundary**, carrying
the exact remote call target and its line 21. The composite producer is manually
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

Baseline and updated: release has **1 unknown build** (line 914); test workflow
has zero supported operations. Both have zero supported deployments, findings,
and errors, and exit `0`. Updated release has **76 notices**, including the
preflight call and a local release-notes action; callee test workflow has **19**.
The preflight job tests source code in a base container rather than the published
application image. Its script execution, recovery paths, and conditional
multi-platform build do not establish an OCI test of the publication output.

## Analysis limits

Reusable workflow calls remain boundaries. Their inputs, outputs, and execution
gates are not expanded into the caller's graph. In these examples, expanding
local calls alone would still leave composite actions, shell logic, dynamic
expressions, or platform selection unresolved.

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
