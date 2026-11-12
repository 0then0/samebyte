<p align="center">
  <img src="assets/samebyte.svg" width="128" height="128" alt="SameByte: one OCI artifact connected to verification and deployment">
</p>

# SameByte

[![CI](https://img.shields.io/github/actions/workflow/status/0then0/samebyte/ci.yml?branch=main&label=CI)](https://github.com/0then0/samebyte/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/0then0/samebyte)](https://github.com/0then0/samebyte/releases/latest)
[![Node.js 22 or later](https://img.shields.io/badge/Node.js-%3E%3D22-43853d)](https://nodejs.org/)
[![License: Apache-2.0](https://img.shields.io/github/license/0then0/samebyte)](LICENSE)

**Test the same bytes you deploy.**

SameByte is a command-line tool and GitHub Action that reads your GitHub Actions workflows and checks whether the container image you deploy is the same image you tested, scanned, and attested. It works on the workflow files alone: nothing is built, pulled, or executed.

## The problem

A green pipeline does not necessarily test the image it ships. A common shape is to test the source code and then build a separate image for production:

```text
npm build → npm test
                 ↓
            docker build → deploy
```

```console
$ samebyte tests/fixtures/rebuild.yml
SB001 HIGH [mismatch]
Production artifact was never tested. Source tests ran, but no recognized OCI test consumes the deployed digest.
```

The fix is to build the image once and pass its digest to every later step:

```text
build → OCI digest
          ├── docker run (tests)
          ├── Trivy
          ├── attestation
          └── deployment
```

```console
$ samebyte tests/fixtures/correct.yml
Deployment: ghcr.io/acme/api@<symbolic build digest> [proven]
  test: proven
  scan: proven
  attest: proven
Detected deployment lineage is proven. Pipeline coverage is incomplete.
```

Both examples show only the relevant lines of the report, and the second shortens the digest. SameByte does not know the real digest. It gives the output of each build step a symbolic identity and proves that the later steps reference that same output. Both workflows are in [`tests/fixtures`](https://github.com/0then0/samebyte/tree/main/tests/fixtures).

## Install

SameByte requires Node.js 22 or later. It is distributed as an npm package attached to each [GitHub Release](https://github.com/0then0/samebyte/releases); it is not published to the npm registry.

```bash
npm install --global https://github.com/0then0/samebyte/releases/download/v0.1.2/samebyte-0.1.2.tgz
samebyte --version
```

Replace `0.1.2` in both places with the release you want. To verify the download before installing it:

```bash
curl -fLO https://github.com/0then0/samebyte/releases/download/v0.1.2/samebyte-0.1.2.tgz
curl -fLO https://github.com/0then0/samebyte/releases/download/v0.1.2/SHA256SUMS
sha256sum --check SHA256SUMS
npm install --global ./samebyte-0.1.2.tgz
```

On macOS, use `shasum -a 256 --check SHA256SUMS` instead of `sha256sum --check`.

## Run it

From the root of a repository:

```bash
samebyte .
```

This analyzes every `*.yml` and `*.yaml` file in `.github/workflows`. You can also pass a workflow directory or a single file:

```bash
samebyte .github/workflows
samebyte .github/workflows/release.yml
```

Other commands and options:

```bash
samebyte explain .                                # same report as the default check command
samebyte graph .                                  # artifacts with their producers and consumers
samebyte . --format json                          # machine-readable report
samebyte . --format sarif --output samebyte.sarif # SARIF 2.1.0 file for Code Scanning
samebyte . --config samebyte.config.json          # annotations for custom steps
```

## Read the result

Each detected deployment gets a state and three checks: `test`, `scan`, and `attest`.

- `proven`: a recognized step used the deployed digest and must succeed before the deployment runs.
- `mismatch`: the evidence shows a different artifact. This produces a finding.
- `unknown`: SameByte could not establish the relationship. The report says where the identity was lost or why a check does not gate the deployment. A missing check is `unknown`, not a violation.

The report also contains:

- **Findings** `SB001`–`SB006`, such as an untested production image or a mutable deployment tag. Each has a workflow location and the evidence path. See the [findings reference](https://github.com/0then0/samebyte/blob/main/docs/analysis.md#findings).
- **Coverage notices** for steps SameByte does not interpret, such as an unsupported action, a complex shell script, or a matrix job. Operations may be hidden behind them. They never change the exit code.
- **Reusable workflow calls** that were followed into a local callee, with the resolved inputs and outputs.

`Artifact lineage verified within the supported analysis scope` appears only when every detected deployment has proven test, scan, and attestation identity and there are no findings, errors, or coverage notices. With coverage notices the summary is `Detected deployment lineage is proven. Pipeline coverage is incomplete.` A run with no recognized deployment says so and never counts as verified.

Exit codes:

- `0`: analysis completed without high-confidence findings. This can include unknown lineage or no recognized deployments, so it is not proof of a complete pipeline.
- `1`: at least one high-confidence finding, including a mutable deployment reference.
- `2`: an input, configuration, YAML, dependency-graph, or analysis error. Errors take precedence over findings.

## What it recognizes

- **Build:** `docker/build-push-action`, `docker build`, `docker buildx build`.
- **Test:** `docker run`. `npm test`, `pnpm test`, and `yarn test` count as source tests, not image tests.
- **Scan:** Trivy, Docker Scout, and Anchore actions; `trivy image`, `grype`, and `docker scout` commands.
- **Attestation:** `actions/attest`, `actions/attest-build-provenance`, `gh attestation verify`.
- **Deployment:** `kubectl set image`, `helm upgrade`, and `helm install`.

Digests are followed through step outputs, job outputs, `needs`, `env`, and simple `echo "name=value" >> "$GITHUB_OUTPUT"` lines. A step SameByte does not recognize can be described with an [annotation](https://github.com/0then0/samebyte/blob/main/docs/analysis.md#unknown-boundaries-and-annotations). The exact inputs, flags, and conditions are listed in the [analysis reference](https://github.com/0then0/samebyte/blob/main/docs/analysis.md).

### Reusable workflows

A job that calls a local reusable workflow (`uses: ./.github/workflows/<file>`) is followed one level into that file. A digest passed through `with` keeps its identity inside the callee, and a digest built by the callee returns through its workflow outputs:

```yaml
jobs:
  verify:
    needs: build
    uses: ./.github/workflows/verify-image.yml
    with:
      image: ghcr.io/acme/api
      digest: ${{ needs.build.outputs.digest }}
```

Each call is analyzed separately, so two calls of the same workflow with different digests are never mixed up. A check inside the callee counts for a deployment in the caller only when that check cannot be skipped or ignored. Remote reusable workflows, nested calls, and matrix calls are reported as coverage notices. Details are in [local reusable workflows](https://github.com/0then0/samebyte/blob/main/docs/analysis.md#local-reusable-workflows).

## Output formats

- **Text** (default) and `explain` print findings with their evidence paths, unknown identities with reasons, deployments, and coverage notices.
- **`graph`** lists each artifact with the steps that produce and consume it.
- **`--format json`** contains operations, artifacts, deployments, findings, diagnostics, `coverage`, and `calls`. The [report format](https://github.com/0then0/samebyte/blob/main/docs/analysis.md#report-format) section describes the fields.
- **`--format sarif`** emits SARIF 2.1.0. Findings are results with workflow locations; coverage notices are `note`-level notifications, not results.

`--output <file>` writes the report to a file instead of stdout and creates missing parent directories. The file is written atomically and only when analysis completed (exit `0` or `1`). After an analysis error or a failed write no file is created, because a partial report would look complete to a consumer such as Code Scanning. A write failure exits `2`. An existing file at that path is left untouched when no new report is written, so give each run a fresh location.

## GitHub Action

```yaml
- uses: actions/checkout@v7
- uses: 0then0/samebyte@v0.1.2
  with:
    path: .github/workflows
    format: sarif
    output: ${{ runner.temp }}/samebyte.sarif
```

The action is prebuilt and runs on the runner's own Node.js 24; it does not install or change Node.js for later steps. Inputs, outputs, a complete Code Scanning upload workflow, and failure behavior are described in the [GitHub Action guide](https://github.com/0then0/samebyte/blob/main/docs/github-action.md).

## Limitations

SameByte checks artifact identity and execution order in workflow files. It is deliberately conservative: when it cannot prove something, the result is `unknown`.

- It does not run workflows, pull images, inspect registries, or verify signatures. A `proven` result describes the workflow graph, not what happened in a particular run.
- It does not judge the quality of tests, scan policies, or Dockerfiles, and it does not replace SLSA, in-toto, or Sigstore.
- Composite actions, remote and nested reusable workflows, matrix expansion, complex shell scripts, and arbitrary binaries are not interpreted. They appear as coverage notices.
- Multi-platform builds are not resolved to a platform manifest, so their identity stays `unknown`.
- Identity is not joined across separate workflow runs, and only GitHub Actions is supported.

## Documentation

- [Analysis reference](https://github.com/0then0/samebyte/blob/main/docs/analysis.md): recognized steps, data flow, reusable workflows, findings, shell rules, annotations, coverage notices, and the report format.
- [GitHub Action](https://github.com/0then0/samebyte/blob/main/docs/github-action.md): inputs, outputs, and Code Scanning upload.
- [Real-world workflow examples](https://github.com/0then0/samebyte/blob/main/docs/evidence/README.md): pinned public pipelines with saved reports and replay commands.
- [Changelog](https://github.com/0then0/samebyte/blob/main/CHANGELOG.md): released changes.

## Community and support

- [Contributing](https://github.com/0then0/samebyte/blob/main/CONTRIBUTING.md): local setup, tests, source layout, pull requests, and releases.
- [Issue forms](https://github.com/0then0/samebyte/issues/new/choose): bug reports and feature requests with reproducible examples.
- [Code of conduct](https://github.com/0then0/samebyte/blob/main/CODE_OF_CONDUCT.md): participation expectations and reporting concerns.
- [Security policy](https://github.com/0then0/samebyte/security/policy): supported versions, trust model, and private vulnerability reporting.

## License

[Apache-2.0](LICENSE).
