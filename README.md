<p align="center">
  <img src="assets/samebyte.svg" width="128" height="128" alt="SameByte: one OCI artifact connected to verification and deployment">
</p>

# SameByte

[![CI](https://img.shields.io/github/actions/workflow/status/0then0/samebyte/ci.yml?branch=main&label=CI)](https://github.com/0then0/samebyte/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/0then0/samebyte)](https://github.com/0then0/samebyte/releases/latest)
[![Node.js 22 or later](https://img.shields.io/badge/Node.js-%3E%3D22-43853d)](https://nodejs.org/)
[![License: Apache-2.0](https://img.shields.io/github/license/0then0/samebyte)](LICENSE)

**Test the same bytes you deploy.**

SameByte is a local, open-source CLI that traces OCI artifact identity through GitHub Actions workflows. A green workflow does not necessarily test the image it deploys:

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

Build the image once, publish its digest, and pass that digest to every consumer:

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

The output above abbreviates the symbolic digest and omits the coverage notice for the opaque `actions/checkout` call. SameByte does not run a build or fetch its real digest. It proves that supported consumers reference the same output. Complete examples are in the repository’s [workflow fixtures](https://github.com/0then0/samebyte/tree/main/tests/fixtures).

## Install a release

SameByte requires Node.js 22 or later. Each stable `vX.Y.Z` tag creates a GitHub Release with a versioned npm package tarball and SHA-256 checksums. The package tarball installs through npm without a registry account:

```bash
npm install --global https://github.com/0then0/samebyte/releases/download/v0.1.2/samebyte-0.1.2.tgz
samebyte .
```

Replace `0.1.2` in both places with the release version you want. To verify a downloaded asset before installing it:

```bash
curl -fLO https://github.com/0then0/samebyte/releases/download/v0.1.2/samebyte-0.1.2.tgz
curl -fLO https://github.com/0then0/samebyte/releases/download/v0.1.2/SHA256SUMS
sha256sum --check SHA256SUMS
npm install --global ./samebyte-0.1.2.tgz
```

On macOS, use `shasum -a 256 --check SHA256SUMS` instead of `sha256sum --check`.

## Usage

```bash
samebyte .
samebyte .github/workflows
samebyte .github/workflows/release.yml
samebyte check . --format text
samebyte explain .
samebyte graph .
samebyte . --format json
samebyte . --format sarif > samebyte.sarif
samebyte . --format sarif --output reports/samebyte.sarif
samebyte . --config samebyte.config.json
```

A repository path scans `.github/workflows/*.yml` and `*.yaml`. A directory path scans its immediate YAML files. Files are analyzed independently: identity is not joined across workflow runs.

Text and `explain` show deployments, unknown identity reasons (including untracked OCI platform selection), and unsupported coverage boundaries. `explain` also prints finding evidence paths. `graph` shows artifacts, producers, consumers, and a separate list of coverage boundaries. `--format json` exposes operations, findings, diagnostics, deployment checks, and the structured `coverage` array. `--format sarif` emits SARIF 2.1.0 findings with workflow locations and evidence; coverage boundaries are invocation notifications at `note` level, not violation results.

Exit codes:

- `0`: analysis completed without high-confidence findings. This can include unknown lineage or no supported deployments.
- `1`: at least one high-confidence finding, including a mutable deployment reference.
- `2`: an input, configuration, YAML, dependency-graph, or analysis error. Errors take precedence over findings.

`--output <file>` writes the report in the selected format to a file instead of stdout; stdout stays empty and errors go to stderr. A relative path resolves against the working directory and missing parent directories are created. The file appears atomically and only when analysis completed (exit `0` or `1`). After an analysis error (`2`) or a failed write no report file is created, because a partial report would look like a complete one to consumers such as Code Scanning. A write failure exits `2` even when there are also findings. A file that already exists at that path is left untouched when no new report is written, so write each run's report to a fresh location, such as `${{ runner.temp }}` in the Action.

`Artifact lineage verified within the supported analysis scope` requires all detected deployments to have proven **test, scan, and attestation** identity, with no findings, errors, or recorded coverage boundaries. With boundaries present, proven deployments remain proven and the summary says `Detected deployment lineage is proven. Pipeline coverage is incomplete.` Missing checks remain `unknown`; their absence alone does not cause a violation. No supported deployments is reported explicitly and never counts as verified lineage. Exit code `0` describes analyzer completion, not a complete pipeline proof.

## Analysis coverage

Coverage notices describe a boundary where operations, values, or execution gates may remain outside the graph. They do not guess what an unknown action or script does, and they do not change exit codes. Findings, unknown detected identities, coverage notices, and analysis errors remain separate report data.

Each JSON `coverage` entry includes a stable `reason`, a boundary `type`, a `location` (`file`, `line`, `job`, and optional zero-based `step`), a `message`, and a `target` when known. Job-level notices have no step index. Reasons are:

- `reusable-workflow-call`: local or remote job-level `uses`; contents and outputs are not expanded.
- `local-action-call`: local action contents, including composite actions, are not expanded.
- `unsupported-action-call`: an action call has no interpreting OCI adapter, or annotations replace interpretation. This includes setup and checkout actions; no assumption about their internals is made.
- `matrix-job`: job strategy is not expanded into instances; operations describe templates.
- `unsupported-shell`: unsupported shell syntax, an unsupported or undeterminable shell, output writes, or annotation-replaced shell interpretation may hide operations or lose values. The message states the cause.
- `uninterpreted-command`: a binary or script command is outside the supported interpreter. One notice per reason per step is retained, with the first uninterpreted command as the target.

Notices describe structural boundaries, including calls that may be skipped. They are not counts of missing operations. An empty array is not a completeness claim: adapters interpret documented interfaces, arbitrary binaries are not executed, and platform manifests are not inspected. There is no coverage percentage. An unsupported `parallel` block is an **analysis error** with exit code `2`.

Trusted annotations can assert an operation and its identity but do not establish that an action or script has no other behavior. Action calls and annotated `run` steps retain a coverage notice. Supported actions are analyzed through their adapters, not by inspecting implementation code.

The [real-world workflow examples](https://github.com/0then0/samebyte/blob/main/docs/evidence/README.md) show how to interpret these reports in release pipelines. They include pinned upstream files, checksums, dependency maps, saved results, and commands for reproducing the analysis.

## Supported data flow

The analysis separates workflow parsing, symbolic values, operation adapters, an artifact graph, and rules. Adapters recognize producers and consumers; the rules compare their resolved identities and execution order.

- `docker/build-push-action` produces a symbolic OCI digest through `steps.<id>.outputs.digest`.
- Step outputs propagate through job `outputs`, direct `needs.<job>.outputs`, and workflow/job/step `env`.
- GitHub expressions are parsed using GitHub's [@actions/expressions](https://github.com/actions/languageservices/tree/main/expressions) AST. Direct property access, bracket notation, string literals, and `github.sha` are supported. Functions, dynamic indexing, and compound expressions remain unknown.
- Simple `echo "name=value" >> "$GITHUB_OUTPUT"` forwards a value, including resolved expressions and environment variables.
- Full 64-hex `sha256` digests provide immutable identity. Tags, including `${{ github.sha }}`, are mutable references. A source revision is not an OCI digest.
- Job dependencies, step order, and completion order matter. A later test, a parallel sibling job, status checks that can bypass success, matrix jobs, and ignored failures do not establish unconditional verification. A plain `if: success()` condition preserves the success gate.
- `background: true` steps only establish a check after `wait` or `wait-all`. Their outputs remain unknown until then. If waiting ignores failure with `continue-on-error`, the result stays unknown. A dependent job starts after background steps in its prerequisite job finish.
- `parallel` syntax is parsed, but its nested operations are unsupported. SameByte reports an analysis diagnostic and exits with code `2` instead of claiming lineage is verified.
- A multi-platform build and `docker run --platform ...` do not prove a specific runtime manifest. SameByte keeps these identities unknown because the selected OCI child manifest can depend on the target platform.
- A concrete digest used by `docker run` without a recognized single-platform producer also remains unknown for testing. It may identify an OCI index, and a test runner can select a different child manifest from the production platform. Identity mismatches between distinct concrete digests are still reported.

The common supported pipeline is:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    outputs:
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@v7
      # Configure registry authentication for your own workflow.
      - id: build
        uses: docker/build-push-action@v7
        with:
          push: true
          tags: ghcr.io/acme/api:release

  verify:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      attestations: write
      artifact-metadata: write
    env:
      IMAGE: ghcr.io/acme/api@${{ needs.build.outputs.digest }}
    steps:
      - run: docker run --rm "$IMAGE" npm test
      - uses: aquasecurity/trivy-action@0.36.0
        with:
          image-ref: ${{ env.IMAGE }}
      - uses: actions/attest@v4
        with:
          subject-name: ghcr.io/acme/api
          subject-digest: ${{ needs.build.outputs.digest }}

  deploy:
    needs: [build, verify]
    runs-on: ubuntu-latest
    steps:
      - run: kubectl set image deployment/api api=ghcr.io/acme/api@${{ needs.build.outputs.digest }}
```

This is a lineage example, not a complete registry/cluster setup. Configure the necessary credentials, permissions, and tooling for actual execution.

## Producers and consumers

- **Build:** `docker/build-push-action` (v6 and v7), `docker build`, `docker buildx build`. Shell builds record a producer and supported `-t`/`--tag` reference, but do not invent an externally accessible digest output.
- **Test:** foreground `docker run` with common flags. This means that the image is exercised; SameByte does not assess its test command or coverage. `npm test`, `pnpm test`, and `yarn test` are source tests, not OCI tests. `docker compose run` is recognized with unknown identity because Compose file interpretation is outside the supported scope.
- **Scan:** `aquasecurity/trivy-action` (`image-ref`), `docker/scout-action` (`image` with `command: cves`, `quickview`, or `compare`), `anchore/scan-action` (`image`); simple `trivy image`, `grype`, and `docker scout cves`/`quickview` commands. Trivy's `input` archive option takes precedence over the image reference and therefore remains unknown. Scout commands such as `environment` and `attestation-add` are not treated as scans.
- **Attestation:** `actions/attest` and `actions/attest-build-provenance` (`subject-name`, `subject-digest`), plus `gh attestation verify oci://...`. This tracks the subject identity; it does not validate signatures or policy itself.
- **Deploy:** simple `kubectl set image` container assignments and `helm upgrade`/`helm install`. Helm chart values alone do not prove what a chart renders, so Helm deployments have unknown identity unless an explicit annotation describes the image. Recognized kubectl dry-run and local modes, and Helm dry-run modes, do not create deployments or coverage notices. `kubectl --dry-run=none` and `--local=false` still describe real deployments. Custom deployment actions require annotations.

Adapters recognize the action repository independently of the pinned ref. This assumes that the referenced action implements its documented interface; SameByte does not audit the action's code. Unsupported flags and inputs may reduce coverage to unknown.

## Findings

- **SB001:** a production image with a proven digest link was built after source tests, and no recognized OCI test consumes that digest. A matching mutable tag only yields a medium confidence candidate because it cannot establish which bytes the registry served. Unrelated image tests never suppress this finding.
- **SB002:** preceding tests use a different concrete digest from deployment for the same repository.
- **SB003:** preceding scans use a different concrete digest from deployment for the same repository.
- **SB004:** preceding attestation operations use a different concrete digest from deployment for the same repository.
- **SB005:** deployment uses a mutable image reference. The mutable-reference finding is high confidence; the artifact relationship is still `unknown`.
- **SB006:** a recognized deployment has unresolved identity or crosses an unsupported shell boundary. This is medium confidence and does not alone fail the CLI.

Two independent build outputs may contain the same bytes. SameByte reports that relationship as `unknown`, not as a proven mismatch. It also avoids comparing unrelated image repositories as mismatches.

## Shell analysis boundaries

A `run` step is interpreted only when SameByte can establish that it runs under `bash` or `sh`. The shell is resolved with GitHub's [documented precedence](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax): step `shell`, then `jobs.<id>.defaults.run.shell`, then `defaults.run.shell`, then the runner default.

- `shell: bash` or `shell: sh`, set at any of these levels, is supported on any runner, including self-hosted and expression-selected runners. Both stop the step at the first failing command (`-e`), which is what makes the supported straight-line syntax meaningful. Any other value (`pwsh`, `powershell`, `cmd`, `python`, a custom template such as `bash {0}`, a different case, or an expression) is unsupported.
- Without an explicit shell, a job with `container` defaults to `sh`.
- Otherwise the default is known only for a single GitHub-hosted label matching exactly: `ubuntu-latest`, `ubuntu-<YY>.<MM>` (optionally `-arm`), `ubuntu-slim`, and `macos-latest`, `macos-<N>` (optionally `-intel`, `-large` or `-xlarge`) run `bash`. `windows-latest`, `windows-<YYYY>` and `windows-11-arm` default to `pwsh` and are unsupported.
- Everything else leaves the shell unknown: `self-hosted` and any custom or larger-runner labels, label arrays, `group:` runner groups, and `runs-on` expressions. Labels are never searched for an operating system name, and a label that looks like a hosted image does not make a self-hosted runner hosted. Add `shell: bash` or `shell: sh` when the step is written for it.

For an unsupported or unknown shell the step keeps an `unsupported-shell` coverage notice with the cause. Its commands are not interpreted: deployments and consumers found there stay `unknown` and step outputs written there are unknown. Other steps, jobs and actions in the same workflow keep their own evidence, and the missing interpretation never creates a finding by itself.

Fail-fast is part of the proof: a recognized test before a deployment in the same script only gates it because `-e` stops the script. SameByte does not model options changed by `set`, `trap`, `BASH_ENV` or startup files; scripts using `set` or control flow are already rejected, but environment-injected shell options are outside the analysis. PowerShell and `cmd` are not analyzed: PowerShell does not stop at a failing native command in the middle of a script, and the step result follows the last command.

## Unknown boundaries and annotations

SameByte does not execute or read arbitrary scripts. `./deploy.sh` by itself is not enough to infer deployment. Complex shell control flow, substitutions, sourced files, heredocs, custom shells, and dynamic transforms cannot prove identity. Shell environment mutation invalidates the affected analysis context; `$GITHUB_ENV` is not interpreted as a supported value transfer.

For a custom step, explicitly declare its behavior in a JSON file:

```json
{
  "annotations": [
    {
      "workflow": "release.yml",
      "job": "deploy",
      "step": "ship",
      "operation": "deploy",
      "image": "ghcr.io/acme/api@${{ needs.build.outputs.digest }}"
    }
  ]
}
```

`workflow` matches the filename, `job` matches its job ID, and `step` matches an explicit step `id`. Operations are `build`, `test`, `scan`, `attest`, or `deploy`. A build annotation may specify `output` (default `digest`) to declare an OCI digest step output, and `image` to record its reference. Consumer annotations require `image`.

Save the configuration as `samebyte.config.json` and pass it with `samebyte . --config samebyte.config.json`.

Annotations replace automatic interpretation of that step. They are trusted user assertions, appear in evidence, and are not independently verified. A coverage notice remains because additional behavior inside the action or shell step is not analyzed. Use distinct workflow filenames when applying one config across several files.

## GitHub Action

The repository includes a [JavaScript action](https://github.com/0then0/samebyte/blob/main/action.yml) that runs on the runner's own Node.js 24 runtime (`runs.using: node24`). It does not install or select Node.js, run `npm`, or change `PATH`, so later steps keep the toolchain the workflow chose. A prebuilt, dependency-free bundle (`action/index.mjs`) is committed to each release tag and checked against the sources in CI, so `uses: 0then0/samebyte@<ref>` works from the ref you pin. The runner must support `node24`: GitHub Actions runner 2.327.1 or later (current GitHub-hosted runners qualify; update older self-hosted runners). The CLI itself still requires only Node.js 22.

Inputs:

- `path` (default `.`): repository, workflow directory or YAML file. Relative paths resolve against `GITHUB_WORKSPACE`.
- `format` (default `text`): `text`, `json` or `sarif`.
- `config` (default empty): optional annotations file, relative to the workspace.
- `output` (default empty): report file in the selected format, relative to the workspace; parent directories are created. Without it the report is printed to the step log.

Output:

- `report-file`: absolute path of the written report. Set only when `output` was given and analysis completed (exit `0` or `1`); empty after an analysis error or a write failure.

With `output`, the step log shows the text summary and the file holds the selected format, so diagnostics are never mixed into JSON or SARIF. The step exit status is the CLI contract: `0`, `1` for findings, `2` for an analysis or write error. Inputs are passed as data, never through a shell.

Upload to Code Scanning stays a separate step in your workflow, with its own permissions. SameByte does not upload anything:

```yaml
name: SameByte
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  lineage:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write # required by upload-sarif
      actions: read # required by upload-sarif in private repositories
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - id: samebyte
        uses: 0then0/samebyte@v0.1.2
        with:
          path: .github/workflows
          format: sarif
          output: ${{ runner.temp }}/samebyte.sarif
      - name: Upload SARIF
        if: ${{ !cancelled() && steps.samebyte.outputs.report-file != '' }}
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ${{ steps.samebyte.outputs.report-file }}
          category: samebyte
```

Do not add `continue-on-error` or `|| true`. The job keeps SameByte's status, and the upload step decides by whether a report exists:

- Findings (exit `1`): the SameByte step fails, the report file exists and `report-file` is set. `!cancelled()` lets the upload run after that failure, and the job still ends as failed.
- Analysis error (exit `2`) or write failure: no file and an empty `report-file`, so the upload is skipped. The job fails and the error stays distinct from a finding; nothing partial reaches Code Scanning.
- Success (exit `0`): the upload runs and the job passes.
- Cancellation: `!cancelled()` skips the upload, and the job is cancelled.

SARIF locations are relative to the workspace, so run `actions/checkout` for the analyzed repository first. For stronger supply-chain protection, replace `v0.1.2` with the full reviewed commit SHA shown on that release. A static `proven` result describes the workflow graph; it is not proof of what ran or a cryptographic verification of an artifact.

## Releases

Push a stable SemVer tag matching `package.json` to run the release workflow. It reruns typecheck, lint, and tests, creates the npm package tarball, writes a SHA-256 checksum file, and publishes both as assets on a GitHub Release with generated release notes.

The package metadata, CLI version, version test, installation examples, and
changelog must be updated together before creating the tag. Follow the
[maintainer release instructions](https://github.com/0then0/samebyte/blob/main/CONTRIBUTING.md#releases)
for the verification, commit, and tag commands. The workflow rejects mismatched
tag, package, or CLI versions. Release assets install directly with npm as shown
above.

## Development

### Dependency updates

[Dependabot](.github/dependabot.yml) checks npm dependencies and GitHub Actions
on the first day of each month. New versions must be at least seven days old.
Minor and patch updates are grouped per ecosystem; major updates use separate
PRs. At most one version-update PR per ecosystem can be open at a time.
Dependabot security updates, when enabled in the repository settings, are not
delayed by this schedule or cooldown. Updates require review and passing CI.

### Local checks

```bash
npm ci --ignore-scripts
npm run typecheck
npm run lint
npm run format
npm test
npm run build
npm pack --dry-run
```

To install the current working tree locally during development, run `npm install --global .` after building.

Biome handles formatting and linting. Tests use `node:test`, including CLI subprocess checks. Fixtures cover a correct pipeline, rebuild after source tests, and an unknown shell boundary; regression tests cover mismatches, mutable tags, expressions, dependency order, annotations, output formats, and conservative shell handling.

Source layout:

- `src/parser.ts`: discovery, YAML locations, structural checks, dependency ordering.
- `src/expressions.ts`: GitHub expression AST, symbolic values, env propagation, OCI identities.
- `src/adapters.ts` and `src/shell.ts`: action interfaces, a restricted shell tokenizer, and shell resolution.
- `src/analyzer.ts` and `src/model.ts`: transfer of values and artifact/operation graph.
- `src/rules.ts`: identity relationships, check ordering, and findings.
- `src/output.ts`, `src/run.ts` and `src/cli.ts`: text, JSON, SARIF, graph, report files, and process exit codes.
- `src/action.ts` and `action/index.mjs`: the GitHub Action entrypoint and its committed bundle. Regenerate with `npm run build:action`; `npm test` fails when the bundle is stale.

SameByte checks lineage and identity only. It does not replace SLSA, in-toto, or Sigstore; scan vulnerabilities; sign artifacts; assess Dockerfiles or test quality; run CI; or guarantee supply-chain security. Reusable workflows, arbitrary binaries, non-GitHub CI, and generic build-system analysis are outside this version.

## Community and support

- [Contributing](https://github.com/0then0/samebyte/blob/main/CONTRIBUTING.md): local setup, tests, pull requests, and release preparation.
- [Issue forms](https://github.com/0then0/samebyte/issues/new/choose): bug reports and feature requests with reproducible examples.
- [Code of conduct](https://github.com/0then0/samebyte/blob/main/CODE_OF_CONDUCT.md): participation expectations and reporting concerns.
- [Security policy](https://github.com/0then0/samebyte/security/policy): supported versions, trust model, and private vulnerability reporting.
- [Changelog](https://github.com/0then0/samebyte/blob/main/CHANGELOG.md): released changes and unreleased work.

## License

[Apache-2.0](LICENSE).
