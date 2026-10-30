# Analysis reference

What SameByte recognizes, what it treats as a boundary, and how to read its results. See the [README](../README.md) for installation and usage.

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

The [real-world workflow examples](evidence/README.md) show how to interpret these reports in release pipelines. They include pinned upstream files, checksums, dependency maps, saved results, and commands for reproducing the analysis.

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
