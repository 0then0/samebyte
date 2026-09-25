# SameByte

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
Production artifact was never tested. The production OCI image was created after source tests; no recognized image test consumes it.
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
Artifact lineage verified.
```

The output above abbreviates the symbolic digest. SameByte does not run a build or fetch its real digest. It proves that supported consumers reference the same output. Complete examples are in [tests/fixtures](tests/fixtures).

## Install from source

Requires Node.js 22 or later and npm. This repository does not imply an existing npm release.

```bash
npm ci --ignore-scripts
npm run build
node dist/cli.js .
```

To install the local checkout as a CLI:

```bash
npm install --global .
samebyte .
```

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
samebyte . --config samebyte.config.json
```

A repository path scans `.github/workflows/*.yml` and `*.yaml`. A directory path scans its immediate YAML files. Files are analyzed independently: identity is not joined across workflow runs.

Text findings include source locations and evidence paths. `explain` explicitly selects the same detailed text view. `graph` shows artifacts, producers, and consumers; `--format json` exposes the structured graph, operations, findings, diagnostics, and deployment checks. `--format sarif` emits SARIF 2.1.0 results with workflow line locations and evidence properties.

Exit codes:

- `0`: analysis completed without high-confidence findings. This can include unknown lineage or no supported deployments.
- `1`: at least one high-confidence finding, including a mutable deployment reference.
- `2`: an input, configuration, YAML, dependency-graph, or analysis error. Errors take precedence over findings.

`Artifact lineage verified` requires all detected deployments to have proven **test, scan, and attestation** identity, with no findings or errors. Missing operations remain `unknown`; their absence alone does not cause a violation.

## Supported data flow

The analysis separates workflow parsing, symbolic values, operation adapters, an artifact graph, and rules. Adapters recognize producers and consumers; the rules compare their resolved identities and execution order.

- `docker/build-push-action` produces a symbolic OCI digest through `steps.<id>.outputs.digest`.
- Step outputs propagate through job `outputs`, direct `needs.<job>.outputs`, and workflow/job/step `env`.
- GitHub expressions are parsed using GitHub's [@actions/expressions](https://github.com/actions/languageservices/tree/main/expressions) AST. Direct property access, bracket notation, string literals, and `github.sha` are supported. Functions, dynamic indexing, and compound expressions remain unknown.
- Simple `echo "name=value" >> "$GITHUB_OUTPUT"` forwards a value, including resolved expressions and environment variables.
- Full 64-hex `sha256` digests provide immutable identity. Tags, including `${{ github.sha }}`, are mutable references. A source revision is not an OCI digest.
- Job dependencies and step/command order matter. A later test, a parallel sibling job, conditional checks, matrix jobs, and ignored failures do not establish unconditional verification.

The common supported pipeline is:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@v4
      # Configure registry authentication for your own workflow.
      - id: build
        uses: docker/build-push-action@v6
        with:
          push: true
          tags: ghcr.io/acme/api:release

  verify:
    needs: build
    runs-on: ubuntu-latest
    env:
      IMAGE: ghcr.io/acme/api@${{ needs.build.outputs.digest }}
    steps:
      - run: docker run --rm "$IMAGE" npm test
      - uses: aquasecurity/trivy-action@0.33.1
        with:
          image-ref: ${{ env.IMAGE }}
      - uses: actions/attest-build-provenance@v2
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

- **Build:** `docker/build-push-action`, `docker build`, `docker buildx build`. Shell builds record a producer and supported `-t`/`--tag` reference, but do not invent an externally accessible digest output.
- **Test:** foreground `docker run` with common flags. This means that the image is exercised; SameByte does not assess its test command or coverage. `npm test`, `pnpm test`, and `yarn test` are source tests, not OCI tests. `docker compose run` is recognized with unknown identity because Compose file interpretation is outside this MVP.
- **Scan:** `aquasecurity/trivy-action` (`image-ref`), `docker/scout-action` (`image` with `command: cves`, `quickview`, or `compare`), `anchore/scan-action` (`image`); simple `trivy image`, `grype`, and `docker scout cves`/`quickview` commands. Scout commands such as `environment` and `attestation-add` are not treated as scans.
- **Attestation:** `actions/attest`, `actions/attest-build-provenance` (`subject-name`, `subject-digest`), and `gh attestation verify oci://...`. This tracks the subject identity; it does not validate signatures or policy itself.
- **Deploy:** simple `kubectl set image` container assignments and `helm upgrade`/`helm install`. Helm chart values alone do not prove what a chart renders, so Helm deployments have unknown identity unless an explicit annotation describes the image. Custom deployment actions require annotations.

Adapters recognize the action repository independently of the pinned ref. This assumes that the referenced action implements its documented interface; SameByte does not audit the action's code. Unsupported flags and inputs may reduce coverage to unknown.

## Findings

- **SB001:** a production image with a proven digest link was built after source tests, and no recognized OCI test consumes that digest. A matching mutable tag only yields a medium confidence candidate because it cannot establish which bytes the registry served. Unrelated image tests never suppress this finding.
- **SB002:** preceding tests use a different concrete digest from deployment for the same repository.
- **SB003:** preceding scans use a different concrete digest from deployment for the same repository.
- **SB004:** preceding attestation operations use a different concrete digest from deployment for the same repository.
- **SB005:** deployment uses a mutable image reference. The mutable-reference finding is high confidence; the artifact relationship is still `unknown`.
- **SB006:** a recognized deployment has unresolved identity or crosses an unsupported shell boundary. This is medium confidence and does not alone fail the CLI.

Two independent build outputs may contain the same bytes. SameByte reports that relationship as `unknown`, not as a proven mismatch. It also avoids comparing unrelated image repositories as mismatches.

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

Annotations replace automatic interpretation of that step. They are trusted user assertions, appear in evidence, and are not independently verified. Use distinct workflow filenames when applying one config across several files.

## GitHub Action

The repository includes a composite [action.yml](action.yml). After making your version available on GitHub, pin it to a reviewed commit:

```yaml
- uses: actions/checkout@v5
- uses: 0then0/samebyte@<reviewed-commit-sha>
  with:
    path: .github/workflows
    format: text
```

The action uses Node 22 and builds the CLI from its npm lockfile, including development dependencies needed by esbuild even when the calling workflow sets `NODE_ENV=production`. It accepts optional `config` and preserves the CLI exit status. SARIF output is printed to stdout; uploading it to GitHub Code Scanning is a separate workflow step. No release, remote workflow execution, or publication is performed by this checkout.

## Development

```bash
npm ci --ignore-scripts
npm run typecheck
npm run lint
npm run format
npm test
npm run build
npm pack --dry-run
```

Biome handles formatting and linting. Tests use `node:test`, including CLI subprocess checks. Fixtures cover a correct pipeline, rebuild after source tests, and an unknown shell boundary; regression tests cover mismatches, mutable tags, expressions, dependency order, annotations, output formats, and conservative shell handling.

Source layout:

- `src/parser.ts`: discovery, YAML locations, structural checks, dependency ordering.
- `src/expressions.ts`: GitHub expression AST, symbolic values, env propagation, OCI identities.
- `src/adapters.ts` and `src/shell.ts`: action interfaces and a restricted shell tokenizer.
- `src/analyzer.ts` and `src/model.ts`: transfer of values and artifact/operation graph.
- `src/rules.ts`: identity relationships, check ordering, and findings.
- `src/output.ts` and `src/cli.ts`: text, JSON, SARIF, graph, and process exit codes.

SameByte checks lineage and identity only. It does not replace SLSA, in-toto, or Sigstore; scan vulnerabilities; sign artifacts; assess Dockerfiles or test quality; run CI; or guarantee supply-chain security. Reusable workflows, arbitrary binaries, non-GitHub CI, and generic build-system analysis are outside this version.

## License

[Apache-2.0](LICENSE).
