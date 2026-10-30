# GitHub Action

The repository includes a [JavaScript action](../action.yml) that runs on the runner's own Node.js 24 runtime (`runs.using: node24`). It does not install or select Node.js, run `npm`, or change `PATH`, so later steps keep the toolchain the workflow chose. A prebuilt, dependency-free bundle (`action/index.mjs`) is committed to each release tag and checked against the sources in CI, so `uses: 0then0/samebyte@<ref>` works from the ref you pin. The runner must support `node24`: GitHub Actions runner 2.327.1 or later (current GitHub-hosted runners qualify; update older self-hosted runners). The CLI itself still requires only Node.js 22.

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
