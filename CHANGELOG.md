# Changelog

User-visible changes are recorded here. Release packages and checksums are
available from [GitHub Releases](https://github.com/0then0/samebyte/releases).

## Unreleased

### Added

- Artifact identity is traced through one level of local reusable workflows
  (`uses: ./.github/workflows/<file>`). Caller values reach the callee through
  typed `workflow_call` inputs with `required` and `default`, and callee digests
  return through `on.workflow_call.outputs` to the caller's `needs`. Callee
  tests, scans, attestations, builds, and deployments join the caller's graph.
- Each call is analyzed in its own context: two calls of one callee, or equal
  job and step ids in different files, never share identity. Caller workflow
  `env` is not carried into the callee.
- Execution gates cross the call. A callee check qualifies a caller deployment
  only when the deployment depends on the call and the check cannot be skipped
  or ignored; otherwise the check stays `unknown` with the specific reason.
- Coverage reasons `reusable-workflow-not-found`, `reusable-workflow-path`,
  `reusable-workflow-invalid`, `reusable-workflow-contract`,
  `reusable-workflow-secrets`, and `nested-reusable-workflow-call`.
- JSON `calls` array and `call` context on operations, coverage notices,
  evidence, and deployment check reasons; text, `explain`, and `graph` list
  expanded calls; SARIF results carry `relatedLocations` for the other file.
- A falcosecurity/falcoctl caller/callee pair in the real-world examples.

### Changed

- An expanded local call no longer has a `reusable-workflow-call` notice;
  unsupported constructs inside the callee are reported individually. Remote
  calls, nested calls, matrix calls, and workflows outside `.github/workflows`
  keep their boundaries.
- In a directory run, a workflow triggered only by `workflow_call` is reported
  through its callers instead of as a separate entry point when a caller
  expands it.
- The README and analysis reference are reorganized for first-time readers, and
  the project icon is redrawn for small sizes.
- The real-world examples keep one set of saved reports in
  `docs/evidence/reports/`; the `0.1.0` comparison reports are removed.
- The JSON report keeps `version: 1`; `calls` is always present and is empty for
  workflows without reusable calls.

## [0.1.2] - 2026-10-30

### Fixed

- A `run` step is interpreted only when its shell is established. The default shell
  is resolved from step, job and workflow `shell` settings, container jobs, and
  exact GitHub-hosted runner labels. Self-hosted labels, runner groups, label
  arrays and `runs-on` expressions no longer default to Bash and keep an
  `unsupported-shell` notice with the cause, so their commands do not become
  `proven`. Explicit `bash` or `sh` still works on any runner.
- The GitHub Action no longer installs or selects Node.js for the calling job.
- Saved real-world reports match the current `unsupported-shell` message, and a test
  now compares them with a fresh replay.

### Added

- `--output <file>` for the CLI, and `output` and `report-file` for the action, so a
  SARIF report can be passed to `github/codeql-action/upload-sarif`. The file is
  written atomically and only when analysis completed; an analysis or write error
  leaves no report.
- An acceptance workflow that runs the local action under a preselected Node.js
  version and checks the toolchain, SARIF validity, findings and exit codes.
- Contributor guidelines, conduct and security policies, issue forms, and a pull
  request template.
- Editor and Git settings with byte-preserving exceptions for pinned upstream
  evidence files.
- Monthly Dependabot checks for npm and GitHub Actions, with a seven-day cooldown,
  grouped minor/patch updates, and one open version-update PR per ecosystem.

### Changed

- The action is a `node24` JavaScript action with a committed, dependency-free
  bundle (`action/index.mjs`) checked against the sources in tests. The bundle keeps
  the license notices of `yaml` and `@actions/expressions`. It requires
  GitHub Actions runner 2.327.1 or later; the CLI still supports Node.js 22.
- CI runs for `main` pushes and pull requests, cancels superseded runs, and keeps
  Node.js 22 and 24 checks independent. Jobs have explicit timeouts.
- Release write permissions are scoped to the release job, concurrent publication
  for the same tag is serialized, and the CLI version is checked before packaging.

## [0.1.1] - 2026-10-11

### Added

- Structured coverage notices for reusable workflows, opaque actions, job
  strategies, unsupported shell steps, and uninterpreted commands.
- Pinned real-world workflow examples, provenance, baseline reports, and a static
  replay tool.
- Explanations for unknown detected identities and unresolved deployment checks.

### Fixed

- Proven deployment summaries now disclose recorded coverage boundaries.
- Annotated shell steps retain coverage notices without duplicating operations.
- Recognized dry-run and local deployment modes do not create false coverage
  notices.
- Replay commands record the selected CLI bundle and quote paths safely.

### Changed

- JSON includes coverage data; text, explain, and graph show coverage boundaries.
  SARIF reports them as notes rather than violations. Existing exit codes and
  identity-proof rules remain unchanged.
- Public documentation explains supported analysis and its limitations.

## [0.1.0] - 2026-09-26

### Added

- Local OCI artifact lineage analysis for GitHub Actions, with build, test, scan,
  attestation, and deployment adapters.
- Symbolic digest propagation, execution-order checks, trusted annotations, and
  conservative handling of conditions and platform selection.
- SB001–SB006 findings and text, JSON, SARIF, graph, and explain output.
- A composite GitHub Action and installable release packages with SHA-256 checksums.

[0.1.2]: https://github.com/0then0/samebyte/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/0then0/samebyte/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/0then0/samebyte/releases/tag/v0.1.0
