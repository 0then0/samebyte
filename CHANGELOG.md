# Changelog

User-visible changes are recorded here. Release packages and checksums are
available from [GitHub Releases](https://github.com/0then0/samebyte/releases).

## Unreleased

### Added

- Contributor guidelines, conduct and security policies, issue forms, and a pull
  request template.
- Editor and Git settings with byte-preserving exceptions for pinned upstream
  evidence files.
- Monthly Dependabot checks for npm and GitHub Actions, with a seven-day cooldown,
  grouped minor/patch updates, and one open version-update PR per ecosystem.

### Changed

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

[0.1.1]: https://github.com/0then0/samebyte/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/0then0/samebyte/releases/tag/v0.1.0
