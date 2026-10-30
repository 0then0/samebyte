# Contributing to SameByte

SameByte traces OCI artifact identity through GitHub Actions workflows. Changes
should preserve the distinction between proven identity, unknown identity,
coverage boundaries, and analysis errors. Start with the [README](README.md) for
supported commands, adapters, findings, and limitations.

## Report a bug or propose a change

Use the [issue forms](https://github.com/0then0/samebyte/issues/new/choose).
For an analyzer bug, include the SameByte version, a minimal workflow, any
annotations, the command, and expected versus actual results. Remove credentials
and private infrastructure details. A reduced example is usually more useful
than a complete production workflow.

Discuss substantial changes to supported CI systems, dependency choices, or
analysis semantics in an issue before implementing them. Small fixes and
clarifications can go directly to a pull request.

Report vulnerabilities through the [security policy](SECURITY.md), not a public
bug report. Participation follows the [code of conduct](CODE_OF_CONDUCT.md).

## Set up a checkout

Use Node.js 22 or later and npm. CI tests Node.js 22 and 24 on Linux.

```bash
git clone https://github.com/0then0/samebyte.git
cd samebyte
npm ci --ignore-scripts
npm test
node dist/cli.js tests/fixtures/correct.yml
```

Use the committed npm lockfile. Do not replace it with another package manager's
lockfile or update unrelated dependencies. Propose new dependencies with an
explanation of why the existing tools are insufficient.

## Make and verify a change

Keep changes focused. Add a regression test for a meaningful behavior change;
documentation-only changes do not require artificial tests. Tests use
`node:test`, assertions, and CLI subprocesses. Avoid registry access, container
execution, or running upstream workflow scripts in tests.

```bash
npm run typecheck
npm run lint
npm test
npm pack --dry-run
```

`npm test` builds the CLI and test bundles before running tests and fails when the
committed action bundle `action/index.mjs` is stale. After changing anything under
`src/`, or updating `yaml`, `@actions/expressions` or `esbuild`, run
`npm run build:action` and commit the regenerated bundle; Dependabot cannot do
this, so dependency pull requests need that extra commit. `npm pack
--dry-run` checks the installable package and also builds the CLI. To format
changes, run `npm run format`, then inspect the diff for unrelated edits.

`.editorconfig` uses UTF-8, LF, and two-space indentation. Biome defines the
TypeScript and JSON formatting rules. Git preserves the original bytes of
checksum-pinned files under `docs/evidence/*/upstream/`; do not reformat them.
Saved reports are generated with `docs/evidence/replay.mjs`. See the
[workflow examples](docs/evidence/README.md) for reproduction commands. Never
execute those upstream actions or scripts as part of regeneration.

For analyzer changes, preserve these invariants:

- Unresolved or independently produced symbolic digests are not proven unequal.
- Source tests do not prove that an OCI artifact was tested.
- Conditions, execution order, ignored failures, and platform selection matter.
- An unsupported action or script is a coverage boundary, not a guessed operation.
- Trusted annotations do not establish that a step has no additional behavior.
- Exit codes remain `0` for no high-confidence findings, `1` for such findings,
  and `2` for analysis errors.

## Submit a pull request

Create a branch in your fork and open a pull request against `main`. Explain the
problem, resulting behavior, and commands used to verify it. Link a related issue
when one exists. Include documentation updates for changed public behavior.

Use English Conventional Commit messages with `feat`, `fix`, `refactor`, `chore`,
`docs`, or `test`, for example `fix: retain coverage for annotated shell steps`.
CI must pass on both supported Node.js versions before merge. Do not commit
build output, local credentials, or release archives. The one exception is
`action/index.mjs`: GitHub runs the action from the tagged commit, so its bundle
is committed and verified against the sources.

## Releases

Maintainers publish GitHub Releases from stable `vX.Y.Z` tags. The tag must match
`package.json`. Only the release job has repository write permissions; ordinary
CI has read-only access.

1. Update `package.json` and `package-lock.json`, for example with
   `npm version patch --no-git-tag-version --ignore-scripts`.
2. Set the matching version in `src/cli.ts` and the version assertion in
   `tests/cli.test.ts`, then run `npm run build:action`. Update the README installation examples and
   [changelog](CHANGELOG.md); retain historical versions in the evidence reports.
3. Run the verification commands above. Check `node dist/cli.js --version` and
   ensure the package contains only the intended files.
4. Commit the release preparation. Create an annotated tag on that commit, for
   example `git tag -a vX.Y.Z -m "SameByte vX.Y.Z"`, replacing `X.Y.Z` with the
   actual version.
5. Push the commit and tag together with
   `git push --atomic origin main refs/tags/vX.Y.Z`.
6. Wait for CI and the release workflow. Check that the published release includes
   `samebyte-X.Y.Z.tgz` and `SHA256SUMS`, then verify the downloaded checksum and
   CLI version.

Do not move published tags or replace existing release assets to fix a release.
Prepare a new patch release instead. SameByte distributes packages through
GitHub Releases; this workflow does not publish to the npm registry.

## License

Contributions are distributed under the project's [Apache-2.0 license](LICENSE).
