import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import test from 'node:test';
import { analyzeWorkflow } from '../src/analyzer.js';
import { parseWorkflow } from '../src/parser.js';

const digest = `ghcr.io/acme/api@sha256:${'a'.repeat(64)}`;
const analyze = (source: string) =>
  analyzeWorkflow(parseWorkflow(source, resolve('fixture.yml')));
// A build, then a two-line test step whose shell varies, an independent scan action
// and a deployment. The scan action must not depend on the test step's shell.
const ref = 'ghcr.io/acme/api@${{ steps.build.outputs.digest }}';
const deployRef = 'ghcr.io/acme/api@${{ needs.release.outputs.digest }}';
const workflow = ({
  job = '    runs-on: ubuntu-latest',
  defaults = '',
  step = '',
}: {
  job?: string;
  defaults?: string;
  step?: string;
} = {}) => `${defaults}jobs:
  release:
${job}
    outputs:
      digest: \${{ steps.build.outputs.digest }}
    steps:
      - id: build
        uses: docker/build-push-action@v7
        with:
          tags: ghcr.io/acme/api:ci
      - ${step ? `${step}\n        ` : ''}run: |
          docker run --rm ${ref} npm test
          echo finished
      - uses: aquasecurity/trivy-action@0.36.0
        with:
          image-ref: ${ref}
  deploy:
    needs: release
    runs-on: ubuntu-latest
    steps:
      - shell: bash
        run: kubectl set image deployment/api api=${deployRef}
`;
const states = (source: string) => {
  const report = analyze(source);
  return {
    report,
    test: report.deployments[0].checks.test,
    scan: report.deployments[0].checks.scan,
    shellNotices: report.coverage.filter((c) => c.reason === 'unsupported-shell'),
  };
};
const assertUnknownShell = (source: string, expectedReason: RegExp) => {
  const { report, test, scan, shellNotices } = states(source);
  assert.equal(test, 'unknown', 'unknown shell must not prove the test');
  assert.equal(shellNotices.length, 1);
  assert.match(shellNotices[0].message, expectedReason);
  assert.equal(shellNotices[0].location.step, 1);
  // Independent evidence from the action step survives, and no finding is invented.
  assert.equal(scan, 'proven');
  assert.deepEqual(report.findings, []);
  assert.equal(report.diagnostics.length, 0);
};

test('GitHub-hosted Linux and macOS runners resolve to the supported default shell', () => {
  for (const label of [
    'ubuntu-latest',
    'ubuntu-24.04',
    'ubuntu-22.04-arm',
    'ubuntu-slim',
    'macos-latest',
    'macos-15',
    'macos-15-intel',
    'macos-latest-xlarge',
  ]) {
    const result = states(workflow({ job: `    runs-on: ${label}` }));
    assert.equal(result.test, 'proven', label);
    assert.equal(result.shellNotices.length, 0, label);
  }
});

test('GitHub-hosted Windows defaults to pwsh and is not interpreted', () => {
  for (const label of ['windows-latest', 'windows-2025', 'windows-11-arm'])
    assertUnknownShell(workflow({ job: `    runs-on: ${label}` }), /defaults to pwsh/);
});

test('runner labels never prove an operating system by substring', () => {
  for (const runsOn of [
    '[self-hosted, win2022]',
    '[self-hosted, linux, x64]',
    '[self-hosted, ubuntu-latest]',
    'self-hosted',
    'ubuntu-latest-8-cores',
    '[ubuntu-latest, gpu]',
    '[ubuntu-latest, windows-latest]',
    'Ubuntu-Latest',
    '{ group: win-runners }',
    '{ group: linux-runners, labels: ubuntu-latest }',
    '{ group: linux-runners, labels: [self-hosted, linux] }',
    '${{ vars.RUNNER }}',
    '${{ matrix.os }}',
    '${{ fromJSON(vars.RUNNERS) }}',
  ])
    assertUnknownShell(
      workflow({ job: `    runs-on: ${runsOn}` }),
      /cannot be determined statically/,
    );
});

test('a single-label array or labels mapping keeps the hosted resolution', () => {
  for (const runsOn of ['[ubuntu-latest]', '{ labels: ubuntu-24.04 }'])
    assert.equal(states(workflow({ job: `    runs-on: ${runsOn}` })).test, 'proven');
});

test('explicit bash or sh is analyzed on an unknown runner', () => {
  for (const runsOn of [
    '[self-hosted, win2022]',
    '${{ vars.RUNNER }}',
    'windows-latest',
  ]) {
    for (const shell of ['bash', 'sh']) {
      const job = `    runs-on: ${runsOn}`;
      for (const source of [
        workflow({ job, step: `shell: ${shell}` }),
        workflow({ job: `${job}\n    defaults:\n      run:\n        shell: ${shell}` }),
        workflow({ job, defaults: `defaults:\n  run:\n    shell: ${shell}\n` }),
      ]) {
        const result = states(source);
        assert.equal(result.test, 'proven', `${runsOn} ${shell}`);
        assert.equal(result.shellNotices.length, 0);
      }
    }
  }
});

test('shell precedence is step, then job defaults, then workflow defaults', () => {
  const job = '    runs-on: ${{ vars.RUNNER }}';
  const jobDefaults = (shell: string) =>
    `${job}\n    defaults:\n      run:\n        shell: ${shell}`;
  const workflowDefaults = (shell: string) =>
    `defaults:\n  run:\n    shell: ${shell}\n`;
  // Step overrides job and workflow defaults in both directions.
  assert.equal(
    states(
      workflow({
        job: jobDefaults('pwsh'),
        defaults: workflowDefaults('pwsh'),
        step: 'shell: bash',
      }),
    ).test,
    'proven',
  );
  assertUnknownShell(
    workflow({
      job: jobDefaults('bash'),
      defaults: workflowDefaults('bash'),
      step: 'shell: pwsh',
    }),
    /step shell "pwsh"/,
  );
  // Job defaults override workflow defaults in both directions.
  assert.equal(
    states(workflow({ job: jobDefaults('sh'), defaults: workflowDefaults('pwsh') }))
      .test,
    'proven',
  );
  assertUnknownShell(
    workflow({ job: jobDefaults('cmd'), defaults: workflowDefaults('bash') }),
    /job defaults\.run\.shell "cmd"/,
  );
  assertUnknownShell(
    workflow({ job, defaults: workflowDefaults('powershell') }),
    /workflow defaults\.run\.shell "powershell"/,
  );
});

test('an explicit shell takes precedence over a Windows hosted runner and a container', () => {
  assert.equal(
    states(workflow({ job: '    runs-on: windows-latest', step: 'shell: bash' })).test,
    'proven',
  );
  assertUnknownShell(
    workflow({
      job: '    runs-on: ubuntu-latest\n    container: node:22',
      step: 'shell: pwsh',
    }),
    /step shell "pwsh"/,
  );
});

test('container jobs default to sh regardless of the runner label', () => {
  for (const runsOn of [
    'ubuntu-latest',
    '[self-hosted, linux]',
    '${{ vars.RUNNER }}',
  ]) {
    for (const container of ['node:22', '{ image: node:22 }']) {
      const result = states(
        workflow({ job: `    runs-on: ${runsOn}\n    container: ${container}` }),
      );
      assert.equal(result.test, 'proven', `${runsOn} ${container}`);
      assert.equal(result.shellNotices.length, 0);
    }
  }
  // A container that may evaluate to nothing does not establish the shell.
  assertUnknownShell(
    workflow({
      job: '    runs-on: ${{ vars.RUNNER }}\n    container: ${{ vars.IMAGE }}',
    }),
    /cannot be determined statically/,
  );
});

test('unsupported and syntactically unknown shell values are not bash', () => {
  for (const shell of [
    'pwsh',
    'powershell',
    'cmd',
    'python',
    'Bash',
    'bash -x {0}',
    'bash {0}',
    'zsh',
    '${{ matrix.shell }}',
    "''",
  ])
    assertUnknownShell(workflow({ step: `shell: ${shell}` }), /is not bash or sh/);
});

test('unknown shell keeps unresolved operations unknown without false violations', () => {
  const report = analyze(`jobs:
  build:
    runs-on: [self-hosted, win2022]
    steps:
      - id: push
        uses: docker/build-push-action@v7
        with:
          tags: ghcr.io/acme/api:ci
  release:
    needs: build
    runs-on: [self-hosted, win2022]
    steps:
      - run: |
          docker run --rm ghcr.io/acme/api@sha256:${'b'.repeat(64)} npm test
          kubectl set image deployment/api api=\${{ needs.build.outputs.image }}
      - run: kubectl set image deployment/api api=ghcr.io/acme/api:latest
`);
  assert.deepEqual(
    report.operations.filter((op) => op.kind === 'test').map((op) => op.identity.kind),
    ['unknown'],
  );
  assert.equal(
    report.coverage.filter((c) => c.reason === 'unsupported-shell').length,
    2,
  );
  // Deployments inside unsupported shells never become proven.
  assert.ok(report.deployments.every((d) => d.state !== 'proven'));
});

test('output writes in an unknown shell do not produce known step outputs', () => {
  const report = analyze(`jobs:
  release:
    runs-on: \${{ vars.RUNNER }}
    steps:
      - id: ref
        run: echo "image=${digest}" >> "$GITHUB_OUTPUT"
      - run: kubectl set image deployment/api api=\${{ steps.ref.outputs.image }}
`);
  assert.equal(report.deployments[0].operation !== undefined, true);
  const deploy = report.operations.find((op) => op.kind === 'deploy');
  assert.equal(deploy?.identity.kind, 'unknown');
});

test('the same workflow differs only by explicit shell on an unknown runner', () => {
  const job = '    runs-on: [self-hosted, win2022]';
  assert.equal(states(workflow({ job })).test, 'unknown');
  assert.equal(states(workflow({ job, step: 'shell: bash' })).test, 'proven');
  assert.equal(states(workflow({ job, step: 'shell: sh' })).test, 'proven');
});
