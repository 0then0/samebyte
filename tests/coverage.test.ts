import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { analyzeWorkflow, mergeReports } from '../src/analyzer.js';
import { graphReport, sarifReport, textReport } from '../src/output.js';
import { parseWorkflow } from '../src/parser.js';

const analyze = (source: string) =>
  analyzeWorkflow(parseWorkflow(source, resolve('coverage.yml')));
const job = (steps: string) =>
  `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n${steps}`;

test('local and remote reusable calls are boundaries, not fabricated operations', () => {
  const report = analyze(`jobs:
  local:
    uses: ./.github/workflows/build.yml
  remote:
    needs: local
    uses: acme/ci/.github/workflows/deploy.yml@v1
`);
  assert.deepEqual(report.operations, []);
  assert.deepEqual(report.findings, []);
  assert.deepEqual(report.diagnostics, []);
  assert.deepEqual(
    report.coverage.map((n) => [n.reason, n.type, n.location.line]),
    [
      ['reusable-workflow-call', 'reusable-workflow', 3],
      ['reusable-workflow-call', 'reusable-workflow', 6],
    ],
  );
  assert.equal(report.coverage[0].location.step, undefined);
  assert.equal(report.coverage[0].target, './.github/workflows/build.yml');
  assert.match(textReport(report), /No supported deployments/);
  assert.match(textReport(report), /COVERAGE reusable-workflow-call/);
  assert.doesNotMatch(textReport(report), /Artifact lineage verified/);
});

test('local composite and opaque remote actions remain visible with no operations', () => {
  const report = analyze(
    job(`      - uses: ./.github/actions/build-image
      - uses: acme/custom-action@v1
`),
  );
  assert.deepEqual(report.operations, []);
  assert.deepEqual(
    report.coverage.map((n) => n.reason),
    ['local-action-call', 'unsupported-action-call'],
  );
  assert.equal(report.coverage[0].location.step, 0);
  assert.match(graphReport(report), /local-action-call/);
  assert.match(textReport(report, true), /custom-action@v1/);
});

test('proven deployments are scoped when coverage is incomplete', async () => {
  const source = await readFile('tests/fixtures/correct.yml', 'utf8');
  const report = analyze(source);
  assert.equal(report.deployments[0].state, 'proven');
  assert.equal(report.coverage[0].target, 'actions/checkout@v4');
  assert.doesNotMatch(textReport(report), /Artifact lineage verified/);
  assert.match(textReport(report), /Pipeline coverage is incomplete/);
  const supported = analyze(source.replace('      - uses: actions/checkout@v4\n', ''));
  assert.deepEqual(supported.coverage, []);
  assert.match(textReport(supported), /verified within the supported analysis scope/);
});

test('unknown detected identities differ from hidden operations and explain their cause', () => {
  const report = analyze(
    job(`      - uses: ./.github/actions/check
      - uses: aquasecurity/trivy-action@v1
        with:
          image-ref: \${{ inputs.image }}
      - run: kubectl set image deployment/api api=\${{ inputs.image }}
`),
  );
  assert.deepEqual(
    report.operations.map((op) => op.kind),
    ['scan', 'deploy'],
  );
  assert.equal(report.operations[0].identity.kind, 'unknown');
  assert.equal(report.coverage.length, 1);
  assert.equal(report.findings[0].ruleId, 'SB006');
  assert.equal(report.findings[0].confidence, 'medium');
  assert.match(textReport(report), /Unknown scan identity/);
  assert.match(textReport(report), /Unresolved GitHub expression/);
  for (const kind of ['test', 'scan', 'attest'] as const) {
    assert.ok(report.deployments[0].checkReasons?.[kind]);
    assert.match(textReport(report), new RegExp(`${kind} identity unknown`));
    assert.match(textReport(report, true), new RegExp(`${kind} identity unknown`));
  }
});

test('parallel remains an analysis error and never a coverage-only notice', () => {
  const report = analyze(
    job(`      - parallel:
          - run: docker run ghcr.io/acme/api:latest
`),
  );
  assert.equal(report.diagnostics.length, 1);
  assert.match(report.diagnostics[0].message, /parallel block/);
  assert.deepEqual(report.coverage, []);
  assert.match(textReport(report), /Analysis failed/);
  const sarif = sarifReport(report) as {
    runs: { invocations: { executionSuccessful: boolean }[] }[];
  };
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, false);
  assert.throws(() => analyze('jobs: []'), /non-empty jobs/);
});

test('matrix, complex shell and uninterpreted binaries do not invent OCI operations', () => {
  const report = analyze(`jobs:
  release:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        arch: [amd64, arm64]
    steps:
      - run: ./deploy.sh
      - run: |
          for image in a b; do
            cosign sign "$image"
          done
`);
  assert.deepEqual(report.operations, []);
  assert.deepEqual(
    report.coverage.map((n) => n.reason),
    ['matrix-job', 'uninterpreted-command', 'unsupported-shell'],
  );
  assert.equal(report.coverage[1].target, './deploy.sh');
});
test('unsupported redirections remain visible even without a recognized operation', () => {
  const report = analyze(job('      - run: ./release > release.log\n'));
  assert.deepEqual(report.operations, []);
  assert.equal(report.coverage[0].reason, 'unsupported-shell');
});

test('symbolic unknown reasons and mismatch findings stay distinct', async () => {
  const report = analyze(
    job(`      - id: first
        uses: docker/build-push-action@v6
      - id: second
        uses: docker/build-push-action@v6
      - uses: aquasecurity/trivy-action@v1
        with:
          image-ref: ghcr.io/acme/api@\${{ steps.first.outputs.digest }}
      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ steps.second.outputs.digest }}
`),
  );
  assert.deepEqual(report.findings, []);
  assert.equal(report.deployments[0].checks.scan, 'unknown');
  assert.match(
    report.deployments[0].checkReasons?.scan?.reason ?? '',
    /Independent symbolic digests/,
  );
  const mismatch = analyze(await readFile('tests/fixtures/rebuild.yml', 'utf8'));
  assert.equal(mismatch.deployments[0].checks.test, 'mismatch');
  assert.equal(mismatch.deployments[0].checkReasons?.test, undefined);
});

test('annotations retain opaque local action boundaries and their trusted evidence', () => {
  const workflow = parseWorkflow(
    job(`      - id: ship
        uses: ./.github/actions/ship
`),
    resolve('coverage.yml'),
  );
  const report = analyzeWorkflow(workflow, {
    annotations: [
      {
        workflow: 'coverage.yml',
        job: 'release',
        step: 'ship',
        operation: 'deploy',
        image: `ghcr.io/acme/api@sha256:${'a'.repeat(64)}`,
      },
    ],
  });
  assert.equal(report.operations[0].identity.kind, 'immutable');
  assert.match(report.operations[0].label, /User-declared/);
  assert.equal(report.coverage[0].reason, 'local-action-call');
});

test('annotations preserve shell boundaries without duplicating automatic operations', async () => {
  const base = (await readFile('tests/fixtures/correct.yml', 'utf8')).replace(
    '      - uses: actions/checkout@v4\n',
    '',
  );
  for (const run of [
    './extra-deploy.sh',
    'kubectl set image deployment/api api=x',
    'if true; then ./extra-deploy.sh; fi',
  ]) {
    const source = `${base}      - id: extra\n        run: ${run}\n`;
    const workflow = parseWorkflow(source, resolve('coverage.yml'));
    const report = analyzeWorkflow(workflow, {
      annotations: [
        {
          workflow: 'coverage.yml',
          job: 'deploy',
          step: 'extra',
          operation: 'scan',
          image: '${{ needs.verify.outputs.image }}',
        },
      ],
    });
    assert.equal(report.deployments.length, 1);
    assert.equal(report.deployments[0].state, 'proven');
    assert.equal(report.operations.length, 6);
    assert.match(report.operations.at(-1)?.label ?? '', /User-declared/);
    assert.equal(report.coverage.length, 1);
    assert.equal(report.coverage[0].reason, 'unsupported-shell');
    assert.equal(report.coverage[0].location.job, 'deploy');
    assert.equal(report.coverage[0].location.step, 1);
    assert.match(textReport(report), /Pipeline coverage is incomplete/);
    assert.doesNotMatch(textReport(report), /Artifact lineage verified/);
    assert.deepEqual(report.findings, []);
  }
});

test('recognized non-mutating deployment modes preserve supported coverage', async () => {
  const base = (await readFile('tests/fixtures/correct.yml', 'utf8')).replace(
    '      - uses: actions/checkout@v4\n',
    '',
  );
  for (const command of [
    'kubectl set image deployment/api api=x --dry-run=client',
    'kubectl -n staging set image deployment/api api=x --dry-run server',
    'kubectl set image deployment/api api=x --dry-run',
    'kubectl set image deployment/api api=x --local',
    'kubectl set image deployment/api api=x --local=true',
    'helm upgrade api ./chart --dry-run',
    'helm install api ./chart --dry-run=server',
  ]) {
    const report = analyze(`${base}      - run: ${command}\n`);
    assert.deepEqual(report.coverage, [], command);
    assert.equal(report.deployments.length, 1, command);
    assert.equal(report.deployments[0].state, 'proven', command);
    assert.match(textReport(report), /verified within the supported analysis scope/);
  }
  for (const mode of ['--dry-run=none', '--dry-run none', '--local=false']) {
    const report = analyze(
      job(`      - run: kubectl set image deployment/api api=x ${mode}\n`),
    );
    assert.equal(report.deployments.length, 1, mode);
  }
  for (const command of [
    'kubectl unsupported --dry-run=client',
    'helm unsupported --dry-run',
    './deploy.sh',
  ]) {
    const report = analyze(job(`      - run: ${command}\n`));
    assert.equal(report.coverage[0].reason, 'uninterpreted-command', command);
  }
});

test('coverage survives report merging; independent workflows do not join outputs', () => {
  const caller = analyze(`jobs:
  build:
    uses: ./.github/workflows/build.yml
  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ needs.build.outputs.digest }}
`);
  const callee = analyzeWorkflow(
    parseWorkflow(
      `jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digest: \${{ steps.build.outputs.digest }}
    steps:
      - id: build
        uses: docker/build-push-action@v6
`,
      resolve('build.yml'),
    ),
  );
  const merged = mergeReports([caller, callee]);
  assert.equal(merged.coverage.length, 1);
  assert.equal(merged.deployments[0].state, 'unknown');
  assert.equal(merged.operations[0].identity.kind, 'unknown');
  assert.equal(merged.operations[1].identity.kind, 'immutable');
});

test('SARIF separates coverage notes from findings and successful execution', () => {
  const report = analyze('jobs:\n  call:\n    uses: ./.github/workflows/build.yml\n');
  const sarif = sarifReport(report) as {
    runs: {
      results: unknown[];
      invocations: {
        executionSuccessful: boolean;
        toolExecutionNotifications: {
          level: string;
          descriptor: { id: string };
          locations: {
            physicalLocation: { region: { startLine: number } };
          }[];
        }[];
      }[];
    }[];
  };
  assert.deepEqual(sarif.runs[0].results, []);
  const invocation = sarif.runs[0].invocations[0];
  assert.equal(invocation.executionSuccessful, true);
  assert.equal(invocation.toolExecutionNotifications[0].level, 'note');
  assert.equal(
    invocation.toolExecutionNotifications[0].descriptor.id,
    'reusable-workflow-call',
  );
  assert.equal(
    invocation.toolExecutionNotifications[0].locations[0].physicalLocation.region
      .startLine,
    3,
  );
});

test('unchanged external inputs preserve baseline operations, findings and errors', async () => {
  const cases = ['nvidia-aicr', 'prebid-salesagent', 'liatrio-demo', 'music-assistant'];
  for (const name of cases) {
    const base = `docs/evidence/${name}`;
    const provenance = JSON.parse(await readFile(`${base}/provenance.json`, 'utf8'));
    for (const file of provenance.files) {
      const path = `${base}/upstream/${file.path}`;
      const source = await readFile(path);
      assert.equal(
        createHash('sha256').update(source).digest('hex'),
        file.sha256,
        path,
      );
      if (!file.path.startsWith('.github/workflows/')) continue;
      const report = analyzeWorkflow(parseWorkflow(source.toString(), resolve(path)));
      const baseline = JSON.parse(
        await readFile(
          `docs/evidence/baseline/${name}/${file.path.split('/').at(-1)}.json`,
          'utf8',
        ),
      ).report;
      assert.deepEqual(
        report.operations.map((op) => [
          op.kind,
          op.identity.kind,
          op.location.job,
          op.location.line,
        ]),
        baseline.operations.map(
          (op: {
            kind: string;
            identity: { kind: string };
            location: { job: string; line: number };
          }) => [op.kind, op.identity.kind, op.location.job, op.location.line],
        ),
        path,
      );
      assert.deepEqual(report.findings, baseline.findings, path);
      assert.deepEqual(report.deployments, baseline.deployments, path);
      assert.deepEqual(report.diagnostics, baseline.diagnostics, path);
      assert.ok(report.coverage.length > 0, path);
    }
  }
});
