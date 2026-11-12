import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import type { Report } from '../src/model.js';

// Every case runs the built CLI or the committed action bundle; nothing here
// calls analyzer helpers directly.
const repository = resolve('tests/fixtures/reusable');
const workflows = join(repository, '.github/workflows');
const bundle = resolve('dist/cli.js');
const cli = (args: string[], cwd = process.cwd()) =>
  spawnSync(process.execPath, [bundle, ...args], { encoding: 'utf8', cwd });
const fixture = (name: string) => join(workflows, name);
const json = (
  path: string,
  cwd?: string,
): { report: Report; status: number | null } => {
  const result = cli([path, '--format', 'json'], cwd);
  assert.equal(result.stderr, '');
  return { report: JSON.parse(result.stdout), status: result.status };
};
const analyze = (name: string) => json(fixture(name));
const operation = (report: Report, id: string) =>
  report.operations.find((item) => item.id === id);
const deployed = (report: Report, index = 0) =>
  operation(report, report.deployments[index].operation);
const reasons = (report: Report, index = 0) =>
  Object.fromEntries(
    Object.entries(report.deployments[index].checkReasons ?? {}).map(([kind, item]) => [
      kind,
      item.reason,
    ]),
  );
// A scratch repository with its own .github/workflows directory.
const scratch = async (
  files: Record<string, string>,
  body: (root: string, workflow: (name: string) => string) => Promise<void>,
) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'samebyte-reusable-')));
  try {
    const directory = join(root, '.github/workflows');
    await mkdir(directory, { recursive: true });
    for (const [name, content] of Object.entries(files))
      if (content.startsWith('copy:'))
        await copyFile(fixture(content.slice(5)), join(directory, name));
      else await writeFile(join(directory, name), content);
    await body(root, (name) => join(directory, name));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
};

test('a caller digest is tested, scanned and attested inside a local callee', () => {
  const { report, status } = analyze('pipeline.yml');
  assert.equal(status, 0);
  assert.deepEqual(report.diagnostics, []);
  assert.deepEqual(report.findings, []);
  // The call is fully handled: no opaque boundary is left for it.
  assert.deepEqual(report.coverage, []);
  assert.deepEqual(report.deployments[0].checks, {
    test: 'proven',
    scan: 'proven',
    attest: 'proven',
  });
  const deploy = deployed(report);
  const consumers = report.operations.filter((item) => item.call);
  assert.deepEqual(
    consumers.map((item) => [item.kind, item.location.job, item.identity.key]),
    ['test', 'scan', 'attest'].map((kind) => [
      kind,
      `verify / ${kind}`,
      deploy?.identity.key,
    ]),
  );
  // Both source locations survive: the operation in the callee, the call in the caller.
  for (const item of consumers) {
    assert.equal(item.location.file, fixture('verify-image.yml'));
    assert.deepEqual(
      [item.call?.file, item.call?.line, item.call?.job, item.call?.workflow],
      [fixture('pipeline.yml'), 16, 'verify', fixture('verify-image.yml')],
    );
  }
  // The symbolic digest crosses the input as an identity, with every hop recorded.
  const trace = consumers[0].identity.trace;
  for (const hop of [
    'build.build: docker/build-push-action@v6',
    'needs.build.outputs.digest',
    '.github/workflows/pipeline.yml:19 job verify: with.digest',
    'call verify -> .github/workflows/verify-image.yml:9 workflow_call input digest',
    'inputs.digest',
    'verify / test step 1: docker run',
  ])
    assert.ok(trace.includes(hop), hop);
  assert.ok(
    trace.indexOf('needs.build.outputs.digest') < trace.indexOf('inputs.digest'),
  );
  assert.equal(report.calls.length, 1);
  assert.equal(report.calls[0].status, 'expanded');
  assert.equal(report.calls[0].inputs?.digest.value, deploy?.identity.key);
  assert.deepEqual(report.calls[0].jobs, [
    'verify / test',
    'verify / scan',
    'verify / attest',
  ]);

  const text = cli([fixture('pipeline.yml')]).stdout;
  assert.match(
    text,
    /CALL verify \(.*pipeline\.yml:16\) -> .*verify-image\.yml \[expanded\]/,
  );
  assert.match(text, /Artifact lineage verified within the supported analysis scope/);
  const explain = cli(['explain', fixture('pipeline.yml')]).stdout;
  assert.match(explain, /-> call verify -> \.github\/workflows\/verify-image\.yml:9/);
  const graph = cli(['graph', fixture('pipeline.yml')]).stdout;
  assert.match(
    graph,
    /-> test: .*pipeline\.yml#verify > .*verify-image\.yml#test\.1:1/,
  );
  assert.match(graph, /CALL verify/);
});

test('a callee that receives a different digest is a mismatch with evidence in both files', async () => {
  const { report, status } = analyze('pipeline-mismatch.yml');
  assert.equal(status, 1);
  assert.deepEqual(
    report.findings.map((finding) => [finding.ruleId, finding.state]),
    [
      ['SB002', 'mismatch'],
      ['SB003', 'mismatch'],
      ['SB004', 'mismatch'],
    ],
  );
  for (const finding of report.findings) {
    // The problem is the deployment in the caller; the callee is related evidence.
    assert.equal(finding.location.file, fixture('pipeline-mismatch.yml'));
    assert.equal(finding.location.line, 13);
    const [checked, deployment] = finding.evidence;
    assert.match(checked.reference, /@sha256:a{64}$/);
    assert.equal(checked.location?.file, fixture('verify-image.yml'));
    assert.equal(checked.call?.file, fixture('pipeline-mismatch.yml'));
    assert.equal(checked.call?.line, 5);
    assert.match(deployment.reference, /@sha256:b{64}$/);
    assert.equal(deployment.call, undefined);
  }
  const text = cli(['explain', fixture('pipeline-mismatch.yml')]).stdout;
  assert.match(
    text,
    /in .*verify-image\.yml:17 \(verify \/ test\), called from .*pipeline-mismatch\.yml:5 \(verify\)/,
  );

  const directory = await mkdtemp(join(tmpdir(), 'samebyte-sarif-'));
  try {
    const file = join(directory, 'report.sarif');
    const written = cli([
      fixture('pipeline-mismatch.yml'),
      '--format',
      'sarif',
      '--output',
      file,
    ]);
    assert.equal(written.status, 1, written.stderr);
    const validated = spawnSync(
      process.execPath,
      ['scripts/validate-sarif.mjs', file, 'SB002', 'SB003', 'SB004'],
      { encoding: 'utf8' },
    );
    assert.equal(validated.status, 0, validated.stderr);
    const [result] = JSON.parse(await readFile(file, 'utf8')).runs[0].results;
    const uri = (location: {
      physicalLocation: {
        artifactLocation: { uri: string };
        region: { startLine: number };
      };
    }) =>
      `${location.physicalLocation.artifactLocation.uri}:${location.physicalLocation.region.startLine}`;
    const base = 'tests/fixtures/reusable/.github/workflows';
    assert.equal(uri(result.locations[0]), `${base}/pipeline-mismatch.yml:13`);
    assert.deepEqual(result.relatedLocations.map(uri), [
      `${base}/verify-image.yml:17`,
      `${base}/pipeline-mismatch.yml:5`,
    ]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('a callee that rebuilds the image leaves the deployed digest unqualified', () => {
  // Caller and callee both have a job `build` with a step `build`, and the callee
  // also reuses the id `build` for its test step.
  const { report, status } = analyze('same-ids.yml');
  assert.equal(status, 0);
  const builds = report.operations.filter((item) => item.kind === 'build');
  assert.deepEqual(
    builds.map((item) => item.location.job),
    ['build', 'test / build'],
  );
  assert.notEqual(builds[0].identity.key, builds[1].identity.key);
  const tested = report.operations.find((item) => item.kind === 'test');
  // `needs.build` inside the callee is the callee's own build, not the caller's.
  assert.equal(tested?.identity.key, builds[1].identity.key);
  assert.equal(deployed(report)?.identity.key, builds[0].identity.key);
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.match(reasons(report).test, /Independent symbolic digests/);
  assert.equal(new Set(report.operations.map((item) => item.id)).size, 4);
  assert.equal(report.artifacts.length, 2);
});

test('a digest built by a callee returns through a workflow output', () => {
  const { report, status } = analyze('callee-build.yml');
  assert.equal(status, 0);
  assert.deepEqual(report.coverage, []);
  assert.equal(report.deployments[0].state, 'proven');
  const build = report.operations.find((item) => item.kind === 'build');
  assert.equal(build?.location.job, 'build / build');
  assert.equal(build?.location.file, fixture('build-image.yml'));
  assert.equal(build?.producedReference, 'ghcr.io/acme/api:release');
  const trace = deployed(report)?.identity.trace ?? [];
  // step output -> callee job output -> workflow output -> caller needs
  const hops = [
    'steps.build.outputs.digest',
    'jobs.build.outputs.digest',
    '.github/workflows/build-image.yml:10 workflow_call output digest',
    'call build (.github/workflows/callee-build.yml:5) output digest',
    'needs.build.outputs.digest',
  ];
  let last = -1;
  for (const hop of hops) {
    const index = trace.indexOf(hop, last + 1);
    assert.ok(index > last, hop);
    last = index;
  }
  assert.deepEqual(report.calls[0].inputs?.tags, {
    state: 'resolved',
    value: 'ghcr.io/acme/api:release',
    source: 'default',
    line: 6,
    path: report.calls[0].inputs?.tags.path,
  });
  assert.equal(report.calls[0].outputs?.digest.value, build?.identity.key);
});

test('two invocations of one callee keep separate identities and gates', () => {
  const { report, status } = analyze('two-calls.yml');
  assert.equal(status, 0);
  assert.equal(new Set(report.calls.map((call) => call.id)).size, 4);
  assert.equal(new Set(report.operations.map((item) => item.id)).size, 11);
  const [api, worker] = report.operations.filter((item) => item.kind === 'build');
  assert.notEqual(api.identity.key, worker.identity.key);
  const tests = report.operations.filter((item) => item.kind === 'test');
  assert.deepEqual(
    tests.map((item) => [item.location.job, item.identity.key, item.location.line]),
    [
      ['verify-api / test', api.identity.key, 17],
      ['verify-worker / test', worker.identity.key, 17],
    ],
  );
  assert.deepEqual(
    report.deployments.map((item) => item.state),
    ['proven', 'proven', 'unknown'],
  );
  // The third deployment ships the api digest but only waits for the worker call.
  assert.equal(deployed(report, 2)?.identity.key, api.identity.key);
  for (const kind of ['test', 'scan', 'attest'] as const) {
    const reason = report.deployments[2].checkReasons?.[kind];
    assert.match(
      reason?.reason ?? '',
      /call verify-api, but the deployment does not depend/,
    );
    assert.equal(reason?.call?.job, 'verify-api');
    assert.equal(reason?.file, fixture('verify-image.yml'));
  }
});

test('inputs follow declared types, defaults and required', () => {
  const { report } = analyze('typed-inputs.yml');
  const call = (job: string) => report.calls.find((item) => item.caller.job === job);
  const values = (job: string) =>
    Object.fromEntries(
      Object.entries(call(job)?.inputs ?? {}).map(([name, input]) => [
        name,
        [input.value, input.state, input.source],
      ]),
    );
  assert.deepEqual(values('defaults'), {
    image: ['ghcr.io/acme/api', 'resolved', 'with'],
    tag: ['stable', 'resolved', 'default'],
    push: ['true', 'resolved', 'default'],
    'dry-run': ['false', 'resolved', 'type-default'],
    retries: ['0', 'resolved', 'type-default'],
    shards: ['2', 'resolved', 'default'],
    note: ['', 'resolved', 'type-default'],
  });
  const explicit = values('explicit');
  assert.deepEqual(explicit.tag, ['v2', 'resolved', 'with']);
  assert.deepEqual(explicit.push, ['false', 'resolved', 'with']);
  assert.deepEqual(explicit['dry-run'], ['true', 'resolved', 'with']);
  assert.deepEqual(explicit.retries, ['3', 'resolved', 'with']);
  // An expression for a number input and a number for a string input stay unknown.
  assert.equal(explicit.shards[1], 'unknown');
  assert.deepEqual(explicit.note, ['7', 'unknown', 'with']);
  assert.match(
    call('explicit')?.inputs?.note.path[0] ?? '',
    /does not match declared type/,
  );
  assert.deepEqual(
    report.operations.map((item) => [item.location.job, item.identity.reference]),
    [
      ['defaults / test', 'ghcr.io/acme/api:stable'],
      ['explicit / test', 'ghcr.io/acme/api:v2'],
    ],
  );
  assert.equal(call('explicit')?.outputs?.reference.value, 'ghcr.io/acme/api:v2');
  // A call GitHub would reject is not expanded.
  for (const job of ['missing-required', 'undeclared']) {
    assert.equal(call(job)?.status, 'boundary');
    assert.equal(call(job)?.reason, 'reusable-workflow-contract');
  }
  assert.deepEqual(
    report.coverage.map((notice) => [notice.reason, notice.location.job]),
    [
      ['reusable-workflow-contract', 'missing-required'],
      ['reusable-workflow-contract', 'undeclared'],
    ],
  );
  assert.match(report.coverage[0].message, /required input image is not provided/);
  assert.match(report.coverage[1].message, /input registry is not declared/);
});

test('an unknown input or unsupported expression stays unknown inside the callee', () => {
  const { report, status } = analyze('unknown-input.yml');
  assert.equal(status, 0);
  assert.deepEqual(report.findings, []);
  assert.equal(report.calls[0].inputs?.image.state, 'unknown');
  assert.equal(report.calls[0].inputs?.digest.state, 'unknown');
  for (const item of report.operations.filter((op) => op.call)) {
    assert.equal(item.identity.kind, 'unknown');
    assert.ok(item.identity.trace.includes('Unresolved GitHub expression'));
    assert.ok(
      item.identity.trace.some((hop) =>
        /unknown-input\.yml:1[89] job verify: with\./.test(hop),
      ),
    );
  }
  assert.equal(deployed(report)?.identity.kind, 'immutable');
  assert.equal(report.deployments[0].state, 'unknown');
  assert.match(reasons(report).test, /unresolved artifact identity/);
});

test('a missing, unsupported or skippable output mapping confirms nothing', () => {
  const { report, status } = analyze('bad-outputs.yml');
  assert.equal(status, 0);
  const deployments = report.deployments.map((_, index) => deployed(report, index));
  assert.deepEqual(
    deployments.map((item) => item?.identity.kind),
    ['immutable', 'unknown', 'unknown', 'unknown', 'unknown', 'unknown'],
  );
  assert.ok(report.deployments.every((item) => item.state === 'unknown'));
  const why = (index: number) => deployments[index]?.identity.trace.join('\n') ?? '';
  assert.match(
    why(1),
    /references a job that does not exist in .*bad-outputs-callee\.yml/,
  );
  assert.match(
    why(1),
    /bad-outputs-callee\.yml:8 workflow_call output missing-job-digest/,
  );
  assert.match(why(2), /Callee job build .* declares no output with this name/);
  assert.match(why(3), /Unresolved GitHub expression/);
  assert.match(why(4), /Callee job optional is conditional/);
  // The name `image-digest` is not declared by the callee; a name proves nothing.
  assert.match(
    why(5),
    /declares no workflow_call output with this name \(call build\)/,
  );
  assert.deepEqual(
    Object.entries(report.calls[0].outputs ?? {}).map(([name, value]) => [
      name,
      value.state,
    ]),
    [
      ['digest', 'resolved'],
      ['missing-job-digest', 'unknown'],
      ['missing-output-digest', 'unknown'],
      ['computed-digest', 'unknown'],
      ['skipped-digest', 'unknown'],
    ],
  );
});

test('workflow-level env of the caller does not reach the callee', () => {
  const { report, status } = analyze('caller-env.yml');
  assert.equal(status, 0);
  const inside = report.operations.filter((item) => item.call);
  assert.deepEqual(
    inside.map((item) => [item.kind, item.identity.kind]),
    [
      ['test', 'unknown'],
      ['scan', 'unknown'],
    ],
  );
  assert.ok(inside[0].identity.trace.includes('Unresolved shell variable: IMAGE'));
  // The caller's own job still sees its env.
  assert.match(deployed(report)?.identity.reference ?? '', /@sha256:a{64}$/);
  assert.equal(report.deployments[0].state, 'unknown');
});

test('conditions and ignored failures inside a callee do not qualify a deployment', () => {
  const { report, status } = analyze('weak-gates.yml');
  assert.equal(status, 0);
  assert.deepEqual(report.findings, []);
  const deploy = deployed(report);
  // Every check references the deployed digest; only the gate is missing.
  for (const item of report.operations.filter((op) => op.call))
    assert.equal(item.identity.key, deploy?.identity.key);
  assert.deepEqual(report.deployments[0].checks, {
    test: 'unknown',
    scan: 'unknown',
    attest: 'unknown',
  });
  const why = reasons(report);
  assert.match(why.test, /Callee job verify \/ test is conditional/);
  assert.match(why.scan, /continue-on-error inside the reusable workflow/);
  // The attest job is unconditional but needs the conditional test job.
  assert.match(why.attest, /Callee job verify \/ test is conditional/);
  assert.equal(report.deployments[0].checkReasons?.test?.call?.line, 16);
});

test('a deployment that bypasses the call status is not qualified by it', () => {
  const { report } = analyze('always-deploy.yml');
  assert.equal(report.deployments[0].state, 'unknown');
  assert.match(reasons(report).test, /condition is not proven to run/);
});

test('nested, matrix, remote and secret boundaries are kept', () => {
  const { report, status } = analyze('boundaries.yml');
  assert.equal(status, 0);
  assert.deepEqual(
    report.coverage.map((notice) => [
      notice.reason,
      notice.location.job,
      notice.call?.job,
    ]),
    [
      ['nested-reusable-workflow-call', 'nested / inner', 'nested'],
      ['matrix-job', 'matrix', undefined],
      ['reusable-workflow-call', 'remote', undefined],
      ['reusable-workflow-secrets', 'secrets', undefined],
    ],
  );
  assert.equal(report.coverage[0].location.file, fixture('nested-callee.yml'));
  assert.match(report.coverage[2].message, /^Reusable workflow contents and outputs/);
  const status_ = (job: string) =>
    report.calls.find((call) => call.caller.job === job)?.status;
  assert.equal(status_('nested'), 'expanded');
  assert.equal(status_('nested / inner'), 'boundary');
  assert.equal(status_('remote'), 'boundary');
  // The first level of the nested callee is still observed.
  assert.ok(report.operations.some((item) => item.location.job === 'nested / scan'));
  assert.ok(
    !report.operations.some((item) => item.location.job.startsWith('nested / inner')),
  );
  // Matrix call operations are templates: guarded, never a gate.
  const templates = report.operations.filter((item) => item.call?.job === 'matrix');
  assert.equal(templates.length, 3);
  assert.ok(templates.every((item) => item.guarded && !item.guardedByJobCondition));
  // An output behind the nested call is unknown, and says where it was lost.
  const nested = deployed(report, 1);
  assert.equal(nested?.identity.kind, 'unknown');
  assert.match(
    nested?.identity.trace[0] ?? '',
    /call nested \/ inner is not expanded \(nested-reusable-workflow-call\)/,
  );
  const sarif = JSON.parse(
    cli([fixture('boundaries.yml'), '--format', 'sarif']).stdout,
  );
  const [notification] = sarif.runs[0].invocations[0].toolExecutionNotifications;
  assert.equal(notification.descriptor.id, 'nested-reusable-workflow-call');
  assert.deepEqual(
    notification.locations.map(
      (location: { physicalLocation: { artifactLocation: { uri: string } } }) =>
        location.physicalLocation.artifactLocation.uri.split('/').at(-1),
    ),
    ['nested-callee.yml', 'boundaries.yml'],
  );
});

test('unloadable callees are distinct boundaries and never read outside the root', async () => {
  const { report, status } = analyze('unloadable.yml');
  assert.equal(status, 0);
  assert.deepEqual(report.diagnostics, []);
  assert.deepEqual(
    report.coverage.map((notice) => [notice.location.job, notice.reason]),
    [
      ['missing', 'reusable-workflow-not-found'],
      ['escape', 'reusable-workflow-path'],
      ['elsewhere', 'reusable-workflow-path'],
      ['with-ref', 'reusable-workflow-path'],
      ['invalid-yaml', 'reusable-workflow-invalid'],
      ['not-callable', 'reusable-workflow-contract'],
      ['broken-contract', 'reusable-workflow-contract'],
    ],
  );
  assert.deepEqual(
    report.operations.map((item) => item.kind),
    ['deploy'],
  );
  assert.ok(report.calls.every((call) => call.status === 'boundary' && !call.workflow));
  assert.match(
    deployed(report)?.identity.trace[0] ?? '',
    /call missing is not expanded \(reusable-workflow-not-found\)/,
  );

  const outside = await realpath(await mkdtemp(join(tmpdir(), 'samebyte-outside-')));
  try {
    await copyFile(fixture('verify-image.yml'), join(outside, 'verify-image.yml'));
    const call = (name: string) =>
      `on: push\njobs:\n  verify:\n    uses: ./.github/workflows/${name}\n    with:\n      image: ghcr.io/acme/api\n      digest: sha256:${'a'.repeat(64)}\n`;
    await scratch(
      {
        'link.yml': call('linked.yml'),
        'large.yml': call('huge.yml'),
        'huge.yml': `on: workflow_call\n#${' '.repeat(1024 * 1024)}\njobs: {}\n`,
      },
      async (_root, workflow) => {
        // A symbolic link inside .github/workflows that points out of the repository.
        await symlink(join(outside, 'verify-image.yml'), workflow('linked.yml'));
        const linked = json(workflow('link.yml')).report;
        assert.equal(linked.coverage[0].reason, 'reusable-workflow-path');
        assert.match(
          linked.coverage[0].message,
          /resolves outside the analyzed repository/,
        );
        assert.deepEqual(linked.operations, []);
        const large = json(workflow('large.yml')).report;
        assert.equal(large.coverage[0].reason, 'reusable-workflow-invalid');
        assert.match(large.coverage[0].message, /exceeds 1048576 bytes/);
      },
    );
  } finally {
    await rm(outside, { recursive: true, force: true });
  }
});

test('the callee is located from the repository root, not the working directory', async () => {
  const expected = analyze('pipeline.yml').report;
  const elsewhere = await realpath(await mkdtemp(join(tmpdir(), 'samebyte-cwd-')));
  try {
    // A decoy with the same relative path under the working directory is ignored.
    await mkdir(join(elsewhere, '.github/workflows'), { recursive: true });
    await writeFile(
      join(elsewhere, '.github/workflows/verify-image.yml'),
      'on: workflow_call\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo decoy\n',
    );
    assert.deepEqual(json(fixture('pipeline.yml'), elsewhere).report, expected);
    assert.deepEqual(
      json('.github/workflows/pipeline.yml', repository).report,
      expected,
    );
    assert.deepEqual(json('pipeline.yml', workflows).report, expected);
  } finally {
    await rm(elsewhere, { recursive: true, force: true });
  }
});

test('a workflow outside .github/workflows has no root and keeps the opaque boundary', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'samebyte-rootless-'));
  try {
    const file = join(directory, 'pipeline.yml');
    await copyFile(fixture('pipeline.yml'), file);
    await copyFile(fixture('verify-image.yml'), join(directory, 'verify-image.yml'));
    const { report } = json(file);
    assert.equal(report.coverage[0].reason, 'reusable-workflow-call');
    assert.match(report.coverage[0].message, /no repository root is established/);
    assert.deepEqual(
      report.operations.map((item) => item.kind),
      ['build', 'deploy'],
    );
    assert.equal(report.deployments[0].state, 'unknown');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('a directory run reports a reusable-only workflow per invocation, not as an entry point', () =>
  scratch(
    {
      'pipeline.yml': 'copy:pipeline.yml',
      'verify-image.yml': 'copy:verify-image.yml',
      'build-image.yml': 'copy:build-image.yml',
    },
    async (root, workflow) => {
      for (const input of [root, join(root, '.github/workflows')]) {
        const { report, status } = json(input);
        assert.equal(status, 0);
        // The called workflow appears once, through its invocation. The uncalled
        // reusable workflow is still analyzed by itself.
        assert.deepEqual(report.workflows, [
          workflow('build-image.yml'),
          workflow('pipeline.yml'),
        ]);
        assert.deepEqual(
          report.operations.map((item) => [item.kind, item.location.job, !!item.call]),
          [
            ['build', 'build', false],
            ['build', 'build', false],
            ['test', 'verify / test', true],
            ['scan', 'verify / scan', true],
            ['attest', 'verify / attest', true],
            ['deploy', 'deploy', false],
          ],
        );
        assert.equal(report.deployments[0].state, 'proven');
      }
      // Asked for directly, the callee has no inputs: nothing links it to a caller.
      const alone = json(workflow('verify-image.yml')).report;
      assert.deepEqual(alone.calls, []);
      assert.deepEqual(
        alone.operations.map((item) => [item.identity.kind, item.call]),
        [
          ['unknown', undefined],
          ['unknown', undefined],
          ['unknown', undefined],
        ],
      );
      assert.ok(
        alone.operations[0].identity.trace.includes('Unresolved GitHub expression'),
      );
    },
  ));

test('a deployment inside a callee is gated by the caller through the call', () => {
  const caller = (condition: string) => `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digest: \${{ steps.build.outputs.digest }}
    steps:
      - id: build
        uses: docker/build-push-action@v6
        with:
          push: true
          tags: ghcr.io/acme/api:release
      - run: docker run --rm ghcr.io/acme/api@\${{ steps.build.outputs.digest }} npm test
  deploy:
    needs: build
${condition}    uses: ./.github/workflows/deploy.yml
    with:
      image: ghcr.io/acme/api@\${{ needs.build.outputs.digest }}
`;
  const callee = `on:
  workflow_call:
    inputs:
      image:
        type: string
        required: true
jobs:
  rollout:
    runs-on: ubuntu-latest
    steps:
      - run: kubectl set image deployment/api api=\${{ inputs.image }}
`;
  return scratch(
    {
      'gated.yml': caller(''),
      'always.yml': caller('    if: always()\n'),
      'never.yml': caller('    if: false\n'),
      'deploy.yml': callee,
    },
    async (_root, workflow) => {
      const gated = json(workflow('gated.yml')).report;
      assert.equal(gated.deployments[0].checks.test, 'proven');
      assert.equal(deployed(gated)?.location.job, 'deploy / rollout');
      // The call itself can run after a failed test.
      const always = json(workflow('always.yml')).report;
      assert.equal(always.deployments[0].checks.test, 'unknown');
      // A call that never runs contributes no deployment.
      const never = json(workflow('never.yml')).report;
      assert.deepEqual(never.deployments, []);
      assert.deepEqual(
        never.operations.map((item) => item.kind),
        ['build', 'test'],
      );
    },
  );
});

test('a disabled job inside a callee does not hide a deployment in the caller', () =>
  scratch(
    {
      'caller.yml': `on: push
jobs:
  call:
    uses: ./.github/workflows/callee.yml
  deploy:
    needs: call
    runs-on: ubuntu-latest
    steps:
      - run: kubectl set image deployment/api api=ghcr.io/acme/api:latest
`,
      'callee.yml': `on:
  workflow_call:
jobs:
  off:
    if: false
    runs-on: ubuntu-latest
    steps:
      - run: docker run --rm ghcr.io/acme/api:latest npm test
  dependent:
    needs: off
    runs-on: ubuntu-latest
    steps:
      - run: docker run --rm ghcr.io/acme/api:latest npm test
`,
    },
    async (_root, workflow) => {
      const { report, status } = json(workflow('caller.yml'));
      // The mutable deployment is still reported; the jobs that never run are not.
      assert.equal(status, 1);
      assert.deepEqual(
        report.findings.map((finding) => finding.ruleId),
        ['SB005'],
      );
      assert.deepEqual(
        report.operations.map((item) => [item.kind, item.location.job]),
        [['deploy', 'deploy']],
      );
    },
  ));

test('a long chain of calls with an unproven gate is analyzed in bounded time', () => {
  const callee = `on:
  workflow_call:
    inputs:
      image:
        type: string
        required: true
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - if: github.ref == 'refs/heads/main'
        uses: aquasecurity/trivy-action@0.33.1
        with:
          image-ref: \${{ inputs.image }}
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo lint
  unit:
    runs-on: ubuntu-latest
    steps:
      - run: echo unit
`;
  const image = `ghcr.io/acme/api@sha256:${'a'.repeat(64)}`;
  const jobs = ['on: push', 'jobs:'];
  const depth = 16;
  for (let index = 1; index <= depth; index++)
    jobs.push(
      `  call${index}:`,
      ...(index > 1 ? [`    needs: call${index - 1}`] : []),
      '    uses: ./.github/workflows/callee.yml',
      '    with:',
      `      image: ${image}`,
    );
  jobs.push(
    '  deploy:',
    `    needs: call${depth}`,
    '    runs-on: ubuntu-latest',
    '    steps:',
    `      - run: kubectl set image deployment/api api=${image}`,
  );
  return scratch(
    { 'chain.yml': `${jobs.join('\n')}\n`, 'callee.yml': callee },
    async (_root, workflow) => {
      const result = spawnSync(
        process.execPath,
        [bundle, workflow('chain.yml'), '--format', 'json'],
        { encoding: 'utf8', timeout: 10000 },
      );
      assert.equal(result.error, undefined, String(result.error));
      assert.equal(result.status, 0, result.stderr);
      const report: Report = JSON.parse(result.stdout);
      assert.equal(report.calls.length, depth);
      assert.equal(report.deployments[0].checks.scan, 'unknown');
    },
  );
});

test('workflows without reusable calls keep their previous report', () => {
  const { report, status } = json('tests/fixtures/correct.yml');
  assert.equal(status, 0);
  assert.deepEqual(report.calls, []);
  assert.equal(report.version, 1);
  assert.equal(report.deployments[0].state, 'proven');
  assert.doesNotMatch(JSON.stringify(report), /"call"|callEntry/);
  assert.doesNotMatch(cli(['tests/fixtures/correct.yml']).stdout, /CALL|called from/);
  const sarif = cli(['tests/fixtures/rebuild.yml', '--format', 'sarif']).stdout;
  assert.doesNotMatch(sarif, /relatedLocations/);
});

test('the packaged action expands local calls from the workspace', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'samebyte-action-')));
  try {
    const workspace = join(root, 'workspace');
    const action = join(root, 'action');
    await mkdir(join(workspace, '.github/workflows'), { recursive: true });
    await mkdir(action);
    await copyFile(resolve('action/index.mjs'), join(action, 'index.mjs'));
    for (const name of ['pipeline.yml', 'pipeline-mismatch.yml', 'verify-image.yml'])
      await copyFile(fixture(name), join(workspace, '.github/workflows', name));
    const run = (path: string) =>
      spawnSync(process.execPath, [join(action, 'index.mjs')], {
        encoding: 'utf8',
        // The action resolves paths against the workspace, not this directory.
        cwd: root,
        env: {
          PATH: process.env.PATH ?? '',
          GITHUB_WORKSPACE: workspace,
          INPUT_PATH: path,
          INPUT_FORMAT: 'json',
        },
      });
    const single = run('.github/workflows/pipeline.yml');
    assert.equal(single.status, 0, single.stderr);
    const report: Report = JSON.parse(single.stdout);
    assert.equal(report.deployments[0].state, 'proven');
    assert.equal(
      report.calls[0].workflow,
      join(workspace, '.github/workflows/verify-image.yml'),
    );
    // The same analysis as the CLI on the same files.
    assert.deepEqual(report, json('.github/workflows/pipeline.yml', workspace).report);
    const whole = run('.');
    assert.equal(whole.status, 1, whole.stderr);
    const all: Report = JSON.parse(whole.stdout);
    assert.deepEqual(
      all.workflows.map((file) => file.split('/').at(-1)),
      ['pipeline-mismatch.yml', 'pipeline.yml'],
    );
    assert.deepEqual(
      all.findings.map((finding) => finding.ruleId),
      ['SB002', 'SB003', 'SB004'],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
