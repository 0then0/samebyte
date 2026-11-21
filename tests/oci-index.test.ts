import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { analyzeWorkflow } from '../src/analyzer.js';
import type { PlatformCoverage, Report } from '../src/model.js';
import { parsePublication } from '../src/oci-index.js';
import { parseWorkflow } from '../src/parser.js';

const fixture = 'tests/fixtures/buildx-index.oci';
const bytes = readFileSync(fixture);
const index = 'sha256:2d6d4232ce3e8768f2065321bab375fd2aedc850a8424028cb274ca5c1007705';
const amd64 = 'sha256:639224179b629b1a43ed84427ca56d13a604aea8befbcea7b5e7126162409249';
const arm64 = 'sha256:5f3ce6173b8dea1d681ae6ab53dbacec92012831a5443c4c567062417951a8cc';
// Independent arm64 export with an additional image label.
const other = 'sha256:fd4d45fbfcdfcc0085df857ba5b793e3f9e486c1b670acc3e9a162ee1d555a46';
const repo = 'ghcr.io/example/smoke';
const image = (digest: string) => `${repo}@${digest}`;
const digestOf = (content: Uint8Array) =>
  `sha256:${createHash('sha256').update(content).digest('hex')}`;
const pin = (digest: string, flags = '') =>
  `docker run --rm ${flags ? `${flags} ` : ''}${image(digest)}`;
const copy = (digest: string) =>
  `docker buildx imagetools create --tag ${repo}:release ${image(digest)}`;
const binding = { job: 'release', step: 'publish', reference: image(index) };
const shellStep = (command: string) => `      - run: ${JSON.stringify(command)}`;
const publication = (command: string) => `      - id: publish
        run: ${JSON.stringify(command)}`;
const workflow = (
  amdCommand: string,
  armCommand?: string,
  release = copy(index),
) => `jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
${shellStep(amdCommand)}
${armCommand ? shellStep(armCommand) : ''}
  release:
    needs: verify
    runs-on: ubuntu-latest
    steps:
${publication(release)}
`;
const analyze = (yaml: string, content: Uint8Array = bytes, rawBinding = binding) =>
  analyzeWorkflow(parseWorkflow(yaml, 'release.yml'), undefined, undefined, {
    file: fixture,
    bytes: content,
    binding: parsePublication(rawBinding),
    bindingFile: 'publication.json',
  });
const statuses = (coverage: PlatformCoverage | undefined) => {
  assert.ok(coverage);
  return coverage.manifests.map(({ platform, status }) => [platform, status]);
};
const platforms = (coverage: PlatformCoverage | undefined) =>
  statuses(coverage).slice(0, 2);
const cli = (...args: string[]) =>
  spawnSync(process.execPath, ['dist/cli.js', ...args], { encoding: 'utf8' });

test('the offline CLI measures the real Buildx index across three release workflows', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'samebyte-index-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const bindingFile = join(dir, 'publication.json');
  const yaml = join(dir, 'release.yml');
  await writeFile(bindingFile, JSON.stringify(binding));
  const args = [yaml, '--oci-index', fixture, '--publication', bindingFile];

  for (const [command, expected] of [
    [undefined, 'unknown'],
    [pin(arm64, '--platform=linux/arm64'), 'proven'],
    [pin(other, '--platform linux/arm64'), 'mismatch'],
  ] as const) {
    await writeFile(yaml, workflow(pin(amd64), command));
    const result = cli(...args, '--format', 'json');
    assert.equal(result.status, 0, result.stderr);
    const { platformCoverage } = JSON.parse(result.stdout) as Report;
    assert.ok(platformCoverage);
    assert.equal(platformCoverage.index.digest, index);
    assert.equal(platformCoverage.index.actualDigest, index);
    assert.equal(platformCoverage.index.status, 'verified');
    assert.equal(platformCoverage.publication.evidence, 'input');
    assert.equal(platformCoverage.publication.location?.job, 'release');
    assert.deepEqual(statuses(platformCoverage), [
      ['linux/amd64', 'proven'],
      ['linux/arm64', expected],
      ['unknown/unknown', 'service'],
      ['unknown/unknown', 'service'],
    ]);
    assert.equal(platformCoverage.manifests[0].digest, amd64);
    assert.equal(platformCoverage.manifests[0].test?.reference, image(amd64));
    assert.equal(platformCoverage.manifests[1].digest, arm64);
    assert.equal(
      platformCoverage.manifests[1].test?.reference,
      command ? image(expected === 'proven' ? arm64 : other) : undefined,
    );
    if (command)
      assert.equal(platformCoverage.manifests[1].test?.location.job, 'verify');
  }

  for (const mode of ['check', 'explain', 'graph']) {
    const result = cli(mode, ...args);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, new RegExp(`linux/arm64 ${arm64} \\[mismatch\\]`));
    assert.match(result.stdout, /Publication binding supplied as input evidence/);
    assert.doesNotMatch(result.stdout, /Unknown test identity/);
  }
  const sarif = cli(...args, '--format', 'sarif');
  assert.equal(sarif.status, 0, sarif.stderr);
  const sarifCoverage = JSON.parse(sarif.stdout).runs[0].invocations[0].properties
    .platformCoverage;
  assert.equal(sarifCoverage.manifests[1].status, 'mismatch');

  const tampered = join(dir, 'changed.oci');
  await writeFile(tampered, Buffer.concat([bytes, Buffer.from('\n')]));
  const rejected = cli(
    yaml,
    '--oci-index',
    tampered,
    '--publication',
    bindingFile,
    '--format',
    'json',
  );
  assert.equal(rejected.status, 2, rejected.stderr);
  const rejectedReport = JSON.parse(rejected.stdout) as Report;
  assert.equal(rejectedReport.platformCoverage?.index.status, 'mismatch');
  assert.deepEqual(rejectedReport.platformCoverage?.manifests, []);

  const baseline = cli('tests/fixtures/correct.yml', '--format', 'json');
  assert.equal(baseline.status, 0, baseline.stderr);
  const legacy = JSON.parse(baseline.stdout) as Report;
  assert.equal(legacy.platformCoverage, undefined);
  assert.equal(legacy.deployments[0].state, 'proven');
  assert.equal(cli(yaml, '--oci-index', fixture).status, 2);
  assert.equal(cli(dir, ...args.slice(1)).status, 2);

  await writeFile(
    bindingFile,
    JSON.stringify(binding).replace('{', '{"step":"other",'),
  );
  const ambiguous = cli(...args);
  assert.equal(ambiguous.status, 2);
  assert.match(
    ambiguous.stderr,
    /Publication binding contains duplicate JSON object keys/,
  );
});

test('byte tampering and malformed indexes cannot prove any child', () => {
  const altered = Buffer.concat([bytes, Buffer.from('\n')]);
  const tampered = analyze(workflow(pin(amd64)), altered);
  assert.equal(tampered.platformCoverage?.index.status, 'mismatch');
  assert.equal(tampered.platformCoverage?.index.actualDigest, digestOf(altered));
  assert.deepEqual(tampered.platformCoverage?.manifests, []);
  assert.match(tampered.diagnostics[0].message, /bytes do not match/);

  for (const bad of [Buffer.from('{'), Buffer.from([0xff])]) {
    const digest = digestOf(bad);
    const report = analyze(workflow(pin(amd64), undefined, copy(digest)), bad, {
      ...binding,
      reference: image(digest),
    });
    assert.equal(report.platformCoverage?.index.status, 'invalid');
    assert.deepEqual(report.platformCoverage?.manifests, []);
    assert.match(report.diagnostics[0].message, /valid UTF-8 JSON/);
  }
  const duplicateKey = bytes
    .toString('utf8')
    .replace('"schemaVersion": 2', '"schemaVersion": 1, "schemaVersion": 2');
  assert.notEqual(duplicateKey, bytes.toString('utf8'));
  const duplicateBytes = Buffer.from(duplicateKey);
  const duplicateDigest = digestOf(duplicateBytes);
  const duplicateReport = analyze(
    workflow(pin(amd64), undefined, copy(duplicateDigest)),
    duplicateBytes,
    { ...binding, reference: image(duplicateDigest) },
  );
  assert.equal(duplicateReport.platformCoverage?.index.status, 'invalid');
  assert.match(duplicateReport.diagnostics[0].message, /duplicate JSON object keys/);

  for (const fields of [
    { digest: 'sha256:nope' },
    { size: -1 },
    { platform: { os: 'linux', architecture: 'arm64', variant: 'v8/extra' } },
    { size: 3, data: 'eHl6' },
  ]) {
    const raw = JSON.parse(bytes.toString('utf8'));
    Object.assign(raw.manifests[1], fields);
    const report = withIndex(raw, pin(amd64), pin(arm64));
    assert.equal(report.platformCoverage?.index.status, 'invalid');
    assert.deepEqual(
      platforms(report.platformCoverage).map(([, status]) => status),
      ['unknown', 'invalid'],
    );
  }
});

function withIndex(raw: unknown, amdCommand: string, armCommand?: string) {
  const content = Buffer.from(JSON.stringify(raw));
  const digest = digestOf(content);
  return analyze(workflow(amdCommand, armCommand, copy(digest)), content, {
    ...binding,
    reference: image(digest),
  });
}

test('conflicting descriptors stay visible and cannot qualify a platform', () => {
  const raw = JSON.parse(bytes.toString('utf8'));
  const arm = raw.manifests[1];
  raw.manifests.push({
    ...arm,
    digest: other,
    platform: { ...arm.platform, variant: 'v8' },
  });
  raw.manifests.push({
    ...raw.manifests[2],
    annotations: {},
    digest: `sha256:${'a'.repeat(64)}`,
  });
  raw.manifests.push({
    mediaType: raw.mediaType,
    size: 47,
    digest: `sha256:${'b'.repeat(64)}`,
  });
  const report = withIndex(raw, pin(amd64), pin(arm64));
  assert.deepEqual(report.diagnostics, []);
  assert.deepEqual(statuses(report.platformCoverage), [
    ['linux/amd64', 'proven'],
    ['linux/arm64', 'unknown'],
    ['unknown/unknown', 'service'],
    ['unknown/unknown', 'service'],
    ['linux/arm64/v8', 'unknown'],
    ['unknown/unknown', 'unsupported'],
    [undefined, 'unsupported'],
  ]);
  assert.match(
    report.platformCoverage?.manifests[1].reason ?? '',
    /multiple descriptors/,
  );

  raw.manifests[2].digest = amd64;
  const conflictingDigest = withIndex(raw, pin(amd64), pin(arm64));
  assert.equal(conflictingDigest.platformCoverage?.manifests[0].status, 'unknown');
});

test('runtime-equivalent platform aliases and variants are ambiguous', () => {
  const raw = JSON.parse(bytes.toString('utf8'));
  for (const platform of [
    { os: 'linux', architecture: 'arm64', variant: 'v8.0' },
    { os: 'linux', architecture: 'aarch64' },
  ]) {
    raw.manifests[1].platform = { os: 'linux', architecture: 'arm64' };
    raw.manifests.push({ ...raw.manifests[1], digest: other, platform });
    const report = withIndex(raw, pin(amd64), pin(arm64));
    assert.equal(report.platformCoverage?.manifests[0].status, 'proven');
    for (const item of [
      report.platformCoverage?.manifests[1],
      report.platformCoverage?.manifests.at(-1),
    ]) {
      assert.equal(item?.status, 'unknown');
      assert.match(item.reason, /multiple descriptors/);
    }
    raw.manifests.pop();
  }
});

test('a job container can set the Docker platform selector', () => {
  const yaml = workflow(pin(amd64), pin(arm64)).replace(
    '    runs-on: ubuntu-latest',
    `    runs-on: ubuntu-latest
    container:
      image: docker:29-cli
      env:
        DOCKER_DEFAULT_PLATFORM: linux/arm64`,
  );
  const coverage = analyze(yaml).platformCoverage;
  assert.deepEqual(platforms(coverage), [
    ['linux/amd64', 'unknown'],
    ['linux/arm64', 'proven'],
  ]);
  assert.equal(coverage?.manifests[0].test?.selector, 'linux/arm64');
  for (const step of [
    shellStep(pin(amd64, '--platform=linux/amd64')),
    shellStep(pin(amd64)) +
      '\n        env:\n          DOCKER_DEFAULT_PLATFORM: linux/amd64',
  ]) {
    const overridden = analyze(yaml.replace(shellStep(pin(amd64)), step));
    assert.equal(overridden.platformCoverage?.manifests[0].status, 'proven');
  }
});

test('only explicit child pins and compatible platform selectors qualify', () => {
  const raw = JSON.parse(bytes.toString('utf8'));
  raw.manifests[1].platform.variant = 'v9';
  const bad = withIndex(raw, pin(amd64), pin(arm64, '--platform linux/arm64/v8'));
  assert.equal(bad.platformCoverage?.manifests[1].status, 'unknown');
  assert.match(bad.platformCoverage?.manifests[1].reason ?? '', /conflicts/);
  const good = withIndex(raw, pin(amd64), pin(arm64, '--platform linux/arm64/v9'));
  assert.equal(good.platformCoverage?.manifests[1].status, 'proven');

  for (const command of [
    pin(index, '--platform linux/arm64'),
    `docker run --platform linux/arm64 ${repo}:candidate`,
    `docker run --platform linux/arm64 ghcr.io/example/other@${arm64}`,
    pin(other),
  ]) {
    const yaml = workflow(pin(amd64), command).replace(
      'ubuntu-latest',
      'ubuntu-24.04-arm',
    );
    assert.equal(
      analyze(yaml).platformCoverage?.manifests[1].status,
      'unknown',
      command,
    );
  }
  for (const command of [
    '--platform linux/amd64',
    '--platform=linux/arm64 --platform=linux/amd64',
  ]) {
    assert.equal(
      analyze(workflow(pin(amd64), pin(arm64, command))).platformCoverage?.manifests[1]
        .status,
      'unknown',
    );
  }
  const withDefault = workflow(pin(amd64), pin(arm64)).replace(
    shellStep(pin(arm64)),
    shellStep(pin(arm64)) +
      '\n        env:\n          DOCKER_DEFAULT_PLATFORM: linux/amd64',
  );
  assert.equal(analyze(withDefault).platformCoverage?.manifests[1].status, 'unknown');
  const writeDefault = 'echo "DOCKER_DEFAULT_PLATFORM=linux/amd64" >> "$GITHUB_ENV"';
  const mutatedEnv = workflow(pin(amd64), pin(arm64)).replace(
    shellStep(pin(arm64)),
    `${shellStep(writeDefault)}\n${shellStep(pin(arm64))}`,
  );
  assert.equal(analyze(mutatedEnv).platformCoverage?.manifests[1].status, 'unknown');
  assert.equal(
    analyze(mutatedEnv.replace(pin(arm64), pin(arm64, '--platform=linux/arm64')))
      .platformCoverage?.manifests[1].status,
    'proven',
  );
});

test('the test must finish successfully before the selected publication can run', () => {
  const yaml = workflow(pin(amd64), pin(arm64));
  const armStep = shellStep(pin(arm64));
  for (const condition of [
    "        if: github.ref == 'refs/heads/main'",
    '        if: false',
    '        continue-on-error: true',
  ]) {
    const report = analyze(yaml.replace(armStep, `${armStep}\n${condition}`));
    assert.deepEqual(platforms(report.platformCoverage), [
      ['linux/amd64', 'proven'],
      ['linux/arm64', 'unknown'],
    ]);
  }
  for (const changed of [
    yaml.replace('    needs: verify\n', ''),
    yaml.replace(
      '      - id: publish\n',
      '      - id: publish\n        if: always()\n',
    ),
  ]) {
    assert.deepEqual(platforms(analyze(changed).platformCoverage), [
      ['linux/amd64', 'unknown'],
      ['linux/arm64', 'unknown'],
    ]);
  }
});

test('the binding is scoped to one publication and respects concrete identity', () => {
  const yaml = workflow(pin(amd64), pin(arm64));
  for (const [source, declared, reason] of [
    [yaml, { ...binding, step: 'missing' }, /supported publication step/],
    [
      yaml,
      { ...binding, reference: `ghcr.io/example/other@${index}` },
      /repository differs/,
    ],
    [workflow(pin(amd64), pin(arm64), copy(amd64)), binding, /digest differs/],
    [
      yaml.replace('imagetools create', 'imagetools create --dry-run'),
      binding,
      /supported publication step/,
    ],
  ] as const) {
    const report = analyze(source, bytes, declared);
    assert.equal(report.platformCoverage?.publication.status, 'unresolved');
    assert.match(report.diagnostics[0].message, reason);
    assert.deepEqual(platforms(report.platformCoverage), [
      ['linux/amd64', 'unknown'],
      ['linux/arm64', 'unknown'],
    ]);
  }

  const push = `      - id: publish
        uses: docker/build-push-action@v7
        with:
          platforms: linux/amd64,linux/arm64
          push: true
          tags: ${repo}:release`;
  const declaredPush = yaml.replace(publication(copy(index)), push);
  const baseline = analyzeWorkflow(parseWorkflow(declaredPush, 'release.yml'));
  const { platformCoverage, ...withBinding } = analyze(declaredPush);
  assert.deepEqual(withBinding, baseline);
  assert.equal(platformCoverage?.publication.evidence, 'input');
  assert.deepEqual(platforms(platformCoverage), [
    ['linux/amd64', 'proven'],
    ['linux/arm64', 'proven'],
  ]);

  const merge = [
    `docker buildx imagetools create --tag ${repo}:release`,
    image('${{ steps.amd.outputs.digest }}'),
    image('${{ steps.arm.outputs.digest }}'),
  ].join(' ');
  const symbolicSources = `      - id: amd
        uses: docker/build-push-action@v7
        with:
          platforms: linux/amd64
      - id: arm
        uses: docker/build-push-action@v7
        with:
          platforms: linux/arm64
`;
  const assembled = analyze(
    yaml.replace(publication(copy(index)), symbolicSources + publication(merge)),
  );
  assert.equal(assembled.platformCoverage?.publication.evidence, 'input');
  assert.deepEqual(platforms(assembled.platformCoverage), [
    ['linux/amd64', 'proven'],
    ['linux/arm64', 'proven'],
  ]);
  assert.equal(assembled.operations.filter((op) => op.kind === 'build').length, 2);
  assert.ok(
    assembled.operations
      .filter((op) => op.kind === 'build')
      .every((op) => op.identity.kind === 'immutable' && !op.identity.concrete),
  );
});

test('a standalone manifest merge cannot bind an index with extra descriptors', () => {
  const command = `${copy(amd64)} ${image(arm64)}`;
  const yaml = workflow(pin(amd64), pin(arm64), command);
  const rejected = analyze(yaml);
  assert.equal(rejected.platformCoverage?.publication.status, 'unresolved');
  assert.match(rejected.diagnostics[0].message, /standalone manifest sources/);
  assert.deepEqual(platforms(rejected.platformCoverage), [
    ['linux/amd64', 'unknown'],
    ['linux/arm64', 'unknown'],
  ]);

  const raw = JSON.parse(bytes.toString('utf8'));
  raw.manifests = raw.manifests.slice(0, 2);
  const content = Buffer.from(JSON.stringify(raw));
  const accepted = analyze(yaml, content, {
    ...binding,
    reference: image(digestOf(content)),
  });
  assert.equal(accepted.platformCoverage?.publication.evidence, 'input');
  assert.deepEqual(platforms(accepted.platformCoverage), [
    ['linux/amd64', 'proven'],
    ['linux/arm64', 'proven'],
  ]);
});
