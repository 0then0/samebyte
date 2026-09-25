import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const cli = (...args: string[]) =>
  spawnSync(process.execPath, ['dist/cli.js', ...args], { encoding: 'utf8' });
test('CLI exit codes and JSON/SARIF output', () => {
  const good = cli('tests/fixtures/correct.yml', '--format', 'json');
  assert.equal(good.status, 0, good.stderr);
  assert.equal(JSON.parse(good.stdout).deployments[0].state, 'proven');
  assert.equal(cli('tests/fixtures/rebuild.yml').status, 1);
  assert.equal(cli('tests/fixtures/unknown.yml').status, 0);
  assert.equal(cli('--format', 'invalid').status, 2);
  assert.equal(cli('/nonexistent/samebyte.yml').status, 2);
  const sarif = cli('tests/fixtures/rebuild.yml', '--format', 'sarif');
  assert.equal(sarif.status, 1);
  assert.equal(JSON.parse(sarif.stdout).runs[0].results[0].ruleId, 'SB001');
});
test('graph, explain, help and version are runnable', () => {
  assert.match(cli('graph', 'tests/fixtures/correct.yml').stdout, /artifact-1/);
  assert.match(cli('explain', 'tests/fixtures/correct.yml').stdout, /proven/);
  assert.match(cli('--help').stdout, /Usage:/);
  assert.equal(cli('--version').stdout.trim(), '0.1.0');
});
test('skipped deployments exit successfully and are absent from JSON and graph', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'samebyte-test-'));
  try {
    const file = join(dir, 'skipped.yml');
    await writeFile(
      file,
      `jobs:\n  disabled:\n    if: false\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo disabled\n  deploy:\n    needs: disabled\n    if: inputs.mode == 'always()'\n    runs-on: ubuntu-latest\n    steps:\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api:latest\n`,
    );
    const result = cli(file, '--format', 'json');
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.deepEqual(report.findings, []);
    assert.deepEqual(report.deployments, []);
    assert.deepEqual(report.operations, []);
    assert.deepEqual(report.artifacts, []);
    const graph = cli('graph', file);
    assert.equal(graph.status, 0, graph.stderr);
    assert.doesNotMatch(graph.stdout, /deploy|artifact-1/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test('invalid and empty workflows produce analysis errors', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'samebyte-test-'));
  try {
    assert.equal(cli(dir).status, 2);
    await writeFile(join(dir, 'invalid.yml'), 'jobs: []');
    const result = cli(dir, '--format', 'json');
    assert.equal(result.status, 2);
    assert.equal(JSON.parse(result.stdout).diagnostics.length, 1);
    const invalidOutput = cli('tests/fixtures/invalid-output.yml', '--format', 'json');
    assert.equal(invalidOutput.status, 2);
    assert.match(JSON.parse(invalidOutput.stdout).diagnostics[0].message, /outputs/);
    await writeFile(
      join(dir, 'parallel.yml'),
      'jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - parallel:\n          - run: docker run ghcr.io/acme/api:latest\n',
    );
    const parallel = cli(join(dir, 'parallel.yml'), '--format', 'json');
    assert.equal(parallel.status, 2);
    assert.match(JSON.parse(parallel.stdout).diagnostics[0].message, /parallel block/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
