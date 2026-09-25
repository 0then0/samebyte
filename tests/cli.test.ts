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
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
