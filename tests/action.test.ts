import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFile,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { parseDocument } from 'yaml';

const bundle = resolve('action/index.mjs');
const fixtures = resolve('tests/fixtures');
const unsafe = 'out put; $(touch PWNED) `touch PWNED` \'q\' "d" ünï & %.sarif';

// Mirrors the runner: a workspace with the checked-out repository, an isolated
// copy of the bundle without package.json or node_modules, and inputs as INPUT_*.
async function sandbox() {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'samebyte-action-')));
  const workspace = join(root, 'work space');
  const action = join(root, 'action dir');
  await mkdir(join(workspace, '.github/workflows'), { recursive: true });
  await mkdir(action);
  await copyFile(bundle, join(action, 'index.mjs'));
  for (const name of ['correct', 'rebuild'])
    await copyFile(
      join(fixtures, `${name}.yml`),
      join(workspace, '.github/workflows', `${name}.yml`),
    );
  const githubOutput = join(root, 'github_output');
  await writeFile(githubOutput, '');
  const run = (inputs: Record<string, string | undefined>) => {
    const env: Record<string, string> = {
      PATH: process.env.PATH ?? '',
      GITHUB_WORKSPACE: workspace,
      GITHUB_OUTPUT: githubOutput,
    };
    for (const [name, value] of Object.entries(inputs))
      if (value !== undefined) env[`INPUT_${name.toUpperCase()}`] = value;
    return spawnSync(process.execPath, [join(action, 'index.mjs')], {
      encoding: 'utf8',
      cwd: root,
      env,
    });
  };
  const outputs = () => readFile(githubOutput, 'utf8');
  return { root, workspace, run, outputs };
}
const outputValue = (raw: string, name: string): string | undefined =>
  new RegExp(`^${name}<<(\\S+)\\n([\\s\\S]*?)\\n\\1$`, 'm').exec(raw)?.[2];
const withSandbox = async (
  body: (box: Awaited<ReturnType<typeof sandbox>>) => Promise<void>,
) => {
  const box = await sandbox();
  try {
    await body(box);
  } finally {
    await rm(box.root, { recursive: true, force: true });
  }
};
// The metacharacters appear inside legitimate file names; a command would create this one.
const injected = (names: string[]) => names.filter((name) => name === 'PWNED');

test('action metadata is a self-contained node24 JavaScript action', async () => {
  const action = parseDocument(await readFile('action.yml', 'utf8')).toJS() as {
    runs: { using: string; main: string; steps?: unknown };
    inputs: Record<string, unknown>;
    outputs: Record<string, unknown>;
  };
  assert.equal(action.runs.using, 'node24');
  assert.equal(action.runs.steps, undefined);
  assert.deepEqual(Object.keys(action.inputs).sort(), [
    'config',
    'format',
    'output',
    'path',
  ]);
  assert.deepEqual(Object.keys(action.outputs), ['report-file']);
  assert.equal(resolve(action.runs.main), bundle);
});

test('the committed action bundle matches the sources', () => {
  const check = spawnSync(process.execPath, ['scripts/build-action.mjs', '--check'], {
    encoding: 'utf8',
  });
  assert.equal(check.status, 0, check.stderr);
});

test('text and json go to the step log and no file output is produced', async () =>
  withSandbox(async ({ run, outputs }) => {
    const text = run({ path: '.github/workflows/correct.yml', format: 'text' });
    assert.equal(text.status, 0, text.stderr);
    assert.match(text.stdout, /Deployment:/);
    const json = run({ path: '.github/workflows/correct.yml', format: 'json' });
    assert.equal(json.status, 0, json.stderr);
    assert.equal(JSON.parse(json.stdout).deployments[0].state, 'proven');
    // Defaults analyze the whole workspace, which includes the rebuild finding.
    assert.equal(run({}).status, 1);
    assert.equal(await outputs(), '');
  }));

test('sarif is written to the requested file and exposed as an output', async () =>
  withSandbox(async ({ workspace, run, outputs }) => {
    const result = run({ path: '.', format: 'sarif', output: join('reports', unsafe) });
    // The rebuild fixture is a finding: exit 1, and the report is still saved.
    assert.equal(result.status, 1, result.stderr);
    const file = join(workspace, 'reports', unsafe);
    const sarif = JSON.parse(await readFile(file, 'utf8'));
    assert.equal(sarif.version, '2.1.0');
    assert.deepEqual(
      sarif.runs[0].results.map((r: { ruleId: string }) => r.ruleId),
      ['SB001'],
    );
    assert.equal(
      sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
      '.github/workflows/rebuild.yml',
    );
    assert.equal(outputValue(await outputs(), 'report-file'), file);
    const validated = spawnSync(
      process.execPath,
      ['scripts/validate-sarif.mjs', file, 'SB001'],
      { encoding: 'utf8' },
    );
    assert.equal(validated.status, 0, validated.stderr);
    // The log carries a human-readable summary, never the SARIF document.
    assert.match(result.stdout, /SB001/);
    assert.doesNotMatch(result.stdout, /"\$schema"/);
    assert.equal((await readdir(join(workspace, 'reports'))).length, 1);
    // Inputs are data: nothing executed the metacharacters in the file name.
    assert.deepEqual(injected(await readdir(workspace)), []);
  }));

test('a clean analysis writes json to an absolute path and exits 0', async () =>
  withSandbox(async ({ root, run, outputs }) => {
    const file = join(root, 'absolute report.json');
    const result = run({
      path: '.github/workflows/correct.yml',
      format: 'json',
      output: file,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(await readFile(file, 'utf8')).findings.length, 0);
    assert.equal(outputValue(await outputs(), 'report-file'), file);
  }));

test('analysis errors exit 2 without a report file or output', async () =>
  withSandbox(async ({ workspace, run, outputs }) => {
    await writeFile(join(workspace, 'broken.yml'), 'jobs: []');
    for (const path of ['broken.yml', 'does-not-exist.yml']) {
      const result = run({ path, format: 'sarif', output: 'broken.sarif' });
      assert.equal(result.status, 2, `${path}: ${result.stderr}`);
      assert.match(result.stdout, /::error::|ERROR/);
    }
    const missingConfig = run({ config: 'missing.json', output: 'broken.sarif' });
    assert.equal(missingConfig.status, 2);
    assert.match(missingConfig.stdout, /^::error::SameByte: /m);
    assert.deepEqual(
      (await readdir(workspace)).filter((name) => name.endsWith('.sarif')),
      [],
    );
    assert.equal(await outputs(), '');
  }));

test('a write failure exits 2, leaves no partial file and sets no output', async () =>
  withSandbox(async ({ workspace, run, outputs }) => {
    await writeFile(join(workspace, 'plain file'), 'x');
    await mkdir(join(workspace, 'a directory'));
    for (const output of [join('plain file', 'r.sarif'), 'a directory']) {
      const result = run({
        path: '.github/workflows/correct.yml',
        format: 'sarif',
        output,
      });
      assert.equal(result.status, 2, result.stdout);
      assert.match(result.stdout, /::error::SameByte: cannot write report/);
    }
    // Even a finding does not hide the write failure behind exit 1.
    const finding = run({ path: '.', format: 'sarif', output: 'a directory' });
    assert.equal(finding.status, 2);
    assert.equal(await outputs(), '');
    assert.deepEqual((await readdir(workspace)).sort(), [
      '.github',
      'a directory',
      'plain file',
    ]);
    assert.deepEqual(await readdir(join(workspace, 'a directory')), []);
  }));

test('inputs are never evaluated by a shell', async () =>
  withSandbox(async ({ workspace, run }) => {
    const payload = '$(touch PWNED); touch PWNED #';
    for (const inputs of [
      { path: payload },
      { config: payload },
      { path: '.', format: 'sarif', output: payload },
    ]) {
      const result = run(inputs);
      assert.ok([1, 2].includes(result.status ?? -1), result.stderr);
    }
    const bad = run({ format: `json${payload}` });
    assert.equal(bad.status, 2);
    assert.match(bad.stdout, /Unsupported format/);
    assert.deepEqual(injected(await readdir(workspace)), []);
  }));

test('sarif without an output file is printed to the step log', async () =>
  withSandbox(async ({ run, outputs }) => {
    const result = run({ path: '.github/workflows/rebuild.yml', format: 'sarif' });
    assert.equal(result.status, 1, result.stderr);
    assert.equal(JSON.parse(result.stdout).runs[0].results[0].ruleId, 'SB001');
    assert.equal(await outputs(), '');
  }));

test('the bundle carries the license notices of bundled dependencies', async () => {
  const source = await readFile(bundle, 'utf8');
  assert.match(source, /Copyright Eemeli Aro/);
  assert.match(source, /MIT License/);
});

test('the bundle runs alone and leaves the caller workspace untouched', async () =>
  withSandbox(async ({ root, workspace, run }) => {
    const result = run({ path: '.github/workflows/correct.yml', format: 'json' });
    assert.equal(result.status, 0, result.stderr);
    // No dependency was installed next to the bundle and no process is started.
    assert.deepEqual(await readdir(join(root, 'action dir')), ['index.mjs']);
    assert.doesNotMatch(await readFile(bundle, 'utf8'), /node:child_process/);
    assert.deepEqual(await readdir(workspace), ['.github']);
  }));
