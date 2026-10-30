import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

test('replay records and safely quotes the selected CLI bundle', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'samebyte-replay-'));
  try {
    const bundle = join(dir, "alternate bundle's.mjs");
    const output = join(dir, 'reports');
    await writeFile(
      bundle,
      `import ${JSON.stringify(pathToFileURL(resolve('dist/cli.js')).href)};\n`,
    );
    const replay = spawnSync(
      process.execPath,
      ['docs/evidence/replay.mjs', output, bundle],
      { encoding: 'utf8', timeout: 30000 },
    );
    assert.equal(replay.status, 0, replay.stderr);
    const saved = JSON.parse(
      await readFile(join(output, 'liatrio-demo', 'cw-build-image.yaml.json'), 'utf8'),
    );
    assert.match(saved.command, /alternate bundle/);
    assert.doesNotMatch(saved.command, /^node dist\/cli\.js /);
    const reproduced = spawnSync('sh', ['-c', saved.command], {
      encoding: 'utf8',
      timeout: 5000,
    });
    assert.equal(reproduced.status, saved.exitCode, reproduced.stderr);
    assert.equal(
      JSON.parse(reproduced.stdout).coverage[0].target,
      saved.report.coverage[0].target,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('saved updated reports match a fresh replay', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'samebyte-replay-'));
  try {
    const replay = spawnSync(process.execPath, ['docs/evidence/replay.mjs', dir], {
      encoding: 'utf8',
      timeout: 30000,
    });
    assert.equal(replay.status, 0, replay.stderr);
    const files = (root: string) =>
      readdir(root, { recursive: true, withFileTypes: true });
    const names = async (root: string) =>
      (await files(root))
        .filter((e) => e.isFile())
        .map((e) => join(e.parentPath, e.name).slice(root.length));
    const saved = await names('docs/evidence/updated');
    assert.deepEqual((await names(dir)).sort(), saved.sort());
    for (const name of saved)
      assert.equal(
        await readFile(join(dir, name), 'utf8'),
        await readFile(join('docs/evidence/updated', name), 'utf8'),
        name,
      );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
