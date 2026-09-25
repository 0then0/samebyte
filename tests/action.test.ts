import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { parseDocument } from 'yaml';

test('composite action uses Node 24 actions and installs build tools in production env', async () => {
  const document = parseDocument(await readFile('action.yml', 'utf8'));
  const action = document.toJS() as {
    runs: { steps: { uses?: string; run?: string }[] };
  };
  const setupNode = action.runs.steps.find((step) =>
    step.uses?.startsWith('actions/setup-node@'),
  );
  const install = action.runs.steps.find((step) => step.run?.includes('npm ci'));

  assert.equal(setupNode?.uses, 'actions/setup-node@v5');
  assert.match(install?.run ?? '', /npm ci .*--include=dev/);
  assert.match(install?.run ?? '', /npm run build/);
});
