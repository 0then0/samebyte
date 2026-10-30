// Builds the self-contained action bundle committed at action/index.mjs.
// `--check` rebuilds in memory and fails when the committed file is stale.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { build } from 'esbuild';

const outfile = 'action/index.mjs';
// esbuild drops package license headers, so the notices of bundled dependencies
// are copied into the bundle from the installed packages.
const notices = [];
for (const name of ['yaml', '@actions/expressions']) {
  const text = (await readFile(`node_modules/${name}/LICENSE`, 'utf8')).trim();
  notices.push(`// ${name}\n${text.replace(/^/gm, '// ')}`);
}
const result = await build({
  entryPoints: ['src/action.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  outfile,
  legalComments: 'none',
  // Bundled CommonJS dependencies may call require() for Node built-ins.
  banner: {
    js: `// Bundled third-party software and its license notices:\n${notices.join('\n//\n')}\nimport { createRequire as __samebyteCreateRequire } from 'node:module';\nconst require = __samebyteCreateRequire(import.meta.url);`,
  },
  write: false,
});
const built = result.outputFiles[0].text;
if (process.argv.includes('--check')) {
  const committed = await readFile(outfile, 'utf8').catch(() => undefined);
  if (committed !== built) {
    console.error(`${outfile} is stale. Run: npm run build:action`);
    process.exitCode = 1;
  }
} else {
  await mkdir('action', { recursive: true });
  await writeFile(outfile, built);
}
