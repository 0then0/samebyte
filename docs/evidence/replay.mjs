// Static analysis only: this never executes upstream actions or run scripts.
// Usage: node docs/evidence/replay.mjs <output-directory> [cli-bundle]
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
const evidence = join(root, 'docs/evidence');
const destination = resolve(process.argv[2] ?? '/tmp/samebyte-evidence');
const cli = resolve(process.argv[3] ?? join(root, 'dist/cli.js'));
const shellQuote = (value) => /^[\w./-]+$/.test(value)
  ? value : `'${value.replaceAll("'", "'\\''")}'`;
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const summaries = [];
for (const entry of readdirSync(evidence, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const caseRoot = join(evidence, entry.name);
  if (!existsSync(join(caseRoot, 'provenance.json'))) continue;
  const provenance = JSON.parse(readFileSync(join(caseRoot, 'provenance.json')));
  for (const source of provenance.files) {
    const file = join(caseRoot, 'upstream', source.path);
    if (sha256(readFileSync(file)) !== source.sha256)
      throw new Error(`Changed upstream input: ${file}`);
    // Composite actions are retained for manual inspection, not parsed as workflows.
    if (!source.path.startsWith('.github/workflows/')) continue;
    const relativeFile = file.slice(root.length + 1);
    const normalize = (text) => text
      .replaceAll(root + '/', '')
      .replaceAll(sha256(file).slice(0, 16), sha256(relativeFile).slice(0, 16));
    const run = (...args) => {
      const result = spawnSync(process.execPath, [cli, ...args], {
        cwd: root, encoding: 'utf8', timeout: 30000,
      });
      if (result.error) throw result.error;
      if (result.stderr) throw new Error(result.stderr);
      return { exitCode: result.status, stdout: normalize(result.stdout) };
    };
    const json = run(file, '--format', 'json');
    const report = JSON.parse(json.stdout);
    const target = join(destination, entry.name, source.path.split('/').at(-1));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(`${target}.json`, JSON.stringify({
      command: `node ${shellQuote(relative(root, cli))} ${shellQuote(relativeFile)} --format json`,
      exitCode: json.exitCode, report,
    }, null, 2) + '\n');
    for (const command of ['check', 'explain']) {
      const result = run(command, file);
      writeFileSync(`${target}.${command}.txt`, result.stdout);
    }
    summaries.push({
      repository: provenance.repository, commit: provenance.commit, path: source.path,
      exitCode: json.exitCode,
      operations: report.operations.map(op => ({
        kind: op.kind, identity: op.identity.kind, job: op.location.job,
        line: op.location.line,
      })),
      deployments: report.deployments.length,
      findings: report.findings.map(f => f.ruleId),
      errors: report.diagnostics.length,
      ...(report.coverage ? { boundaries: report.coverage.length } : {}),
    });
  }
}
mkdirSync(destination, { recursive: true });
writeFileSync(join(destination, 'summary.json'), JSON.stringify(summaries, null, 2) + '\n');
console.log(JSON.stringify(summaries.map(({operations, ...s}) => ({
  ...s, operations: operations.length,
})), null, 2));
