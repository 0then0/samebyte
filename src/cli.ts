#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { textReport } from './output.js';
import { execute, type Format, formats } from './run.js';

const help = `SameByte — Test the same bytes you deploy.

Usage: samebyte [check|explain|graph] [path] [options]

  --format text|json|sarif  Output format (default: text)
  --config <file>          Explicit artifact annotations (JSON)
  --output <file>          Write the report to a file instead of stdout
  --help                  Show usage
  --version               Show version

Exit codes: 0 no high-confidence violations; 1 violations; 2 analysis error.
Unknown lineage is not a verified pipeline. All analysis is local and static.
With --output the file is written only when analysis completed (exit 0 or 1).`;
async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      format: { type: 'string', default: 'text' },
      config: { type: 'string' },
      output: { type: 'string' },
      help: { type: 'boolean' },
      version: { type: 'boolean' },
    },
  });
  if (values.help) {
    console.log(help);
    return 0;
  }
  if (values.version) {
    console.log('0.1.2');
    return 0;
  }
  const command = ['check', 'explain', 'graph'].includes(positionals[0])
    ? (positionals.shift() as 'check' | 'explain' | 'graph')
    : 'check';
  if (positionals.length > 1)
    throw new Error('Expected a single path. Use --help for usage.');
  if (!formats.includes(values.format as Format))
    throw new Error('Unsupported format. Expected text, json or sarif.');
  if (values.output === '') throw new Error('--output requires a file path.');
  const outcome = await execute({
    input: positionals[0] ?? '.',
    format: values.format as Format,
    command,
    config: values.config,
    output: values.output,
  });
  if (!values.output) console.log(outcome.rendered);
  else if (outcome.writeError) {
    if (outcome.report.diagnostics.length) console.error(textReport(outcome.report));
    console.error(`SameByte: ${outcome.writeError}`);
  }
  return outcome.code;
}
main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    console.error(
      `SameByte: ${error instanceof Error ? error.message : String(error)}`,
    );
    process.exitCode = 2;
  });
