import { randomUUID } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { textReport } from './output.js';
import { execute, type Format, formats } from './run.js';

// Inputs arrive as INPUT_* environment variables (never interpolated into a shell).
// Relative paths resolve against the checked-out workspace, not the action directory.
const input = (name: string): string => process.env[`INPUT_${name}`] ?? '';
const escapeCommand = (value: string) =>
  value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const setOutput = (name: string, value: string) => {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  const delimiter = `samebyte_${randomUUID()}`;
  appendFileSync(file, `${name}<<${delimiter}\n${value}\n${delimiter}\n`);
};

async function main(): Promise<number> {
  if (process.env.GITHUB_WORKSPACE) process.chdir(process.env.GITHUB_WORKSPACE);
  const format = input('FORMAT') || 'text';
  if (!formats.includes(format as Format))
    throw new Error('Unsupported format. Expected text, json or sarif.');
  const output = input('OUTPUT');
  const outcome = await execute({
    input: input('PATH') || '.',
    format: format as Format,
    config: input('CONFIG') || undefined,
    output: output || undefined,
  });
  // Without an output file the report is the step's stdout, as with the CLI. With
  // one, the log carries the human-readable summary and the file the chosen format.
  console.log(output ? textReport(outcome.report, true) : outcome.rendered);
  if (outcome.writeError)
    console.log(`::error::${escapeCommand(`SameByte: ${outcome.writeError}`)}`);
  if (outcome.reportFile) setOutput('report-file', outcome.reportFile);
  return outcome.code;
}
main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.log(`::error::${escapeCommand(`SameByte: ${message}`)}`);
    process.exitCode = 2;
  });
