import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import {
  analyzeWorkflow,
  type Config,
  mergeReports,
  validateConfig,
} from './analyzer.js';
import type { Report } from './model.js';
import { graphReport, sarifReport, textReport } from './output.js';
import { discover, readWorkflow } from './parser.js';

export const formats = ['text', 'json', 'sarif'] as const;
export type Format = (typeof formats)[number];
export interface Options {
  input: string;
  format: Format;
  command?: 'check' | 'explain' | 'graph';
  config?: string;
  // Relative paths resolve against the process working directory.
  output?: string;
}
export interface Outcome {
  report: Report;
  code: number;
  // The report in the selected format; the caller decides where it is shown.
  rendered: string;
  // Absolute path of the written report; only set when the file is complete.
  reportFile?: string;
  // Set when an output file was requested but not written.
  writeError?: string;
}

export async function analyze(input: string, configFile?: string): Promise<Report> {
  let config: Config = { annotations: [] };
  if (configFile)
    config = validateConfig(JSON.parse(await readFile(configFile, 'utf8')));
  const reports: Report[] = [];
  const diagnostics: Report['diagnostics'] = [];
  const files = await discover(input);
  if (!files.length)
    diagnostics.push({ file: resolve(input), message: 'No YAML workflows found.' });
  for (const file of files) {
    try {
      reports.push(analyzeWorkflow(await readWorkflow(file), config));
    } catch (error) {
      diagnostics.push({
        file,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
  const report = mergeReports(reports);
  report.diagnostics.push(...diagnostics);
  return report;
}
export function render(
  report: Report,
  format: Format,
  command: Options['command'] = 'check',
): string {
  if (format === 'json') return JSON.stringify(report, null, 2);
  if (format === 'sarif') return JSON.stringify(sarifReport(report), null, 2);
  if (command !== 'graph') return textReport(report, true);
  return [
    graphReport(report),
    ...report.diagnostics.map((d) => `ERROR ${d.file}: ${d.message}`),
  ]
    .filter(Boolean)
    .join('\n');
}
export const exitCode = (report: Report): number =>
  report.diagnostics.length
    ? 2
    : report.findings.some((f) => f.confidence === 'high')
      ? 1
      : 0;

// The destination either holds the complete report or is left untouched: content is
// written to a sibling temporary file and renamed into place.
export async function writeReportFile(path: string, content: string): Promise<void> {
  const temporary = join(
    dirname(path),
    `.${basename(path)}.${process.pid}.${Date.now()}.tmp`,
  );
  try {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(temporary, `${content}\n`, { flag: 'wx' });
    await rename(temporary, path);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

export async function execute(options: Options): Promise<Outcome> {
  const report = await analyze(options.input, options.config);
  const rendered = render(report, options.format, options.command);
  const outcome: Outcome = { report, code: exitCode(report), rendered };
  if (!options.output) return outcome;
  // A report of a failed analysis is incomplete; consumers such as code scanning
  // would treat missing results as resolved, so no file is produced for it.
  if (report.diagnostics.length) {
    outcome.writeError = 'analysis failed; no report file was written';
    return outcome;
  }
  const path = resolve(options.output);
  try {
    await writeReportFile(path, rendered);
    outcome.reportFile = path;
  } catch (error) {
    outcome.code = 2;
    outcome.writeError = `cannot write report to ${path}: ${
      error instanceof Error ? error.message : String(error)
    }`;
  }
  return outcome;
}
