#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import {
  analyzeWorkflow,
  type Config,
  mergeReports,
  validateConfig,
} from './analyzer.js';
import type { Report } from './model.js';
import { graphReport, sarifReport, textReport } from './output.js';
import { discover, readWorkflow } from './parser.js';

const help = `SameByte — Test the same bytes you deploy.

Usage: samebyte [check|explain|graph] [path] [options]

  --format text|json|sarif  Output format (default: text)
  --config <file>          Explicit artifact annotations (JSON)
  --help                  Show usage
  --version               Show version

Exit codes: 0 no high-confidence violations; 1 violations; 2 analysis error.
Unknown lineage is not a verified pipeline. All analysis is local and static.`;
async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      format: { type: 'string', default: 'text' },
      config: { type: 'string' },
      help: { type: 'boolean' },
      version: { type: 'boolean' },
    },
  });
  if (values.help) {
    console.log(help);
    return 0;
  }
  if (values.version) {
    console.log('0.1.0');
    return 0;
  }
  const command = ['check', 'explain', 'graph'].includes(positionals[0])
    ? positionals.shift()
    : 'check';
  if (positionals.length > 1)
    throw new Error('Expected a single path. Use --help for usage.');
  if (!['text', 'json', 'sarif'].includes(values.format ?? ''))
    throw new Error('Unsupported format. Expected text, json or sarif.');
  const input = positionals[0] ?? '.';
  let config: Config = { annotations: [] };
  if (values.config)
    config = validateConfig(JSON.parse(await readFile(values.config, 'utf8')));
  const reports: Report[] = [];
  const diagnostics: Report['diagnostics'] = [];
  const files = await discover(input);
  if (!files.length)
    diagnostics.push({
      file: resolve(input),
      message: 'No YAML workflows found.',
    });
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
  console.log(
    values.format === 'json'
      ? JSON.stringify(report, null, 2)
      : values.format === 'sarif'
        ? JSON.stringify(sarifReport(report), null, 2)
        : command === 'graph'
          ? [
              graphReport(report),
              ...report.diagnostics.map((d) => `ERROR ${d.file}: ${d.message}`),
            ]
              .filter(Boolean)
              .join('\n')
          : textReport(report, true),
  );
  return report.diagnostics.length
    ? 2
    : report.findings.some((f) => f.confidence === 'high')
      ? 1
      : 0;
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
