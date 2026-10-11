import { relative } from 'node:path';
import type { CoverageNotice, Report } from './model.js';

const coverageText = (notice: CoverageNotice): string =>
  `COVERAGE ${notice.reason} (${notice.location.file}:${notice.location.line}, ${notice.location.job})${notice.target ? `: ${notice.target}` : ''}\n  ${notice.message}`;
export function textReport(report: Report, explain = false): string {
  const lines: string[] = [];
  for (const diagnostic of report.diagnostics)
    lines.push(`ERROR ${diagnostic.file}: ${diagnostic.message}`);
  if (report.coverage.length)
    lines.push(
      'Analysis coverage is incomplete. Unsupported boundaries may hide operations.',
      ...report.coverage.map(coverageText),
      '',
    );
  for (const finding of report.findings) {
    lines.push(
      `${finding.ruleId} ${finding.severity.toUpperCase()} [${finding.state}]`,
      finding.message,
      `  ${finding.location.file}:${finding.location.line} (${finding.location.job})`,
    );
    for (const evidence of finding.evidence) {
      lines.push(`  ${evidence.reference}`);
      if (explain) lines.push(...evidence.path.map((part) => `    -> ${part}`));
    }
    lines.push('');
  }
  for (const operation of report.operations) {
    if (
      operation.kind === 'source-test' ||
      (operation.identity.kind !== 'unknown' && !operation.runtimeIdentityUnknown)
    )
      continue;
    lines.push(
      `Unknown ${operation.kind} identity (${operation.location.file}:${operation.location.line}, ${operation.location.job}): ${operation.identity.reference}`,
      ...[
        ...new Set([
          ...operation.identity.trace,
          ...(operation.guarded
            ? [
                'Conditions, strategy, or ignored failures prevent an unconditional proof.',
              ]
            : []),
        ]),
      ].map((reason) => `  ${reason}`),
    );
  }
  for (const deployment of report.deployments) {
    const operation = report.operations.find((op) => op.id === deployment.operation);
    lines.push(
      `Deployment: ${operation?.identity.reference} [${deployment.state}]`,
      ...Object.entries(deployment.checks).map(
        ([kind, state]) => `  ${kind}: ${state}`,
      ),
    );
    if (operation) {
      for (const kind of ['test', 'scan', 'attest'] as const) {
        if (deployment.checks[kind] !== 'unknown') continue;
        const reason = deployment.checkReasons?.[kind];
        if (reason)
          lines.push(
            `  ${kind} identity unknown (${reason.file}:${reason.line}): ${reason.reason}`,
          );
      }
    }
  }
  if (!report.deployments.length)
    lines.push('No supported deployments found. Artifact lineage was not verified.');
  if (report.diagnostics.length)
    lines.push('Analysis failed. Artifact lineage was not verified.');
  else if (
    report.deployments.length &&
    report.deployments.every((d) => d.state === 'proven') &&
    !report.findings.length
  )
    lines.push(
      report.coverage.length
        ? 'Detected deployment lineage is proven. Pipeline coverage is incomplete.'
        : 'Artifact lineage verified within the supported analysis scope.',
    );
  else if (report.deployments.length && !report.findings.length)
    lines.push(
      'No high-confidence violations found. Incomplete lineage remains unknown.',
    );
  return lines.join('\n');
}
export function graphReport(report: Report): string {
  const artifacts = report.artifacts
    .map((artifact) =>
      [
        `${artifact.id} [${artifact.identity.kind}]`,
        `  ${artifact.identity.reference}`,
        ...artifact.producers.map((id) => `  <- ${id}`),
        ...artifact.consumers.map(
          (id) => `  -> ${report.operations.find((op) => op.id === id)?.kind}: ${id}`,
        ),
      ].join('\n'),
    )
    .join('\n\n');
  return [artifacts, ...report.coverage.map(coverageText)].filter(Boolean).join('\n\n');
}
export function sarifReport(report: Report): unknown {
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'SameByte',
            informationUri: 'https://github.com/0then0/samebyte',
            rules: ['SB001', 'SB002', 'SB003', 'SB004', 'SB005', 'SB006'].map((id) => ({
              id,
            })),
          },
        },
        invocations: [
          {
            executionSuccessful: report.diagnostics.length === 0,
            toolExecutionNotifications: [
              ...report.diagnostics.map((d) => ({
                level: 'error',
                message: { text: `${d.file}: ${d.message}` },
              })),
              ...report.coverage.map((notice) => ({
                level: 'note',
                descriptor: { id: notice.reason },
                message: { text: coverageText(notice) },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: {
                        uri: relative(process.cwd(), notice.location.file)
                          .split('/')
                          .map(encodeURIComponent)
                          .join('/'),
                        uriBaseId: '%SRCROOT%',
                      },
                      region: { startLine: notice.location.line },
                    },
                  },
                ],
                properties: { type: notice.type, target: notice.target },
              })),
            ],
          },
        ],
        results: report.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: finding.severity === 'high' ? 'error' : 'warning',
          message: { text: finding.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: relative(process.cwd(), finding.location.file)
                    .split('/')
                    .map(encodeURIComponent)
                    .join('/'),
                  uriBaseId: '%SRCROOT%',
                },
                region: { startLine: finding.location.line },
              },
            },
          ],
          properties: {
            confidence: finding.confidence,
            state: finding.state,
            evidence: finding.evidence,
          },
        })),
      },
    ],
  };
}
