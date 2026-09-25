import { relative } from 'node:path';
import type { Report } from './model.js';
export function textReport(report: Report, explain = false): string {
  const lines: string[] = [];
  for (const diagnostic of report.diagnostics)
    lines.push(`ERROR ${diagnostic.file}: ${diagnostic.message}`);
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
  for (const deployment of report.deployments) {
    const operation = report.operations.find((op) => op.id === deployment.operation);
    lines.push(
      `Deployment: ${operation?.identity.reference} [${deployment.state}]`,
      ...Object.entries(deployment.checks).map(
        ([kind, state]) => `  ${kind}: ${state}`,
      ),
    );
    if (explain && operation) {
      for (const kind of ['test', 'scan', 'attest'] as const) {
        if (deployment.checks[kind] !== 'unknown') continue;
        for (const uncertain of report.operations.filter(
          (op) =>
            op.kind === kind &&
            op.runtimeIdentityUnknown !== undefined &&
            op.identity.key === operation.identity.key,
        ))
          lines.push(
            `  ${kind} identity unknown (${uncertain.location.file}:${uncertain.location.line}): ${uncertain.runtimeIdentityUnknown}`,
          );
      }
    }
  }
  if (!report.deployments.length)
    lines.push('No supported deployments found. Artifact lineage was not verified.');
  else if (
    report.deployments.every((d) => d.state === 'proven') &&
    !report.findings.length &&
    !report.diagnostics.length
  )
    lines.push('Artifact lineage verified.');
  else if (!report.findings.length)
    lines.push(
      'No high-confidence violations found. Incomplete lineage remains unknown.',
    );
  return lines.join('\n');
}
export function graphReport(report: Report): string {
  return report.artifacts
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
            toolExecutionNotifications: report.diagnostics.map((d) => ({
              level: 'error',
              message: { text: `${d.file}: ${d.message}` },
            })),
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
