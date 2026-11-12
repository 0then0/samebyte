import { relative } from 'node:path';
import type { Call, CallSite, CoverageNotice, Report } from './model.js';

// Locations inside a called workflow also name the call site in the caller.
const calledFrom = (call?: CallSite): string =>
  call ? `, called from ${call.file}:${call.line} (${call.job})` : '';
const coverageText = (notice: CoverageNotice): string =>
  `COVERAGE ${notice.reason} (${notice.location.file}:${notice.location.line}, ${notice.location.job}${calledFrom(notice.call)})${notice.target ? `: ${notice.target}` : ''}\n  ${notice.message}`;
const callText = (call: Call, explain: boolean): string[] => {
  const values = (label: string, entries: Call['inputs']) =>
    Object.entries(entries ?? {}).flatMap(([name, entry]) => [
      `  ${label} ${name} = ${entry.value}${entry.state === 'unknown' ? ' [unknown]' : ''}${entry.source && entry.source !== 'with' ? ` (${entry.source})` : ''}`,
      ...(explain ? entry.path.map((part) => `    -> ${part}`) : []),
    ]);
  return [
    `CALL ${call.caller.job} (${call.caller.file}:${call.caller.line}${calledFrom(call.call)}) -> ${call.workflow ?? call.target} [expanded]`,
    ...values('input', call.inputs),
    ...values('output', call.outputs),
  ];
};
// Calls that were not expanded are already listed as coverage boundaries.
const callsText = (report: Report, explain: boolean): string[] => {
  const expanded = report.calls.filter((call) => call.status === 'expanded');
  return expanded.length
    ? [
        'Reusable workflow calls:',
        ...expanded.flatMap((call) => callText(call, explain)),
        '',
      ]
    : [];
};
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
  lines.push(...callsText(report, explain));
  for (const finding of report.findings) {
    lines.push(
      `${finding.ruleId} ${finding.severity.toUpperCase()} [${finding.state}]`,
      finding.message,
      `  ${finding.location.file}:${finding.location.line} (${finding.location.job})${calledFrom(finding.call)}`,
    );
    for (const evidence of finding.evidence) {
      lines.push(`  ${evidence.reference}`);
      if (evidence.location)
        lines.push(
          `    in ${evidence.location.file}:${evidence.location.line} (${evidence.location.job})${calledFrom(evidence.call)}`,
        );
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
      `Unknown ${operation.kind} identity (${operation.location.file}:${operation.location.line}, ${operation.location.job}${calledFrom(operation.call)}): ${operation.identity.reference}`,
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
            `  ${kind} identity unknown (${reason.file}:${reason.line}${calledFrom(reason.call)}): ${reason.reason}`,
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
  return [
    artifacts,
    callsText(report, false).slice(0, -1).join('\n'),
    ...report.coverage.map(coverageText),
  ]
    .filter(Boolean)
    .join('\n\n');
}
const sarifLocation = (file: string, line: number) => ({
  physicalLocation: {
    artifactLocation: {
      uri: relative(process.cwd(), file).split('/').map(encodeURIComponent).join('/'),
      uriBaseId: '%SRCROOT%',
    },
    region: { startLine: line },
  },
});
// Evidence in a called workflow and the call site that reached it. The primary
// location stays the place of the problem itself.
function relatedLocations(finding: Report['findings'][number]) {
  const related: { file: string; line: number; text: string }[] = [];
  const add = (file: string, line: number, text: string) => {
    if (!related.some((item) => item.file === file && item.line === line))
      related.push({ file, line, text });
  };
  const site = (call: CallSite) =>
    add(call.file, call.line, `Reusable workflow call ${call.job}`);
  if (finding.call) site(finding.call);
  for (const evidence of finding.evidence) {
    if (!evidence.location) continue;
    add(
      evidence.location.file,
      evidence.location.line,
      `Evidence in called workflow (${evidence.location.job}): ${evidence.reference}`,
    );
    if (evidence.call) site(evidence.call);
  }
  return related.map((item, id) => ({
    id,
    ...sarifLocation(item.file, item.line),
    message: { text: item.text },
  }));
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
                  sarifLocation(notice.location.file, notice.location.line),
                  ...(notice.call
                    ? [sarifLocation(notice.call.file, notice.call.line)]
                    : []),
                ],
                properties: {
                  type: notice.type,
                  target: notice.target,
                  ...(notice.call ? { call: notice.call } : {}),
                },
              })),
            ],
          },
        ],
        results: report.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: finding.severity === 'high' ? 'error' : 'warning',
          message: { text: finding.message },
          locations: [sarifLocation(finding.location.file, finding.location.line)],
          ...(relatedLocations(finding).length
            ? { relatedLocations: relatedLocations(finding) }
            : {}),
          properties: {
            confidence: finding.confidence,
            state: finding.state,
            evidence: finding.evidence,
            ...(finding.call ? { call: finding.call } : {}),
          },
        })),
      },
    ],
  };
}
