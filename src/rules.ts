import type { Deployment, Finding, Operation, State, Workflow } from './model.js';

const normalizedCondition = (condition: unknown) =>
  String(condition)
    .replace(/^\s*\$\{\{\s*|\s*\}\}\s*$/g, '')
    .trim()
    .replace(/^\((.*)\)$/s, '$1')
    .trim()
    .toLowerCase();
const explicitSuccess = (condition: unknown) =>
  condition === undefined || normalizedCondition(condition) === 'success()';
const hasStatusCheck = (condition: unknown) =>
  /\b(?:success|failure|cancelled|always)\s*\(/i.test(String(condition));
const bypassesSuccess = (condition: unknown) =>
  hasStatusCheck(condition) && !explicitSuccess(condition);

function jobDependsOn(from: string, to: string, workflow: Workflow): boolean {
  if (from === to) return true;
  const seen = new Set<string>();
  const visit = (job: string): boolean => {
    if (seen.has(job)) return false;
    seen.add(job);
    return workflow.jobs[job].needs.some((need) => need === from || visit(need));
  };
  return visit(to);
}
function dependsOn(a: Operation, b: Operation, workflow: Workflow): boolean {
  return jobDependsOn(a.location.job, b.location.job, workflow);
}
export function precedes(a: Operation, b: Operation, workflow: Workflow): boolean {
  if (!dependsOn(a, b, workflow)) return false;
  if (a.location.job !== b.location.job) return true;
  if (a.order >= b.order) return false;
  return a.completionStep === undefined || a.completionStep < b.location.step;
}
export function analyzeRules(
  operations: Operation[],
  workflow: Workflow,
): { findings: Finding[]; deployments: Deployment[] } {
  const findings: Finding[] = [];
  const deployments: Deployment[] = [];
  const evidence = (ops: Operation[]) =>
    ops.map((op) => ({
      operation: op.id,
      reference: op.identity.reference,
      path: op.identity.trace,
    }));
  for (const deploy of operations.filter((op) => op.kind === 'deploy')) {
    const checks: Deployment['checks'] = {
      test: 'unknown',
      scan: 'unknown',
      attest: 'unknown',
    };
    const checkReasons: NonNullable<Deployment['checkReasons']> = {};
    const add = (
      ruleId: string,
      message: string,
      state: State,
      ops: Operation[],
      high = true,
    ) =>
      findings.push({
        ruleId,
        message,
        state,
        severity: high ? 'high' : 'medium',
        confidence: high ? 'high' : 'medium',
        location: deploy.location,
        evidence: evidence([...ops, deploy]),
      } as Finding);
    if (deploy.identity.kind === 'mutable')
      add(
        'SB005',
        'Mutable deployment reference. Artifact identity cannot be proven.',
        'unknown',
        [],
      );
    if (deploy.identity.kind === 'unknown')
      add(
        'SB006',
        'Artifact identity lost or unsupported deployment boundary.',
        'unknown',
        [],
        false,
      );
    for (const kind of ['test', 'scan', 'attest'] as const) {
      const candidates = operations.filter(
        (op) => op.kind === kind && precedes(op, deploy, workflow),
      );
      const guaranteed = (op: Operation): boolean => {
        const safeCondition = (condition: unknown) =>
          condition === undefined ||
          explicitSuccess(condition) ||
          !hasStatusCheck(condition);
        const operationStepConditionIsSafe = (condition: unknown) =>
          condition === undefined || explicitSuccess(condition);
        const operationJob = workflow.jobs[op.location.job];
        const operationStep = operationJob.steps[op.location.step];
        const deploymentJob = workflow.jobs[deploy.location.job];
        const deploymentStep = deploymentJob.steps[deploy.location.step];
        if (!safeCondition(deploymentJob.if) || !safeCondition(deploymentStep?.if))
          return false;
        const visit = (id: string): boolean => {
          const job = workflow.jobs[id];
          if (id === op.location.job)
            return (
              safeCondition(job.if) &&
              operationStepConditionIsSafe(operationStep?.if) &&
              (!op.guarded || op.guardedByJobCondition === true)
            );
          if (
            job.strategy !== undefined ||
            job['continue-on-error'] ||
            !safeCondition(job.if)
          )
            return false;
          return job.needs.some(visit);
        };
        return visit(deploy.location.job);
      };
      const same = candidates.find(
        (op) =>
          guaranteed(op) &&
          op.identity.kind === 'immutable' &&
          deploy.identity.kind === 'immutable' &&
          op.identity.key === deploy.identity.key,
      );
      if (same) {
        // The exact digest was checked, but an OCI index may select a different
        // runtime manifest. Keep that result unknown and do not compare other
        // test digests as though the deployed digest had never been tested.
        if (same.runtimeIdentityUnknown === undefined) checks[kind] = 'proven';
        else
          checkReasons[kind] = {
            file: same.location.file,
            line: same.location.line,
            reason: same.runtimeIdentityUnknown,
          };
        continue;
      }
      // Compare only concrete digests of the same named repository. Independent
      // symbolic build outputs can still represent identical bytes.
      const different = candidates.filter(
        (op) =>
          guaranteed(op) &&
          op.identity.concrete &&
          deploy.identity.concrete &&
          op.identity.repository &&
          op.identity.repository === deploy.identity.repository &&
          op.identity.key !== deploy.identity.key,
      );
      if (different.length) {
        checks[kind] = 'mismatch';
        add(
          { test: 'SB002', scan: 'SB003', attest: 'SB004' }[kind],
          `${{ test: 'Tested', scan: 'Scanned', attest: 'Attested' }[kind]} artifact differs from deployed artifact.`,
          'mismatch',
          different,
        );
      }
    }
    const sourceTests = operations.filter(
      (op) =>
        op.kind === 'source-test' && !op.guarded && precedes(op, deploy, workflow),
    );
    const builds = operations.filter(
      (op) => op.kind === 'build' && !op.guarded && precedes(op, deploy, workflow),
    );
    const sourceCheckedBefore = (build: Operation) =>
      sourceTests.some((test) => precedes(test, build, workflow));
    const stronglyLinkedBuild = builds.find(
      (build) =>
        build.identity.kind === 'immutable' &&
        deploy.identity.kind === 'immutable' &&
        build.identity.key === deploy.identity.key &&
        sourceCheckedBefore(build),
    );
    const weaklyLinkedBuild = builds.find(
      (build) =>
        deploy.identity.kind === 'mutable' &&
        build.producedReference === deploy.identity.reference &&
        sourceCheckedBefore(build),
    );
    const deployJob = workflow.jobs[deploy.location.job];
    const deployStep = deployJob.steps[deploy.location.step];
    const possibleTestOfDeployed = operations.some((op) => {
      const intermediateBypasses = Object.entries(workflow.jobs).some(
        ([jobId, job]) =>
          jobId !== op.location.job &&
          jobId !== deploy.location.job &&
          bypassesSuccess(job.if) &&
          jobDependsOn(op.location.job, jobId, workflow) &&
          jobDependsOn(jobId, deploy.location.job, workflow),
      );
      if (
        op.kind !== 'test' ||
        !dependsOn(op, deploy, workflow) ||
        (op.location.job === deploy.location.job && op.order >= deploy.order) ||
        op.runtimeIdentityUnknown !== undefined ||
        op.identity.kind !== 'immutable' ||
        deploy.identity.kind !== 'immutable' ||
        op.identity.key !== deploy.identity.key ||
        bypassesSuccess(deployJob.if) ||
        bypassesSuccess(deployStep?.if) ||
        intermediateBypasses
      )
        return false;
      return !op.guarded || op.guardedByJobCondition === true;
    });
    if (stronglyLinkedBuild && checks.test === 'unknown' && !possibleTestOfDeployed) {
      checks.test = 'mismatch';
      add(
        'SB001',
        'Production artifact was never tested. Source tests ran, but no recognized OCI test consumes the deployed digest.',
        'mismatch',
        [...sourceTests, stronglyLinkedBuild],
      );
    }
    if (weaklyLinkedBuild && checks.test === 'unknown')
      add(
        'SB001',
        'A candidate production image was built after source tests, but a mutable tag cannot prove which bytes were deployed.',
        'unknown',
        [...sourceTests, weaklyLinkedBuild],
        false,
      );
    const state = Object.values(checks).includes('mismatch')
      ? 'mismatch'
      : Object.values(checks).every((value) => value === 'proven')
        ? 'proven'
        : 'unknown';
    deployments.push({
      operation: deploy.id,
      state,
      checks,
      ...(Object.keys(checkReasons).length ? { checkReasons } : {}),
    });
  }
  return { findings, deployments };
}
