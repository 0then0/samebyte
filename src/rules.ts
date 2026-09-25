import type { Deployment, Finding, Operation, State, Workflow } from './model.js';

export function precedes(a: Operation, b: Operation, workflow: Workflow): boolean {
  if (a.location.job === b.location.job) return a.order < b.order;
  const seen = new Set<string>();
  const visit = (job: string): boolean => {
    if (seen.has(job)) return false;
    seen.add(job);
    return workflow.jobs[job].needs.some(
      (need) => need === a.location.job || visit(need),
    );
  };
  return visit(b.location.job);
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
        const hasStatusCheck = (condition: unknown) =>
          /\b(?:success|failure|cancelled|always)\s*\(/i.test(String(condition));
        const operationJob = workflow.jobs[op.location.job];
        const operationStep = operationJob.steps[op.location.step];
        const deploymentJob = workflow.jobs[deploy.location.job];
        const deploymentStep = deploymentJob.steps[deploy.location.step];
        if (hasStatusCheck(deploymentStep?.if)) return false;
        const onlyDefaultJobCondition =
          operationJob.if !== undefined &&
          operationJob.strategy === undefined &&
          !operationJob['continue-on-error'] &&
          operationStep?.if === undefined &&
          !operationStep?.['continue-on-error'] &&
          !hasStatusCheck(operationJob.if);
        const visit = (id: string): boolean => {
          const job = workflow.jobs[id];
          if (id === op.location.job) return !op.guarded || onlyDefaultJobCondition;
          if (
            job.strategy !== undefined ||
            job['continue-on-error'] ||
            hasStatusCheck(job.if)
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
        checks[kind] = 'proven';
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
    if (stronglyLinkedBuild && checks.test === 'unknown') {
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
    deployments.push({ operation: deploy.id, state, checks });
  }
  return { findings, deployments };
}
