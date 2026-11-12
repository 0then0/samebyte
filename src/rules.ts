import { hasStatusCheck } from './expressions.js';
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
const bypassesSuccess = (condition: unknown) =>
  hasStatusCheck(condition) && !explicitSuccess(condition);
const neverRuns = (condition: unknown) => normalizedCondition(condition) === 'false';
const isDisabled = (operation: Operation, workflow: Workflow) => {
  const job = workflow.jobs[operation.location.job];
  return neverRuns(job.if) || neverRuns(job.steps[operation.location.step]?.if);
};
function jobIsSkippedByNeeds(
  jobId: string,
  workflow: Workflow,
  memo = new Map<string, boolean>(),
  visiting = new Set<string>(),
): boolean {
  const cached = memo.get(jobId);
  if (cached !== undefined) return cached;
  const job = workflow.jobs[jobId];
  if (neverRuns(job.if)) {
    memo.set(jobId, true);
    return true;
  }
  // A job of a called workflow cannot run when the call itself does not.
  if (
    job.callEntry &&
    !visiting.has(job.callEntry) &&
    jobIsSkippedByNeeds(job.callEntry, workflow, memo, visiting)
  ) {
    memo.set(jobId, true);
    return true;
  }
  if (bypassesSuccess(job.if) || visiting.has(jobId)) {
    if (!visiting.has(jobId)) memo.set(jobId, false);
    return false;
  }
  visiting.add(jobId);
  // A skipped job inside a called workflow is not assumed to skip the calling
  // job, so only the start of the call propagates a skip out of it.
  const skipped = job.needs.some(
    (need) =>
      (!workflow.jobs[need].callEntry ||
        workflow.jobs[need].callEntry === job.callEntry) &&
      jobIsSkippedByNeeds(need, workflow, memo, visiting),
  );
  visiting.delete(jobId);
  memo.set(jobId, skipped);
  return skipped;
}

export const operationIsUnreachable = (
  operation: Operation,
  workflow: Workflow,
  memo = new Map<string, boolean>(),
) =>
  isDisabled(operation, workflow) ||
  jobIsSkippedByNeeds(operation.location.job, workflow, memo);

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
  const reachability = new Map<string, boolean>();
  const evidence = (ops: Operation[]) =>
    ops.map((op) => ({
      operation: op.id,
      reference: op.identity.reference,
      path: op.identity.trace,
      ...(op.call ? { location: op.location, call: op.call } : {}),
    }));
  for (const deploy of operations.filter(
    (op) => op.kind === 'deploy' && !operationIsUnreachable(op, workflow, reachability),
  )) {
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
        ...(deploy.call ? { call: deploy.call } : {}),
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
      // Why an operation inside a reusable workflow call does not gate a
      // deployment outside that call, when the call itself is the reason.
      const callGate = (op: Operation): string | undefined => {
        const entry = workflow.jobs[op.location.job].callEntry;
        if (!entry || workflow.jobs[deploy.location.job].callEntry === entry)
          return undefined;
        const operationJob = workflow.jobs[op.location.job];
        if (
          operationJob['continue-on-error'] ||
          operationJob.steps[op.location.step]?.['continue-on-error']
        )
          return `continue-on-error inside the reusable workflow lets the call succeed when this ${kind} fails.`;
        if (workflow.jobs[entry].strategy !== undefined)
          return `The reusable workflow is called with a strategy; this ${kind} is a template, not proof for each instance.`;
        // Whether a skipped callee job fails the calling job is not documented,
        // so a conditional job is not treated as a gate for the caller.
        const seen = new Set<string>();
        const conditional = (id: string): string | undefined => {
          const job = workflow.jobs[id];
          if (job.callEntry !== entry || seen.has(id)) return undefined;
          seen.add(id);
          if (!explicitSuccess(job.if)) return id;
          for (const need of job.needs) {
            const found = conditional(need);
            if (found) return found;
          }
        };
        const skipped = conditional(op.location.job);
        if (skipped)
          return `Callee job ${skipped} is conditional; when it is skipped the reusable workflow call can still succeed, so this ${kind} is not a proven gate.`;
        if (operationJob.strategy !== undefined)
          return `The callee job has a strategy; this ${kind} is a template, not proof for each instance.`;
      };
      const guaranteed = (op: Operation): boolean => {
        if (callGate(op)) return false;
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
        // The result for a job is the same on every path that reaches it.
        const visited = new Map<string, boolean>();
        const visit = (id: string): boolean => {
          const known = visited.get(id);
          if (known !== undefined) return known;
          const job = workflow.jobs[id];
          const result =
            id === op.location.job
              ? safeCondition(job.if) &&
                operationStepConditionIsSafe(operationStep?.if) &&
                (!op.guarded || op.guardedByJobCondition === true)
              : job.strategy === undefined &&
                !job['continue-on-error'] &&
                safeCondition(job.if) &&
                job.needs.some(visit);
          visited.set(id, result);
          return result;
        };
        return visit(deploy.location.job);
      };
      const sameIdentity = (op: Operation) =>
        op.identity.kind === 'immutable' &&
        deploy.identity.kind === 'immutable' &&
        op.identity.key === deploy.identity.key;
      const same = candidates.find((op) => guaranteed(op) && sameIdentity(op));
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
            ...(same.call ? { call: same.call } : {}),
          };
        continue;
      }
      // A reachable conditional consumer may check this exact artifact on the
      // runs where deployment occurs. Without evaluating condition correlation,
      // do not turn a different unconditional digest into a proven mismatch.
      const possibleSame = candidates.find(sameIdentity);
      if (possibleSame) {
        checkReasons[kind] = {
          file: possibleSame.location.file,
          line: possibleSame.location.line,
          reason:
            callGate(possibleSame) ??
            `A preceding ${kind} consumer references the deployed artifact, but its condition is not proven to run.`,
          ...(possibleSame.call ? { call: possibleSame.call } : {}),
        };
        continue;
      }
      // A recognized consumer with an unresolved identity may refer to the
      // deployed digest. Do not claim a mismatch while that possibility is
      // still in the lineage; the check remains unknown instead.
      const unresolved = candidates.find(
        (op) => op.identity.kind === 'unknown' && !isDisabled(op, workflow),
      );
      if (unresolved) {
        checkReasons[kind] = {
          file: unresolved.location.file,
          line: unresolved.location.line,
          reason: `A preceding ${kind} consumer has unresolved artifact identity.`,
          ...(unresolved.call ? { call: unresolved.call } : {}),
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
      } else {
        const symbolic = candidates.some(
          (op) =>
            op.identity.kind === 'immutable' &&
            deploy.identity.kind === 'immutable' &&
            op.identity.key !== deploy.identity.key &&
            (!op.identity.concrete || !deploy.identity.concrete),
        );
        // A consumer of the deployed artifact behind a call boundary that the
        // deployment does not wait for qualifies nothing.
        const unordered = operations.find(
          (op) =>
            op.kind === kind &&
            sameIdentity(op) &&
            op.call?.id !== deploy.call?.id &&
            !precedes(op, deploy, workflow),
        );
        const callSite = unordered?.call ?? deploy.call;
        checkReasons[kind] = unordered
          ? {
              file: unordered.location.file,
              line: unordered.location.line,
              reason: `The deployed artifact has a ${kind} consumer across reusable workflow call ${callSite?.job}, but the deployment does not depend on its completion.`,
              ...(unordered.call ? { call: unordered.call } : {}),
            }
          : {
              file: deploy.location.file,
              line: deploy.location.line,
              reason:
                deploy.identity.kind !== 'immutable'
                  ? 'Deployment identity is unresolved or mutable; equality cannot be proven.'
                  : symbolic
                    ? 'Independent symbolic digests have no proven equality or inequality.'
                    : `No preceding supported ${kind} consumer proves identity and successful execution for this deployment.`,
              ...(deploy.call ? { call: deploy.call } : {}),
            };
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
    const possibleTestOfDeployed = operations.some(
      (op) =>
        op.kind === 'test' &&
        precedes(op, deploy, workflow) &&
        deploy.identity.kind === 'immutable' &&
        (op.identity.kind === 'unknown' ||
          (op.identity.kind === 'immutable' &&
            op.identity.key === deploy.identity.key) ||
          (op.identity.kind === 'mutable' &&
            op.identity.repository === deploy.identity.repository)),
    );
    if (stronglyLinkedBuild && checks.test === 'unknown' && !possibleTestOfDeployed) {
      checks.test = 'mismatch';
      delete checkReasons.test;
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
