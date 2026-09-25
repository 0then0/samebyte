import { createHash } from 'node:crypto';
import { basename } from 'node:path';
import { actionConsumption, shellBuild, shellConsumption } from './adapters.js';
import {
  bind,
  environment,
  identity,
  resolveValue,
  type Scope,
  shellValue,
  unknownValue,
} from './expressions.js';
import type {
  Artifact,
  Operation,
  OperationKind,
  Report,
  Value,
  Workflow,
} from './model.js';
import { analyzeRules, operationIsUnreachable } from './rules.js';
import { balancedQuotes, tokenize } from './shell.js';
export interface Annotation {
  workflow: string;
  job: string;
  step: string;
  operation: Exclude<OperationKind, 'source-test'>;
  image?: string;
  output?: string;
}
export interface Config {
  annotations: Annotation[];
}
const isExplicitSuccess = (condition: unknown): boolean =>
  String(condition)
    .replace(/^\s*\$\{\{\s*|\s*\}\}\s*$/g, '')
    .replace(/^\((.*)\)$/s, '$1')
    .trim()
    .toLowerCase() === 'success()';
const invalidateTrivyInput = (scope: Scope) => {
  const value = unknownValue('unknown TRIVY_INPUT value', 'Shell environment mutation');
  bind(scope, 'env.TRIVY_INPUT', value);
  scope.set('shell.TRIVY_INPUT', value);
};
export function validateConfig(raw: unknown): Config {
  const config = raw as Config;
  if (!config || !Array.isArray(config.annotations))
    throw new Error('Config requires an annotations array.');
  for (const item of config.annotations) {
    if (
      !item ||
      !['build', 'test', 'scan', 'attest', 'deploy'].includes(item.operation) ||
      ![item.workflow, item.job, item.step].every(
        (value) => typeof value === 'string' && !!value,
      ) ||
      (item.image !== undefined && typeof item.image !== 'string') ||
      (item.output !== undefined && typeof item.output !== 'string')
    )
      throw new Error(
        'Invalid annotation. Expected workflow, job, step, operation and optional image/output strings.',
      );
    if (item.operation !== 'build' && !item.image)
      throw new Error('Consumer annotations require image.');
  }
  return config;
}
export function analyzeWorkflow(
  workflow: Workflow,
  config: Config = { annotations: [] },
): Report {
  const operations: Operation[] = [];
  const jobOutputs = new Map<string, Scope>();
  let digestSequence = 0;
  const namespace = createHash('sha256')
    .update(workflow.file)
    .digest('hex')
    .slice(0, 16);
  for (const [jobId, job] of Object.entries(workflow.jobs)) {
    let scope: Scope = new Map();
    const backgroundOperations = new Map<string, Operation[]>();
    const pendingBackgroundOutputs = new Map<string, Map<string, Value>>();
    const hasParallelBlock = job.steps.some((step) => step.parallel !== undefined);
    const publishStepOutput = (
      stepId: string,
      name: string,
      value: Value,
      background: boolean,
    ) => {
      const key = `steps.${stepId}.outputs.${name}`;
      if (!background) {
        bind(scope, key, value);
        return;
      }
      const outputs = pendingBackgroundOutputs.get(stepId) ?? new Map<string, Value>();
      outputs.set(key, value);
      pendingBackgroundOutputs.set(stepId, outputs);
      bind(
        scope,
        key,
        unknownValue(value.text, 'Output unavailable before background wait'),
      );
    };
    const releaseBackgroundOutputs = (stepId: string, mayHaveFailed = false) => {
      for (const [key, value] of pendingBackgroundOutputs.get(stepId) ?? [])
        bind(
          scope,
          key,
          mayHaveFailed
            ? {
                ...value,
                unknown: true,
                trace: [...value.trace, 'Background result may have been ignored'],
              }
            : value,
        );
      pendingBackgroundOutputs.delete(stepId);
    };
    for (const need of job.needs)
      for (const [key, value] of jobOutputs.get(need) ?? [])
        bind(scope, `needs.${need}.outputs.${key}`, value);
    scope = environment(environment(scope, workflow.env), job.env);
    for (const [index, step] of job.steps.entries()) {
      if (
        step.wait !== undefined ||
        step['wait-all'] === true ||
        step['wait-all'] === null
      ) {
        const mayHaveFailed =
          !!step['continue-on-error'] ||
          (step.if !== undefined && !isExplicitSuccess(step.if));
        const targets =
          step['wait-all'] === true || step['wait-all'] === null
            ? [...backgroundOperations.keys()]
            : Array.isArray(step.wait)
              ? step.wait
              : [step.wait as string];
        for (const target of targets) {
          for (const operation of backgroundOperations.get(target) ?? []) {
            operation.completionStep = index;
            operation.guarded ||= mayHaveFailed;
            if (mayHaveFailed) operation.guardedByJobCondition = false;
          }
          releaseBackgroundOutputs(target, mayHaveFailed);
          backgroundOperations.delete(target);
        }
        continue;
      }
      if (step.cancel !== undefined) {
        const targets = Array.isArray(step.cancel)
          ? step.cancel
          : [step.cancel as string];
        for (const target of targets) {
          for (const operation of backgroundOperations.get(target) ?? []) {
            operation.completionStep = index;
            operation.guarded = true;
            operation.guardedByJobCondition = false;
          }
          pendingBackgroundOutputs.delete(target);
          backgroundOperations.delete(target);
        }
        continue;
      }
      const firstOperation = operations.length;
      const backgroundId = step.id ?? `__samebyte_background_${index}`;
      const stepScope = environment(scope, step.env);
      const stepId = step.id ?? String(index + 1);
      const guarded =
        (job.if !== undefined && !isExplicitSuccess(job.if)) ||
        (step.if !== undefined && !isExplicitSuccess(step.if)) ||
        job.strategy !== undefined ||
        hasParallelBlock ||
        !!job['continue-on-error'] ||
        !!step['continue-on-error'];
      const guardedByJobCondition =
        guarded &&
        job.if !== undefined &&
        !isExplicitSuccess(job.if) &&
        step.if === undefined &&
        job.strategy === undefined &&
        !job['continue-on-error'] &&
        !step['continue-on-error'] &&
        !hasParallelBlock;
      const prefix = `${workflow.file}#${jobId}.${stepId}`;
      const record = (
        kind: OperationKind,
        value: Value,
        label: string,
        extraGuard = false,
      ) => {
        const operationIdentity = identity({
          ...value,
          trace: [...value.trace, `${jobId} step ${index + 1}: ${label}`],
        });
        const runtimeIdentityUnknown =
          kind === 'test' && operationIdentity.concrete
            ? 'digest may reference an OCI index; selected platform manifest is not tracked'
            : undefined;
        const operation: Operation = {
          id: `${prefix}:${operations.length}`,
          kind,
          identity: runtimeIdentityUnknown
            ? {
                ...operationIdentity,
                trace: [...operationIdentity.trace, runtimeIdentityUnknown],
              }
            : operationIdentity,
          label,
          runtimeIdentityUnknown,
          order: operations.length,
          guardedByJobCondition: guardedByJobCondition && !extraGuard,
          completionStep: step.background === true ? job.steps.length : undefined,
          guarded: guarded || extraGuard,
          location: {
            file: workflow.file,
            line: step.line,
            job: jobId,
            step: index,
          },
        };
        operations.push(operation);
        return operation;
      };
      const produce = (
        label: string,
        output?: string,
        reference?: Value,
        unknownIdentity = false,
      ) => {
        const digest: Value = {
          text: `__samebyte_digest_${namespace}_${++digestSequence}__`,
          unknown: guarded || unknownIdentity,
          trace: [
            `${jobId}.${stepId}: ${label}`,
            ...(unknownIdentity
              ? ['multi-platform child manifest identity is not tracked']
              : []),
            'OCI digest output',
          ],
        };
        const build = record('build', digest, label);
        if (reference && !reference.unknown && !/[\s,]/.test(reference.text))
          build.producedReference = reference.text;
        if (output && step.id)
          publishStepOutput(step.id, output, digest, step.background === true);
      };
      const annotations = config.annotations.filter(
        (a) =>
          a.workflow === basename(workflow.file) &&
          a.job === jobId &&
          a.step === step.id,
      );
      if (annotations.length) {
        for (const a of annotations) {
          if (a.operation === 'build')
            produce(
              'User-declared OCI producer',
              a.output ?? 'digest',
              a.image ? resolveValue(a.image, stepScope) : undefined,
            );
          else
            record(
              a.operation,
              resolveValue(a.image, stepScope),
              'User-declared artifact consumer',
            );
        }
        if (step.background === true)
          backgroundOperations.set(backgroundId, operations.slice(firstOperation));
        continue;
      }
      if (step.uses) {
        const action = step.uses.split('@')[0].toLowerCase();
        if (action === 'docker/build-push-action') {
          const platforms = String(step.with?.platforms ?? '').trim();
          const multiPlatform =
            platforms.includes('${{') ||
            platforms.split(/[\s,]+/).filter(Boolean).length > 1;
          produce(
            step.uses,
            'digest',
            step.with?.tags ? resolveValue(step.with.tags, stepScope) : undefined,
            multiPlatform,
          );
        } else {
          const inputs = Object.fromEntries(
            Object.entries(step.with ?? {}).map(([key, raw]) => [
              key,
              resolveValue(raw, stepScope),
            ]),
          );
          for (const consumer of actionConsumption(
            step.uses,
            Object.fromEntries(
              Object.entries(inputs).map(([key, value]) => [key, value.text]),
            ),
            Object.fromEntries(
              [...stepScope]
                .filter(([key]) => key.startsWith('shell.'))
                .map(([key, value]) => [key.slice(6), value.text]),
            ),
          )) {
            const usedInputs = consumer.usedInputs ?? [];
            record(
              consumer.kind,
              consumer.reference
                ? {
                    text: consumer.reference,
                    unknown: usedInputs.some((key) => inputs[key]?.unknown),
                    trace: usedInputs.flatMap((key) => {
                      const value = inputs[key];
                      return value
                        ? [...value.trace, `with.${key} = ${value.text}`]
                        : [];
                    }),
                  }
                : unknownValue(step.uses, 'Unsupported or missing image input'),
              step.uses,
            );
          }
        }
      }
      if (step.run) {
        const lines = step.run
          .replace(/\\\r?\n/g, ' ')
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter((line) => line && !line.startsWith('#'));
        // Control flow changes the meaning of later lines. Invalidate the whole
        // script before interpreting any individual command.
        const shell =
          step.shell ?? job.defaults?.run?.shell ?? workflow.defaults?.run?.shell;
        const unsupportedShell =
          shell !== undefined
            ? !['bash', 'sh'].includes(shell)
            : JSON.stringify(job['runs-on'] ?? '').includes('windows');
        const complex =
          unsupportedShell ||
          lines.some((line) => !balancedQuotes(line)) ||
          lines.some((line) =>
            /^(if|then|else|elif|fi|for|while|until|case|esac|do|done|function|exit|return|set|source|alias|eval|exec|trap|unset|read|declare|typeset|local|readonly)\b|\$\(|`|\|\||&&|;|\||<<|^\.\s|[{}]/.test(
              line
                .replace(/\$\{\{.*?\}\}/g, 'EXPR')
                .replace(/\$\{[A-Za-z_]\w*\}/g, 'VAR'),
            ),
          );
        const outputPattern =
          /^echo\s+(["'])([A-Za-z_][\w-]*)=(.*?)\1\s*>>\s*["']?\$(?:GITHUB_OUTPUT|\{GITHUB_OUTPUT\})["']?$/;
        const unknownOutputWrite = lines.some(
          (line) => line.includes('GITHUB_OUTPUT') && !outputPattern.test(line),
        );
        for (const line of lines) {
          const output =
            /^echo\s+(["'])([A-Za-z_][\w-]*)=(.*?)\1\s*>>\s*["']?\$(?:GITHUB_OUTPUT|\{GITHUB_OUTPUT\})["']?$/.exec(
              line,
            );
          if (output && step.id) {
            const value =
              complex || unknownOutputWrite
                ? unknownValue('unknown step output', 'Complex shell output')
                : output[1] === "'"
                  ? resolveValue(output[3], stepScope)
                  : shellValue(output[3], stepScope);
            value.unknown ||= guarded;
            publishStepOutput(step.id, output[2], value, step.background === true);
            continue;
          }
          if (line.includes('GITHUB_ENV')) {
            for (const target of [scope, stepScope])
              for (const key of target.keys())
                if (key.startsWith('env.') || key.startsWith('shell.'))
                  target.set(
                    key,
                    unknownValue('unknown environment value', 'GITHUB_ENV mutation'),
                  );
            invalidateTrivyInput(scope);
            invalidateTrivyInput(stepScope);
          }
          const resolved = shellValue(line, stepScope);
          const tokens = complex ? undefined : tokenize(resolved.text);
          if (!tokens) {
            if (/\b(kubectl|helm)\b/.test(line))
              record(
                'deploy',
                unknownValue(
                  'unknown deployment reference',
                  'Unsupported shell syntax',
                ),
                'unsupported shell command',
                true,
              );
            if (/\bdocker\s+(?:run|compose)\b/.test(line))
              record(
                'test',
                unknownValue('unknown image reference', 'Unsupported shell syntax'),
                'unsupported shell command',
                true,
              );
            continue;
          }
          const build = shellBuild(tokens);
          if (build)
            produce(
              tokens.slice(0, 3).join(' '),
              undefined,
              build.tag ? { ...resolved, text: build.tag } : undefined,
            );
          for (const consumer of shellConsumption(
            tokens,
            Object.fromEntries(
              [...stepScope]
                .filter(([key]) => key.startsWith('shell.'))
                .map(([key, value]) => [key.slice(6), value.text]),
            ),
          ))
            record(
              consumer.kind,
              consumer.reference
                ? {
                    ...resolved,
                    text: consumer.reference,
                    // An unrelated unresolved variable in a test command must
                    // not erase an image identity that was parsed separately.
                    // Unknown symbolic values retain their own text, which lets
                    // us keep the reference unknown when that value is the image.
                    unknown:
                      consumer.identityUnknown !== undefined ||
                      consumer.reference.includes('__samebyte_unknown__') ||
                      [...stepScope.values()].some(
                        (value) =>
                          value.unknown &&
                          value.text.length > 0 &&
                          (consumer.reference?.includes(value.text) ||
                            consumer.reference === value.text.split(/\s/, 1)[0]),
                      ),
                    trace: consumer.identityUnknown
                      ? [...resolved.trace, consumer.identityUnknown]
                      : resolved.trace,
                  }
                : consumer.kind === 'source-test'
                  ? unknownValue(
                      'local application build',
                      'source tests do not establish OCI identity',
                    )
                  : unknownValue(
                      'unknown image reference',
                      'Image reference could not be resolved',
                    ),
              tokens.slice(0, 2).join(' '),
            );
          // Assignment and external scripts may mutate env or external state.
          // Do not read local scripts or infer their behavior from their names.
          if (
            /^[A-Za-z_]\w*=/.test(line) ||
            tokens[0] === 'export' ||
            line.includes('GITHUB_ENV')
          ) {
            for (const key of stepScope.keys())
              if (key.startsWith('env.') || key.startsWith('shell.'))
                stepScope.set(
                  key,
                  unknownValue(
                    'unknown environment value',
                    'Shell environment mutation',
                  ),
                );
            const assignedTrivyInput =
              /^TRIVY_INPUT=/.test(line) ||
              (tokens[0] === 'export' &&
                tokens.slice(1).some((token) => /^TRIVY_INPUT(?:=|$)/.test(token)));
            if (assignedTrivyInput) invalidateTrivyInput(stepScope);
            if (line.includes('GITHUB_ENV'))
              for (const key of scope.keys())
                if (key.startsWith('env.') || key.startsWith('shell.'))
                  scope.set(
                    key,
                    unknownValue('unknown environment value', 'GITHUB_ENV mutation'),
                  );
            if (line.includes('GITHUB_ENV')) invalidateTrivyInput(scope);
          }
        }
      }
      if (step.background === true)
        backgroundOperations.set(backgroundId, operations.slice(firstOperation));
    }
    for (const stepId of pendingBackgroundOutputs.keys())
      releaseBackgroundOutputs(stepId);
    const outputs: Scope = new Map();
    for (const [key, raw] of Object.entries(job.outputs ?? {}))
      bind(outputs, key, resolveValue(raw, scope));
    jobOutputs.set(jobId, outputs);
  }
  const reachability = new Map<string, boolean>();
  const reachableOperations = operations.filter(
    (operation) => !operationIsUnreachable(operation, workflow, reachability),
  );
  const artifacts: Artifact[] = [];
  for (const operation of reachableOperations.filter(
    (op) => op.kind !== 'source-test',
  )) {
    let artifact =
      operation.identity.kind === 'immutable'
        ? artifacts.find((a) => a.identity.key === operation.identity.key)
        : undefined;
    if (!artifact) {
      artifact = {
        id: `${workflow.file}#artifact-${artifacts.length + 1}`,
        identity: operation.identity,
        producers: [],
        consumers: [],
      };
      artifacts.push(artifact);
    }
    (operation.kind === 'build' ? artifact.producers : artifact.consumers).push(
      operation.id,
    );
  }
  const result = analyzeRules(reachableOperations, workflow);
  const diagnostics = Object.entries(workflow.jobs)
    .filter(([, job]) => job.steps.some((step) => step.parallel !== undefined))
    .map(([job]) => ({
      file: workflow.file,
      message: `Job ${job} contains a parallel block whose nested operations are not analyzed; artifact lineage is incomplete.`,
    }));
  return {
    version: 1,
    workflows: [workflow.file],
    operations: reachableOperations,
    artifacts,
    ...result,
    diagnostics,
  };
}
export function mergeReports(reports: Report[]): Report {
  return {
    version: 1,
    workflows: reports.flatMap((r) => r.workflows),
    operations: reports.flatMap((r) => r.operations),
    artifacts: reports.flatMap((r) => r.artifacts),
    deployments: reports.flatMap((r) => r.deployments),
    findings: reports.flatMap((r) => r.findings),
    diagnostics: reports.flatMap((r) => r.diagnostics),
  };
}
