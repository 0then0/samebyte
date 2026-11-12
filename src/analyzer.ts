import { createHash } from 'node:crypto';
import { basename, relative, sep } from 'node:path';
import {
  actionConsumption,
  nonMutatingDeployment,
  shellBuild,
  shellConsumption,
} from './adapters.js';
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
  Call,
  CallSite,
  CallValue,
  CoverageNotice,
  Job,
  Operation,
  OperationKind,
  Report,
  Value,
  Workflow,
} from './model.js';
import { type CallResolution, opaqueCallMessage, unloadedCall } from './reusable.js';
import { analyzeRules, operationIsUnreachable } from './rules.js';
import { balancedQuotes, resolveShell, tokenize } from './shell.js';
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
const hasUnknownShellArgumentBeforeReference = (
  tokens: string[],
  reference: string,
  referenceIndex?: number,
) => {
  const index =
    referenceIndex ?? tokens.findIndex((token) => token.includes(reference));
  return tokens
    .slice(0, index < 0 ? tokens.length : index)
    .some((token) => token.includes('__samebyte_unknown__'));
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
// One analysis pass over the jobs of a workflow. The entry workflow has no call;
// each expanded reusable workflow call gets a frame of its own, so job ids, step
// ids, outputs and inputs of different invocations never share a scope.
interface Frame {
  workflow: Workflow;
  // Maps a job id of this workflow to its node in the combined job graph.
  id: (job: string) => string;
  call?: CallSite;
  entry?: string;
  inputs: Map<string, Value>;
  // The calling job has a strategy: callee operations are templates.
  template: boolean;
}
const isMapping = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);
// A workflow_call input value under GitHub's declared scalar types. A literal of
// another type, or an expression passed to a non-string input, stays unknown.
function typedInput(raw: unknown, type: string, scope: Scope): Value {
  if (typeof raw === 'string' && raw.includes('${{')) {
    const value = resolveValue(raw, scope);
    if (type === 'string') return value;
    return {
      ...value,
      unknown: true,
      trace: [...value.trace, `Expression result is not verified as ${type}`],
    };
  }
  const literal: string = raw === null ? 'null' : typeof raw;
  if (literal === type) return { text: String(raw), unknown: false, trace: [] };
  return unknownValue(
    String(raw ?? ''),
    `Literal ${literal} does not match declared type ${type}`,
  );
}
export function analyzeWorkflow(
  workflow: Workflow,
  config: Config = { annotations: [] },
  // Without a resolution every job-level `uses` stays an opaque boundary.
  resolution?: CallResolution,
): Report {
  const operations: Operation[] = [];
  const coverage: CoverageNotice[] = [];
  const calls: Call[] = [];
  const diagnostics: Report['diagnostics'] = [];
  // Jobs of the entry workflow and of every expanded call, for ordering and gates.
  const graph: Record<string, Job> = {};
  let digestSequence = 0;
  const namespace = createHash('sha256')
    .update(workflow.file)
    .digest('hex')
    .slice(0, 16);
  const display = (file: string) =>
    resolution?.root
      ? relative(resolution.root, file).split(sep).join('/')
      : basename(file);
  const callValue = (value: Value, extra: Partial<CallValue>): CallValue => ({
    state: value.unknown ? 'unknown' : 'resolved',
    value: value.text,
    ...extra,
    path: value.trace,
  });
  const analyzeJobs = (frame: Frame): Map<string, Scope> => {
    const wf = frame.workflow;
    const jobOutputs = new Map<string, Scope>();
    for (const [localJobId, job] of Object.entries(wf.jobs)) {
      const jobId = frame.id(localJobId);
      const jobLocation = { file: wf.file, line: job.line, job: jobId };
      const site: CallSite | undefined = frame.call
        ? { ...frame.call, calleeJob: localJobId }
        : undefined;
      const inCall = site ? { call: site } : {};
      graph[jobId] = frame.entry
        ? {
            ...job,
            needs: [...job.needs.map(frame.id), frame.entry],
            callEntry: frame.entry,
          }
        : job;
      if (job.steps.some((step) => step.parallel !== undefined))
        diagnostics.push({
          file: wf.file,
          message: `Job ${jobId} contains a parallel block whose nested operations are not analyzed; artifact lineage is incomplete.`,
        });
      let scope: Scope = new Map();
      for (const need of job.needs)
        for (const [key, value] of jobOutputs.get(need) ?? [])
          if (key === '*') scope.set(`needs.${need.toLowerCase()}.outputs.*`, value);
          else bind(scope, `needs.${need}.outputs.${key}`, value);
      for (const [name, value] of frame.inputs) bind(scope, `inputs.${name}`, value);
      if (job.strategy !== undefined && !job.uses)
        coverage.push({
          reason: 'matrix-job',
          type: 'matrix',
          location: jobLocation,
          message:
            'Job strategy is not expanded. Operations represent templates; per-instance identity and unconditional execution are not proven.',
          ...inCall,
        });
      if (job.uses) {
        jobOutputs.set(
          localJobId,
          analyzeCall(frame, job as Job & { uses: string }, jobId, jobLocation, scope),
        );
        continue;
      }
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
        const outputs =
          pendingBackgroundOutputs.get(stepId) ?? new Map<string, Value>();
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
      // Workflow-level env is that of this workflow file only: a caller's env is
      // not propagated into a reusable workflow.
      scope = environment(environment(scope, wf.env), job.env);
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
          frame.template ||
          hasParallelBlock ||
          !!job['continue-on-error'] ||
          !!step['continue-on-error'];
        const guardedByJobCondition =
          guarded &&
          job.if !== undefined &&
          !isExplicitSuccess(job.if) &&
          step.if === undefined &&
          job.strategy === undefined &&
          !frame.template &&
          !job['continue-on-error'] &&
          !step['continue-on-error'] &&
          !hasParallelBlock;
        const prefix = site
          ? `${site.id} > ${wf.file}#${localJobId}.${stepId}`
          : `${wf.file}#${jobId}.${stepId}`;
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
              file: wf.file,
              line: step.line,
              job: jobId,
              step: index,
            },
            ...inCall,
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
            a.workflow === basename(wf.file) &&
            a.job === localJobId &&
            a.step === step.id,
        );
        const notice = (
          reason: CoverageNotice['reason'],
          type: CoverageNotice['type'],
          message: string,
          target?: string,
        ) => {
          // One notice per reason per step, even for a multiline script.
          if (
            coverage.some(
              (item) =>
                item.reason === reason &&
                item.location.job === jobId &&
                item.location.step === index,
            )
          )
            return;
          coverage.push({
            reason,
            type,
            location: { ...jobLocation, line: step.line, step: index },
            message,
            ...(target ? { target } : {}),
            ...inCall,
          });
        };
        // An annotation describes the asserted operation, not everything the
        // opaque action does. Retain its coverage boundary as well as its evidence.
        if (step.uses?.startsWith('./'))
          notice(
            'local-action-call',
            'action',
            'Local action contents are not analyzed. Additional operations and value transfers may be hidden behind this call.',
            step.uses,
          );
        if (annotations.length) {
          if (step.run)
            notice(
              'unsupported-shell',
              'shell',
              'Shell interpretation is replaced by trusted annotations. Additional operations and value transfers are not analyzed.',
            );
          if (step.uses && !step.uses.startsWith('./'))
            notice(
              'unsupported-action-call',
              'action',
              'Action interpretation is replaced by trusted annotations. Its contents and additional behavior are not analyzed.',
              step.uses,
            );
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
            const consumers = actionConsumption(
              step.uses,
              Object.fromEntries(
                Object.entries(inputs).map(([key, value]) => [key, value.text]),
              ),
              Object.fromEntries(
                [...stepScope]
                  .filter(([key]) => key.startsWith('shell.'))
                  .map(([key, value]) => [key.slice(6), value.text]),
              ),
            );
            if (!consumers.length && !step.uses.startsWith('./'))
              notice(
                'unsupported-action-call',
                'action',
                'No OCI adapter interprets this action call. Its contents may contain operations or value transfers outside the analyzed graph.',
                step.uses,
              );
            for (const consumer of consumers) {
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
          const shell = resolveShell(wf, job, step);
          const unsupportedShell = !shell.supported;
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
          const shellNotice = () =>
            notice(
              'unsupported-shell',
              'shell',
              shell.supported
                ? 'Shell syntax, shell selection, or output writes are outside the supported interpreter. Operations and value transfers may be missing or unresolved.'
                : `Shell is not supported or cannot be established: ${shell.reason}. Operations and value transfers in this script are not interpreted.`,
            );
          if (complex || unknownOutputWrite) shellNotice();
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
              shellNotice();
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
            const consumers = shellConsumption(
              tokens,
              Object.fromEntries(
                [...stepScope]
                  .filter(([key]) => key.startsWith('shell.'))
                  .map(([key, value]) => [key.slice(6), value.text]),
              ),
            );
            if (
              !build &&
              !consumers.length &&
              !nonMutatingDeployment(tokens) &&
              tokens[0] !== 'echo'
            )
              notice(
                'uninterpreted-command',
                'shell',
                'This command is not interpreted. SameByte does not execute binaries or scripts or infer their OCI behavior from names.',
                tokens[0],
              );
            for (const consumer of consumers)
              record(
                consumer.kind,
                consumer.reference
                  ? {
                      ...resolved,
                      text: consumer.reference,
                      // An unrelated unresolved variable in a test command must
                      // not erase an image identity that was parsed separately.
                      // Unknown shell expansions before the image may shift its
                      // argument position, so their boundary remains unresolved.
                      // Expansions after the image cannot change its identity.
                      unknown:
                        consumer.identityUnknown !== undefined ||
                        consumer.reference.includes('__samebyte_unknown__') ||
                        hasUnknownShellArgumentBeforeReference(
                          tokens,
                          consumer.reference,
                          consumer.referenceIndex,
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
      jobOutputs.set(localJobId, outputs);
    }
    return jobOutputs;
  };
  // Expands one job-level `uses`. Returns the outputs the calling job exposes
  // through `needs`; a call that is not expanded exposes only unknown outputs.
  const analyzeCall = (
    frame: Frame,
    job: Job & { uses: string },
    jobId: string,
    jobLocation: { file: string; line: number; job: string },
    callScope: Scope,
  ): Scope => {
    const wf = frame.workflow;
    const callId = `${wf.file}#${jobId}`;
    const outer = frame.call ? { call: frame.call } : {};
    const caller = { file: wf.file, line: job.line, job: jobId };
    const opaque = (reason: CoverageNotice['reason'], message: string): Scope => {
      coverage.push({
        reason,
        type: 'reusable-workflow',
        location: jobLocation,
        target: job.uses,
        message,
        ...outer,
      });
      if (job.strategy !== undefined) matrixNotice();
      calls.push({
        id: callId,
        caller,
        target: job.uses,
        status: 'boundary',
        reason,
        ...outer,
      });
      return new Map([
        [
          '*',
          unknownValue(
            'unknown reusable workflow output',
            `Reusable workflow call ${jobId} is not expanded (${reason}); its outputs are unknown`,
          ),
        ],
      ]);
    };
    const matrixNotice = () =>
      coverage.push({
        reason: 'matrix-job',
        type: 'matrix',
        location: jobLocation,
        message:
          'Job strategy is not expanded. Operations represent templates; per-instance identity and unconditional execution are not proven.',
        ...outer,
      });
    if (frame.call)
      return opaque(
        'nested-reusable-workflow-call',
        'A reusable workflow called from a reusable workflow is not expanded: one level of local calls is analyzed. Operations, outputs and execution gates behind this nested call are unknown.',
      );
    const unloaded = unloadedCall(job.uses);
    if (unloaded?.status === 'boundary')
      return opaque(unloaded.reason, unloaded.message);
    if (!resolution) return opaque('reusable-workflow-call', opaqueCallMessage);
    if (!resolution.root)
      return opaque(
        'reusable-workflow-call',
        `The calling workflow is not stored in a .github/workflows directory, so no repository root is established and the local reusable workflow is not loaded. ${opaqueCallMessage}`,
      );
    const resolved = resolution.callees.get(job.uses);
    if (!resolved) return opaque('reusable-workflow-call', opaqueCallMessage);
    if (resolved.status === 'boundary')
      return opaque(resolved.reason, resolved.message);
    const callee = resolved.workflow;
    const contract = callee.call ?? { inputs: {}, outputs: {} };
    const calleeName = display(callee.file);
    const passed = job.with === undefined || job.with === null ? {} : job.with;
    const problems: string[] = [];
    if (!isMapping(passed)) problems.push('with must be a mapping');
    const withValues = isMapping(passed) ? passed : {};
    const declared = new Set(
      Object.keys(contract.inputs).map((name) => name.toLowerCase()),
    );
    for (const [key, value] of Object.entries(withValues)) {
      if (!declared.has(key.toLowerCase()))
        problems.push(`input ${key} is not declared by the called workflow`);
      else if (typeof value === 'object' && value !== null)
        problems.push(`input ${key} must be a scalar`);
    }
    const passedKey = (name: string) =>
      Object.keys(withValues).find((key) => key.toLowerCase() === name.toLowerCase());
    for (const [name, input] of Object.entries(contract.inputs))
      if (input.required && passedKey(name) === undefined)
        problems.push(`required input ${name} is not provided`);
    if (problems.length)
      return opaque(
        'reusable-workflow-contract',
        `The call does not match the workflow_call contract of ${calleeName}: ${problems.join('; ')}. GitHub rejects such a call, so the callee is not joined to this caller.`,
      );
    const site: CallSite = { id: callId, ...caller, workflow: callee.file };
    if (job.strategy !== undefined) matrixNotice();
    if (job.secrets !== undefined)
      coverage.push({
        reason: 'reusable-workflow-secrets',
        type: 'reusable-workflow',
        location: jobLocation,
        target: job.uses,
        message:
          'Secrets passed to the reusable workflow are not resolved. Values derived from secrets inside the callee stay unknown.',
      });
    // `with` is evaluated in the caller: its needs are visible, its env is not.
    const inputs = new Map<string, Value>();
    const callInputs: Record<string, CallValue> = {};
    for (const [name, input] of Object.entries(contract.inputs)) {
      const key = passedKey(name);
      const declaration = `${calleeName}:${input.line} workflow_call input ${name}`;
      let value: Value;
      let source: CallValue['source'];
      if (key !== undefined) {
        source = 'with';
        value = typedInput(withValues[key], input.type, callScope);
        value.trace.push(
          `${display(wf.file)}:${job.withLines?.[key] ?? job.line} job ${jobId}: with.${key}`,
        );
      } else if (input.default !== undefined) {
        source = 'default';
        value = typedInput(input.default, input.type, new Map());
        value.trace.push(`${declaration}: default`);
      } else {
        source = 'type-default';
        value = {
          text: { string: '', number: '0', boolean: 'false' }[input.type],
          unknown: false,
          trace: [`${declaration}: not passed, ${input.type} default`],
        };
      }
      value.trace.push(`call ${jobId} -> ${declaration}`);
      inputs.set(name, value);
      callInputs[name] = callValue(value, { source, line: input.line });
    }
    const entry = `${jobId} (call)`;
    const id = (calleeJob: string) => `${jobId} / ${calleeJob}`;
    graph[entry] = {
      line: job.line,
      needs: job.needs,
      steps: [],
      if: job.if,
      strategy: job.strategy,
    };
    const inner = analyzeJobs({
      workflow: callee,
      id,
      call: site,
      entry,
      inputs,
      template: job.strategy !== undefined,
    });
    // The calling job completes after every job of the callee.
    graph[jobId] = {
      ...job,
      steps: [],
      needs: [...job.needs, entry, ...Object.keys(callee.jobs).map(id)],
    };
    // A callee job that can be skipped, or whose failure is ignored, leaves its
    // outputs empty while the call still succeeds.
    const uncertainOutputs = (
      calleeJob: string,
      seen = new Set<string>(),
    ): string | undefined => {
      if (seen.has(calleeJob)) return undefined;
      seen.add(calleeJob);
      const target = callee.jobs[calleeJob];
      if (target.if !== undefined && !isExplicitSuccess(target.if))
        return `Callee job ${calleeJob} is conditional; its outputs are empty when it is skipped`;
      if (target['continue-on-error'])
        return `Callee job ${calleeJob} ignores failure; its outputs may be unset`;
      if (target.strategy !== undefined)
        return `Callee job ${calleeJob} has a strategy; its outputs come from one instance`;
      for (const need of target.needs) {
        const reason = uncertainOutputs(need, seen);
        if (reason) return reason;
      }
    };
    // Workflow outputs may read `jobs.<job>.outputs.<name>` and `inputs`.
    const outputScope: Scope = new Map();
    for (const [name, value] of inputs) bind(outputScope, `inputs.${name}`, value);
    outputScope.set(
      'jobs.*',
      unknownValue(
        'unknown job output',
        `Workflow output references a job that does not exist in ${calleeName}`,
      ),
    );
    for (const calleeJob of Object.keys(callee.jobs)) {
      const uncertain = uncertainOutputs(calleeJob);
      const prefix = `jobs.${calleeJob}.outputs`;
      outputScope.set(
        `${prefix.toLowerCase()}.*`,
        unknownValue(
          'unknown job output',
          `Callee job ${calleeJob} in ${calleeName} declares no output with this name`,
        ),
      );
      for (const [key, value] of inner.get(calleeJob) ?? [])
        if (key === '*') outputScope.set(`${prefix.toLowerCase()}.*`, value);
        else
          bind(
            outputScope,
            `${prefix}.${key}`,
            uncertain
              ? { ...value, unknown: true, trace: [...value.trace, uncertain] }
              : value,
          );
    }
    const outputs: Scope = new Map();
    const callOutputs: Record<string, CallValue> = {};
    for (const [name, output] of Object.entries(contract.outputs)) {
      const value = resolveValue(output.value, outputScope);
      if (job.strategy !== undefined) {
        value.unknown = true;
        value.trace.push('Matrix call: the output comes from one unspecified instance');
      }
      value.trace.push(
        `${calleeName}:${output.line} workflow_call output ${name}`,
        `call ${jobId} (${display(wf.file)}:${job.line}) output ${name}`,
      );
      bind(outputs, name, value);
      callOutputs[name] = callValue(value, { line: output.line });
    }
    outputs.set(
      '*',
      unknownValue(
        'unknown reusable workflow output',
        `${calleeName} declares no workflow_call output with this name (call ${jobId})`,
      ),
    );
    calls.push({
      id: callId,
      caller,
      target: job.uses,
      workflow: callee.file,
      status: 'expanded',
      inputs: callInputs,
      outputs: callOutputs,
      jobs: Object.keys(callee.jobs).map(id),
    });
    return outputs;
  };
  analyzeJobs({
    workflow,
    id: (job) => job,
    inputs: new Map(),
    template: false,
  });
  const jobGraph: Workflow = { ...workflow, jobs: graph };
  const reachability = new Map<string, boolean>();
  const reachableOperations = operations.filter(
    (operation) => !operationIsUnreachable(operation, jobGraph, reachability),
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
  const result = analyzeRules(reachableOperations, jobGraph);
  return {
    version: 1,
    workflows: [workflow.file],
    operations: reachableOperations,
    artifacts,
    ...result,
    diagnostics,
    coverage,
    calls,
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
    coverage: reports.flatMap((r) => r.coverage),
    calls: reports.flatMap((r) => r.calls),
  };
}
