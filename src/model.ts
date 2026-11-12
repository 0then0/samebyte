export type State = 'proven' | 'mismatch' | 'unknown';
export type OperationKind =
  | 'build'
  | 'test'
  | 'scan'
  | 'attest'
  | 'deploy'
  | 'source-test';
export interface Location {
  file: string;
  line: number;
  job: string;
  step: number;
}
export interface Value {
  text: string;
  trace: string[];
  unknown: boolean;
}
export interface Identity {
  kind: 'immutable' | 'mutable' | 'unknown';
  key?: string;
  concrete: boolean;
  reference: string;
  repository?: string;
  trace: string[];
}
// Where a reusable workflow was called from. Operations, coverage notices and
// evidence found inside a callee carry both this call site and their own location.
export interface CallSite {
  // Matches Report.calls[].id; unique per invocation.
  id: string;
  file: string;
  line: number;
  job: string;
  // The called workflow file and, when known, the job inside it.
  workflow: string;
  calleeJob?: string;
}
export interface Operation {
  id: string;
  kind: OperationKind;
  identity: Identity;
  location: Location;
  label: string;
  guarded: boolean;
  guardedByJobCondition?: boolean;
  runtimeIdentityUnknown?: string;
  order: number;
  completionStep?: number;
  producedReference?: string;
  call?: CallSite;
}
export interface Artifact {
  id: string;
  identity: Identity;
  producers: string[];
  consumers: string[];
}
export interface Finding {
  ruleId: string;
  severity: 'high' | 'medium';
  confidence: 'high' | 'medium';
  state: State;
  message: string;
  location: Location;
  evidence: {
    operation: string;
    reference: string;
    path: string[];
    // Present for operations inside a reusable workflow call.
    location?: Location;
    call?: CallSite;
  }[];
  call?: CallSite;
}
export interface Deployment {
  operation: string;
  state: State;
  checks: Record<'test' | 'scan' | 'attest', State>;
  checkReasons?: Partial<
    Record<
      'test' | 'scan' | 'attest',
      { file: string; line: number; reason: string; call?: CallSite }
    >
  >;
}
export interface CoverageNotice {
  reason:
    | 'reusable-workflow-call'
    | 'reusable-workflow-not-found'
    | 'reusable-workflow-path'
    | 'reusable-workflow-invalid'
    | 'reusable-workflow-contract'
    | 'reusable-workflow-secrets'
    | 'nested-reusable-workflow-call'
    | 'local-action-call'
    | 'unsupported-action-call'
    | 'matrix-job'
    | 'unsupported-shell'
    | 'uninterpreted-command';
  type: 'reusable-workflow' | 'action' | 'matrix' | 'shell';
  // Job-level boundaries have no step index.
  location: Omit<Location, 'step'> & { step?: number };
  message: string;
  target?: string;
  call?: CallSite;
}
export interface CallValue {
  state: 'resolved' | 'unknown';
  value: string;
  // Inputs: where the value came from. Outputs: line of the mapping in the callee.
  source?: 'with' | 'default' | 'type-default';
  line?: number;
  path: string[];
}
export interface Call {
  id: string;
  caller: { file: string; line: number; job: string };
  target: string;
  // Resolved callee file; absent when the target was not loaded.
  workflow?: string;
  status: 'expanded' | 'boundary';
  reason?: CoverageNotice['reason'];
  inputs?: Record<string, CallValue>;
  outputs?: Record<string, CallValue>;
  jobs?: string[];
  // Set for a call found inside an expanded callee.
  call?: CallSite;
}
export interface Report {
  version: 1;
  workflows: string[];
  artifacts: Artifact[];
  operations: Operation[];
  deployments: Deployment[];
  findings: Finding[];
  diagnostics: { file: string; message: string }[];
  coverage: CoverageNotice[];
  calls: Call[];
}
export interface Step {
  id?: string;
  name?: string;
  uses?: string;
  run?: string;
  env?: Record<string, unknown>;
  with?: Record<string, unknown>;
  if?: unknown;
  'continue-on-error'?: unknown;
  background?: unknown;
  wait?: unknown;
  'wait-all'?: unknown;
  cancel?: unknown;
  parallel?: unknown;
  line: number;
  shell?: string;
}
export interface Job {
  line: number;
  needs: string[];
  steps: Step[];
  env?: Record<string, unknown>;
  outputs?: Record<string, unknown>;
  if?: unknown;
  strategy?: unknown;
  'continue-on-error'?: unknown;
  uses?: string;
  with?: unknown;
  // Line of each `with` entry of a reusable workflow call.
  withLines?: Record<string, number>;
  secrets?: unknown;
  defaults?: { run?: { shell?: string } };
  'runs-on'?: unknown;
  container?: unknown;
  // Set on jobs of an expanded callee: the graph node that starts the call.
  callEntry?: string;
}
export interface WorkflowInput {
  type: 'string' | 'number' | 'boolean';
  required: boolean;
  default?: unknown;
  line: number;
}
export interface WorkflowCallContract {
  inputs: Record<string, WorkflowInput>;
  outputs: Record<string, { value: unknown; line: number }>;
  // A structural problem in on.workflow_call; such a workflow cannot be expanded.
  error?: string;
}
export interface Workflow {
  file: string;
  env?: Record<string, unknown>;
  jobs: Record<string, Job>;
  defaults?: { run?: { shell?: string } };
  // Present when `on` includes workflow_call.
  call?: WorkflowCallContract;
  // True when workflow_call is the only trigger.
  callOnly?: boolean;
}
export const unknownValue = (text: string, reason: string): Value => ({
  text,
  unknown: true,
  trace: [reason],
});
