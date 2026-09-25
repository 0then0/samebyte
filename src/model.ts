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
export interface Operation {
  id: string;
  kind: OperationKind;
  identity: Identity;
  location: Location;
  label: string;
  guarded: boolean;
  order: number;
  completionStep?: number;
  producedReference?: string;
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
  evidence: { operation: string; reference: string; path: string[] }[];
}
export interface Deployment {
  operation: string;
  state: State;
  checks: Record<'test' | 'scan' | 'attest', State>;
}
export interface Report {
  version: 1;
  workflows: string[];
  artifacts: Artifact[];
  operations: Operation[];
  deployments: Deployment[];
  findings: Finding[];
  diagnostics: { file: string; message: string }[];
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
  needs: string[];
  steps: Step[];
  env?: Record<string, unknown>;
  outputs?: Record<string, unknown>;
  if?: unknown;
  strategy?: unknown;
  'continue-on-error'?: unknown;
  uses?: string;
  defaults?: { run?: { shell?: string } };
  'runs-on'?: unknown;
}
export interface Workflow {
  file: string;
  env?: Record<string, unknown>;
  jobs: Record<string, Job>;
  defaults?: { run?: { shell?: string } };
}
export const unknownValue = (text: string, reason: string): Value => ({
  text,
  unknown: true,
  trace: [reason],
});
