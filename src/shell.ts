import type { Job, Step, Workflow } from './model.js';

// Deliberately a tokenizer for straight-line commands, never a shell evaluator.
export function tokenize(command: string): string[] | undefined {
  if (/[`]|\$\(|[|;&<>]/.test(command)) return undefined;
  const tokens: string[] = [];
  let token = '';
  let quote = '';
  let active = false;
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (c === '\\' && quote !== "'") {
      if (i + 1 >= command.length) return undefined;
      token += command[++i];
      active = true;
    } else if (quote) {
      if (c === quote) quote = '';
      else token += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      active = true;
    } else if (/\s/.test(c)) {
      if (active) tokens.push(token);
      token = '';
      active = false;
    } else {
      token += c;
      active = true;
    }
  }
  if (quote) return undefined;
  if (active) tokens.push(token);
  return tokens;
}
export function flag(tokens: string[], ...names: string[]): string | undefined {
  for (let i = 0; i < tokens.length; i++)
    for (const name of names) {
      if (tokens[i] === name) return tokens[i + 1];
      if (tokens[i].startsWith(`${name}=`)) return tokens[i].slice(name.length + 1);
    }
  return undefined;
}
export function runImage(
  tokens: string[],
): { reference: string; index: number } | undefined {
  const argumentFlags = new Set([
    '-e',
    '--env',
    '--env-file',
    '-v',
    '--volume',
    '--mount',
    '-w',
    '--workdir',
    '--name',
    '--network',
    '-p',
    '--publish',
    '--entrypoint',
    '-u',
    '--user',
    '--platform',
    '--pull',
    '--label',
  ]);
  const switches = new Set(['--rm', '-i', '-t', '-it', '--init']);
  for (let i = 2; i < tokens.length; i++) {
    const token = tokens[i];
    if (argumentFlags.has(token)) {
      i++;
      continue;
    }
    if (
      switches.has(token) ||
      (token.includes('=') && argumentFlags.has(token.split('=')[0]))
    )
      continue;
    if (token.startsWith('-')) return undefined;
    return { reference: token, index: i };
  }
  return undefined;
}
export function balancedQuotes(command: string): boolean {
  let quote = '';
  for (let i = 0; i < command.length; i++) {
    const char = command[i];
    if (char === '\\' && quote !== "'") {
      i++;
      continue;
    }
    if (quote) {
      if (char === quote) quote = '';
    } else if (char === "'" || char === '"') quote = char;
  }
  return quote === '';
}

export type ShellResolution =
  | { supported: true; shell: 'bash' | 'sh'; source: string }
  | { supported: false; reason: string };

// Exact GitHub-hosted labels only. A label is never searched for OS substrings:
// self-hosted runners and larger runners carry arbitrary user-chosen labels.
const hostedPosix =
  /^(?:ubuntu-(?:latest|slim|\d{2}\.\d{2}(?:-arm)?)|macos-(?:latest|\d+)(?:-(?:intel|large|xlarge))?)$/;
const hostedWindows = /^windows-(?:latest|\d{4}|11-arm)$/;
const expression = (value: unknown) =>
  typeof value === 'string' && value.includes('${{');

function singleRunnerLabel(runsOn: unknown): string | undefined {
  if (typeof runsOn === 'string') return runsOn;
  if (Array.isArray(runsOn) && runsOn.length === 1) return singleRunnerLabel(runsOn[0]);
  if (runsOn && typeof runsOn === 'object' && !Array.isArray(runsOn)) {
    const { group, labels } = runsOn as { group?: unknown; labels?: unknown };
    return group === undefined ? singleRunnerLabel(labels) : undefined;
  }
  return undefined;
}

// Resolves which interpreter GitHub runs for a `run` step, following the documented
// precedence: step shell, job defaults, workflow defaults, then the runner default.
// Only bash and sh (both `-e`, so a failing command stops the step) are supported.
export function resolveShell(
  workflow: Workflow,
  job: Job,
  step: Step,
): ShellResolution {
  const explicit =
    step.shell ?? job.defaults?.run?.shell ?? workflow.defaults?.run?.shell;
  if (explicit !== undefined) {
    const source =
      step.shell !== undefined
        ? 'step shell'
        : job.defaults?.run?.shell !== undefined
          ? 'job defaults.run.shell'
          : 'workflow defaults.run.shell';
    return explicit === 'bash' || explicit === 'sh'
      ? { supported: true, shell: explicit, source }
      : {
          supported: false,
          reason: `${source} ${JSON.stringify(explicit)} is not bash or sh`,
        };
  }
  // Documented: run steps in a job container default to sh, on a Linux host.
  const container = job.container;
  if (container !== undefined && container !== null && !expression(container))
    return { supported: true, shell: 'sh', source: 'container job default' };
  const label = singleRunnerLabel(job['runs-on']);
  if (label !== undefined && hostedPosix.test(label))
    return { supported: true, shell: 'bash', source: `GitHub-hosted runner ${label}` };
  if (label !== undefined && hostedWindows.test(label))
    return {
      supported: false,
      reason: `GitHub-hosted runner ${label} defaults to pwsh`,
    };
  return {
    supported: false,
    reason:
      'the runner operating system and default shell cannot be determined statically; set shell: bash or shell: sh',
  };
}
