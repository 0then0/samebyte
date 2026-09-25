import type { OperationKind } from './model.js';
import { flag, runImage } from './shell.js';
export interface Consumption {
  kind: OperationKind;
  reference?: string;
  usedInputs?: string[];
  identityUnknown?: string;
}
export function actionConsumption(
  uses: string,
  inputs: Record<string, string>,
  env: Record<string, string> = {},
): Consumption[] {
  const action = uses.split('@')[0].toLowerCase();
  if (action === 'aquasecurity/trivy-action') {
    const archiveInput = inputs.input?.trim() || env.TRIVY_INPUT?.trim();
    return [
      {
        kind: 'scan',
        reference:
          (inputs['scan-type'] && inputs['scan-type'] !== 'image') || archiveInput
            ? undefined
            : inputs['image-ref'],
        usedInputs: ['scan-type', 'image-ref', 'input'],
      },
    ];
  }
  if (action === 'docker/scout-action') {
    const commands = (inputs.command ?? '').split(',').map((command) => command.trim());
    if (commands.some((command) => ['cves', 'quickview', 'compare'].includes(command)))
      return [
        { kind: 'scan', reference: inputs.image, usedInputs: ['command', 'image'] },
      ];
    return [];
  }
  if (action === 'anchore/scan-action')
    return [{ kind: 'scan', reference: inputs.image, usedInputs: ['image'] }];
  if (['actions/attest', 'actions/attest-build-provenance'].includes(action))
    return [
      {
        kind: 'attest',
        reference: inputs['subject-digest']
          ? `${inputs['subject-name'] ? `${inputs['subject-name']}@` : ''}${inputs['subject-digest']}`
          : undefined,
        usedInputs: ['subject-name', 'subject-digest'],
      },
    ];
  // Unknown deployment actions need explicit annotations instead of guesses.
  return [];
}
const kubectlGlobalValueFlags = new Set([
  '--as',
  '--as-group',
  '--as-uid',
  '--as-user-extra',
  '--cache-dir',
  '--certificate-authority',
  '--client-certificate',
  '--client-key',
  '--cluster',
  '--context',
  '--kubeconfig',
  '--kuberc',
  '--log-flush-frequency',
  '--namespace',
  '--password',
  '--profile',
  '--profile-output',
  '--proxy-url',
  '--request-timeout',
  '--server',
  '--tls-server-name',
  '--token',
  '--user',
  '--username',
  '--v',
  '--vmodule',
  '-n',
  '-s',
  '-v',
]);
const kubectlGlobalBooleanFlags = new Set([
  '--disable-compression',
  '--insecure-skip-tls-verify',
  '--match-server-version',
  '--warnings-as-errors',
]);
function stripKubectlGlobalFlags(tokens: string[]): {
  tokens: string[];
  unknown: boolean;
} {
  const command = ['kubectl'];
  for (let i = 1; i < tokens.length; ) {
    const token = tokens[i];
    const flagName = token.split('=', 1)[0];
    if (kubectlGlobalValueFlags.has(flagName)) {
      i += token.includes('=') ? 1 : 2;
      continue;
    }
    if (kubectlGlobalBooleanFlags.has(flagName)) {
      i++;
      continue;
    }
    if (token.startsWith('-')) {
      const setImage = tokens.some(
        (candidate, index) => candidate === 'set' && tokens[index + 1] === 'image',
      );
      return { tokens, unknown: setImage };
    }
    command.push(...tokens.slice(i));
    return { tokens: command, unknown: false };
  }
  return { tokens: command, unknown: false };
}
export function shellConsumption(
  tokens: string[],
  env: Record<string, string> = {},
): Consumption[] {
  if (tokens[0] === 'kubectl') {
    const normalized = stripKubectlGlobalFlags(tokens);
    if (normalized.unknown) return [{ kind: 'deploy' }];
    tokens = normalized.tokens;
  }
  const helmDryRun =
    tokens[0] === 'helm' &&
    tokens
      .slice(2)
      .some((token) => token === '--dry-run' || token.startsWith('--dry-run='));
  const kubectlDryRun =
    tokens[0] === 'kubectl' &&
    tokens.some((token, index) => {
      if (token === '--dry-run') {
        const mode = tokens[index + 1];
        return mode === undefined || mode === 'client' || mode === 'server';
      }
      if (token.startsWith('--dry-run=')) {
        const mode = token.slice('--dry-run='.length);
        return mode === 'client' || mode === 'server';
      }
      return false;
    });
  const kubectlLocal =
    tokens[0] === 'kubectl' &&
    tokens.some((token) => token === '--local' || token === '--local=true');
  if (helmDryRun || kubectlDryRun || kubectlLocal) return [];
  if (tokens[0] === 'docker' && tokens[1] === 'run')
    return [
      {
        kind: 'test',
        reference: runImage(tokens),
        identityUnknown: tokens.some(
          (token, index) =>
            token === '--platform' ||
            token.startsWith('--platform=') ||
            (index > 0 && tokens[index - 1] === '--platform'),
        )
          ? 'platform-specific child manifest is not tracked'
          : undefined,
      },
    ];
  if (tokens[0] === 'docker' && tokens[1] === 'compose' && tokens.includes('run'))
    return [{ kind: 'test' }];
  if (tokens[0] === 'trivy' && tokens[1] === 'image')
    return [
      {
        kind: 'scan',
        reference: env.TRIVY_INPUT?.trim()
          ? undefined
          : simpleOperand(
              tokens.slice(2),
              [
                '--severity',
                '--format',
                '-f',
                '--output',
                '-o',
                '--exit-code',
                '--scanners',
                '--ignorefile',
              ],
              ['--quiet', '-q', '--no-progress', '--ignore-unfixed'],
            ),
      },
    ];
  if (tokens[0] === 'grype')
    return [
      {
        kind: 'scan',
        reference: simpleOperand(
          tokens.slice(1),
          ['--fail-on', '--output', '-o', '--file', '--scope'],
          ['-q', '--quiet'],
        ),
      },
    ];
  if (
    tokens[0] === 'docker' &&
    tokens[1] === 'scout' &&
    ['cves', 'quickview'].includes(tokens[2])
  )
    return [
      {
        kind: 'scan',
        reference: simpleOperand(
          tokens.slice(3),
          ['--only-severity', '--format'],
          ['--exit-code'],
        ),
      },
    ];
  if (tokens[0] === 'gh' && tokens[1] === 'attestation' && tokens[2] === 'verify')
    return [
      {
        kind: 'attest',
        reference: tokens[3]?.startsWith('oci://') ? tokens[3].slice(6) : undefined,
      },
    ];
  if (tokens[0] === 'kubectl' && tokens[1] === 'set' && tokens[2] === 'image') {
    const references: Consumption[] = [];
    const valueFlags = [
      '-n',
      '--namespace',
      '--context',
      '--kubeconfig',
      '-l',
      '--selector',
      '-f',
      '--filename',
      '--field-manager',
    ];
    for (let i = 4; i < tokens.length; i++) {
      const token = tokens[i];
      if (valueFlags.includes(token)) {
        i++;
        continue;
      }
      if (
        token === '--dry-run' ||
        token === '--local' ||
        token.startsWith('--dry-run=') ||
        token.startsWith('--local=') ||
        valueFlags.some((flag) => token.startsWith(`${flag}=`)) ||
        ['--record', '--all'].includes(token)
      )
        continue;
      if (token.startsWith('-')) return [{ kind: 'deploy' }];
      if (token.includes('='))
        references.push({
          kind: 'deploy',
          reference: token.slice(token.indexOf('=') + 1),
        });
    }
    return references;
  }
  if (tokens[0] === 'helm' && ['upgrade', 'install'].includes(tokens[1])) {
    // Values do not prove what an arbitrary chart renders. Keep deployment
    // detection, but let chart-aware analysis or an explicit annotation resolve it.
    return [{ kind: 'deploy' }];
  }
  if (
    ['npm', 'pnpm', 'yarn'].includes(tokens[0]) &&
    (tokens[1] === 'test' || (tokens[1] === 'run' && tokens[2] === 'test'))
  )
    return [{ kind: 'source-test' }];
  return [];
}
function simpleOperand(
  tokens: string[],
  valueFlags: string[],
  switches: string[],
): string | undefined {
  const operands: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    if (valueFlags.includes(tokens[i])) {
      i++;
      continue;
    }
    if (
      switches.includes(tokens[i]) ||
      (tokens[i].includes('=') && valueFlags.includes(tokens[i].split('=')[0]))
    )
      continue;
    if (tokens[i].startsWith('-')) return undefined;
    operands.push(tokens[i]);
  }
  return operands.length === 1 ? operands[0] : undefined;
}
export function shellBuild(tokens: string[]): { tag?: string } | undefined {
  if (
    tokens[0] === 'docker' &&
    (tokens[1] === 'build' || (tokens[1] === 'buildx' && tokens[2] === 'build'))
  )
    return { tag: flag(tokens, '-t', '--tag') };
}
