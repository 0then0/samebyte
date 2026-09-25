import type { OperationKind } from './model.js';
import { flag, runImage } from './shell.js';
export interface Consumption {
  kind: OperationKind;
  reference?: string;
}
export function actionConsumption(
  uses: string,
  inputs: Record<string, string>,
): Consumption[] {
  const action = uses.split('@')[0].toLowerCase();
  if (action === 'aquasecurity/trivy-action')
    return [
      {
        kind: 'scan',
        reference:
          inputs['scan-type'] && inputs['scan-type'] !== 'image'
            ? undefined
            : inputs['image-ref'],
      },
    ];
  if (action === 'docker/scout-action')
    return [{ kind: 'scan', reference: inputs.image }];
  if (action === 'anchore/scan-action')
    return [{ kind: 'scan', reference: inputs.image }];
  if (['actions/attest', 'actions/attest-build-provenance'].includes(action))
    return [
      {
        kind: 'attest',
        reference: inputs['subject-digest']
          ? `${inputs['subject-name'] ? `${inputs['subject-name']}@` : ''}${inputs['subject-digest']}`
          : undefined,
      },
    ];
  // Unknown deployment actions need explicit annotations instead of guesses.
  return [];
}
export function shellConsumption(tokens: string[]): Consumption[] {
  if (
    ['kubectl', 'helm'].includes(tokens[0]) &&
    tokens.some(
      (token) =>
        token === '--dry-run' ||
        token.startsWith('--dry-run=') ||
        token === '--local' ||
        token === '--local=true',
    )
  )
    return [];
  if (tokens[0] === 'docker' && tokens[1] === 'run')
    return [{ kind: 'test', reference: runImage(tokens) }];
  if (tokens[0] === 'docker' && tokens[1] === 'compose' && tokens.includes('run'))
    return [{ kind: 'test' }];
  if (tokens[0] === 'trivy' && tokens[1] === 'image')
    return [
      {
        kind: 'scan',
        reference: simpleOperand(
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
    const values: Record<string, string> = {};
    for (let i = 2; i < tokens.length; i++) {
      if (
        ['--set', '--set-string'].includes(tokens[i]) ||
        /^--set(?:-string)?=/.test(tokens[i])
      ) {
        const input = tokens[i].includes('=')
          ? tokens[i].slice(tokens[i].indexOf('=') + 1)
          : tokens[++i];
        for (const pair of (input ?? '').split(',')) {
          const at = pair.indexOf('=');
          if (at > 0) values[pair.slice(0, at)] = pair.slice(at + 1);
        }
      }
    }
    const repo = values['image.repository'];
    return [
      {
        kind: 'deploy',
        reference: repo
          ? `${repo}${values['image.digest'] ? `@${values['image.digest']}` : `:${values['image.tag'] || 'latest'}`}`
          : values.image,
      },
    ];
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
