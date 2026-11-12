import { open, realpath } from 'node:fs/promises';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import type { CoverageNotice, Workflow } from './model.js';
import { parseWorkflow } from './parser.js';

// A workflow file is read whole before parsing; larger files are not loaded.
export const maxWorkflowBytes = 1024 * 1024;

export type Callee =
  | { status: 'ok'; workflow: Workflow }
  | { status: 'boundary'; reason: CoverageNotice['reason']; message: string };
export interface CallResolution {
  // Directory that contains `.github/workflows` with the calling workflow; absent
  // when the workflow is stored elsewhere and local calls cannot be located.
  root?: string;
  // Keyed by the `uses` value of the calling job.
  callees: Map<string, Callee>;
}
export const opaqueCallMessage =
  'Reusable workflow contents and outputs are not analyzed. Operations and execution gates may be hidden behind this call.';

// GitHub only runs workflows stored directly in `<root>/.github/workflows`, and a
// local `uses` path is relative to that root. A file elsewhere has no root.
export function repositoryRoot(file: string): string | undefined {
  const directory = dirname(resolve(file));
  if (basename(directory) !== 'workflows' || basename(dirname(directory)) !== '.github')
    return undefined;
  return dirname(dirname(directory));
}
export const isLocalCall = (uses: string) =>
  uses.startsWith('./') || uses.startsWith('$/');

const boundary = (reason: CoverageNotice['reason'], message: string): Callee => ({
  status: 'boundary',
  reason,
  message,
});

// Classifies a call that is not loaded from disk; undefined means a loadable local path.
export function unloadedCall(uses: string): Callee | undefined {
  if (uses.includes('${{'))
    return boundary(
      'reusable-workflow-call',
      'The workflow path is dynamic. GitHub does not allow expressions in uses, and no file is loaded for it.',
    );
  if (!isLocalCall(uses)) return boundary('reusable-workflow-call', opaqueCallMessage);
  const path = uses.slice(2);
  if (path.includes('@'))
    return boundary(
      'reusable-workflow-path',
      'A local reusable workflow runs from the caller commit and cannot name a ref. The call is not analyzed.',
    );
  if (
    !/^\.github\/workflows\/[^/\\]+\.[yY][aA]?[mM][lL]$/.test(path) ||
    path.includes('..')
  )
    return boundary(
      'reusable-workflow-path',
      'A local reusable workflow must be a YAML file directly in .github/workflows of the analyzed repository. The call is not analyzed.',
    );
}

async function load(root: string, uses: string): Promise<Callee> {
  const unloaded = unloadedCall(uses);
  if (unloaded) return unloaded;
  const file = join(root, uses.slice(2));
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    // The lexical check above cannot see symbolic links.
    const [realRoot, realFile] = await Promise.all([realpath(root), realpath(file)]);
    if (!realFile.startsWith(realRoot + sep))
      return boundary(
        'reusable-workflow-path',
        'The reusable workflow path resolves outside the analyzed repository root. The file is not read.',
      );
    handle = await open(realFile, 'r');
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT'
      ? boundary(
          'reusable-workflow-not-found',
          `Reusable workflow file ${relative(root, file)} does not exist under the analyzed repository root. Its operations and outputs are unknown.`,
        )
      : boundary(
          'reusable-workflow-invalid',
          `Reusable workflow file cannot be read: ${(error as Error).message}`,
        );
  }
  let source: string;
  try {
    const info = await handle.stat();
    if (!info.isFile())
      return boundary(
        'reusable-workflow-path',
        'The reusable workflow path is not a regular file. The call is not analyzed.',
      );
    if (info.size > maxWorkflowBytes)
      return boundary(
        'reusable-workflow-invalid',
        `Reusable workflow file exceeds ${maxWorkflowBytes} bytes and is not read.`,
      );
    source = await handle.readFile('utf8');
  } finally {
    await handle.close();
  }
  let workflow: Workflow;
  try {
    workflow = parseWorkflow(source, file);
  } catch (error) {
    return boundary(
      'reusable-workflow-invalid',
      `Reusable workflow file is not a valid workflow: ${(error as Error).message.replace(/\s+/g, ' ').trim()}`,
    );
  }
  if (!workflow.call)
    return boundary(
      'reusable-workflow-contract',
      'The called workflow does not declare on.workflow_call, so it cannot be called. Its contents are not joined to this caller.',
    );
  if (workflow.call.error)
    return boundary(
      'reusable-workflow-contract',
      `The called workflow has an invalid workflow_call contract: ${workflow.call.error}.`,
    );
  return { status: 'ok', workflow };
}

// Loads the direct local callees of one workflow. Callees of callees are never
// loaded, so the number of files read is bounded by the jobs of the caller.
export async function resolveCalls(
  workflow: Workflow,
  cache = new Map<string, Promise<Callee>>(),
): Promise<CallResolution> {
  const root = repositoryRoot(workflow.file);
  const callees = new Map<string, Callee>();
  if (!root) return { callees };
  for (const job of Object.values(workflow.jobs)) {
    if (!job.uses || callees.has(job.uses)) continue;
    const key = `${root}\0${job.uses}`;
    let callee = cache.get(key);
    if (!callee) {
      callee = load(root, job.uses);
      cache.set(key, callee);
    }
    callees.set(job.uses, await callee);
  }
  return { root, callees };
}
