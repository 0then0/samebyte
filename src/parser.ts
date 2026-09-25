import { readdir, readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { LineCounter, parseDocument } from 'yaml';
import type { Job, Step, Workflow } from './model.js';

const mapping = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);
export async function discover(input: string): Promise<string[]> {
  const path = resolve(input);
  const info = await stat(path);
  if (info.isFile()) return [path];
  let directory = path;
  try {
    if ((await stat(join(path, '.github/workflows'))).isDirectory())
      directory = join(path, '.github/workflows');
  } catch {
    /* Input may already be a workflow directory. */
  }
  return (await readdir(directory, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && /\.ya?ml$/i.test(entry.name))
    .map((entry) => join(directory, entry.name))
    .sort();
}
export function parseWorkflow(source: string, file: string): Workflow {
  const lines = new LineCounter();
  const doc = parseDocument(source, { lineCounter: lines, uniqueKeys: true });
  if (doc.errors.length) throw new Error(doc.errors.map((e) => e.message).join('\n'));
  const raw = doc.toJS({ maxAliasCount: 100 });
  if (!mapping(raw) || !mapping(raw.jobs) || !Object.keys(raw.jobs).length)
    throw new Error('Workflow must contain a non-empty jobs mapping.');
  const validateMap = (value: unknown, label: string) => {
    if (value !== undefined && !mapping(value))
      throw new Error(`Invalid ${label}: expected mapping`);
  };
  validateMap(raw.env, 'workflow env');
  const jobs: Record<string, Job> = {};
  for (const [id, value] of Object.entries(raw.jobs)) {
    if (!mapping(value)) throw new Error(`Invalid job ${id}`);
    validateMap(value.env, `${id} env`);
    validateMap(value.outputs, `${id} outputs`);
    const needs =
      value.needs === undefined
        ? []
        : typeof value.needs === 'string'
          ? [value.needs]
          : value.needs;
    if (!Array.isArray(needs) || needs.some((item) => typeof item !== 'string'))
      throw new Error(`Invalid needs in ${id}`);
    if (value.steps !== undefined && !Array.isArray(value.steps))
      throw new Error(`Invalid steps in ${id}`);
    if (!value.uses && !Array.isArray(value.steps))
      throw new Error(`Job ${id} needs steps or uses`);
    const ids = new Set<string>();
    const steps = ((value.steps ?? []) as unknown[]).map((step, index) => {
      if (
        !mapping(step) ||
        (typeof step.run !== 'string' && typeof step.uses !== 'string')
      )
        throw new Error(`Invalid step ${id}[${index}]`);
      validateMap(step.env, `${id} step env`);
      validateMap(step.with, `${id} step inputs`);
      if (step.run !== undefined && step.uses !== undefined)
        throw new Error(`Step in ${id} cannot contain both run and uses`);
      if (step.id !== undefined) {
        if (typeof step.id !== 'string' || ids.has(step.id))
          throw new Error(`Invalid or duplicate step id in ${id}`);
        ids.add(step.id);
      }
      const node = doc.getIn(['jobs', id, 'steps', index], true) as {
        range?: number[];
      };
      return {
        ...step,
        line: lines.linePos(node?.range?.[0] ?? 0).line,
      } as Step;
    });
    jobs[id] = { ...value, steps, needs } as Job;
  }
  const visited = new Set<string>();
  const visiting = new Set<string>();
  const ordered: Record<string, Job> = {};
  const visit = (id: string) => {
    if (!jobs[id]) throw new Error(`Unknown job dependency: ${id}`);
    if (visiting.has(id)) throw new Error(`Cyclic job dependency: ${id}`);
    if (visited.has(id)) return;
    visiting.add(id);
    for (const need of jobs[id].needs) visit(need);
    visiting.delete(id);
    visited.add(id);
    ordered[id] = jobs[id];
  };
  for (const id of Object.keys(jobs)) visit(id);
  return {
    file,
    jobs: ordered,
    defaults: raw.defaults as Workflow['defaults'],
    env: mapping(raw.env) ? raw.env : undefined,
  };
}
export async function readWorkflow(file: string): Promise<Workflow> {
  return parseWorkflow(await readFile(file, 'utf8'), file);
}
