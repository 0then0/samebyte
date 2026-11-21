import { createHash } from 'node:crypto';
import { parseDocument } from 'yaml';
import { identity } from './expressions.js';
import type {
  ExecutionPoint,
  Identity,
  Operation,
  PlatformCoverage,
  PlatformManifest,
  Workflow,
} from './model.js';
import {
  checkIsRequired,
  operationIsUnreachable,
  precedes,
  reusableGateReason,
} from './rules.js';

const indexType = 'application/vnd.oci.image.index.v1+json';
const manifestType = 'application/vnd.oci.image.manifest.v1+json';
const attestationType = 'application/vnd.docker.attestation.manifest.v1+json';
const sha256 = /^sha256:[a-f0-9]{64}$/;
const ociDigest = /^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+$/;
const mediaType = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i;
const component = /^[a-z0-9][a-z0-9._-]*$/;
const architectureAliases = new Map([
  ['x86_64', 'amd64'],
  ['x86-64', 'amd64'],
  ['i386', '386'],
  ['aarch64', 'arm64'],
  ['armhf', 'arm'],
  ['armel', 'arm'],
]);
const namePart = '[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*';
const hostPart = '[a-z0-9]+(?:-+[a-z0-9]+)*';
const host = `(?:${hostPart}(?:\\.${hostPart})*|\\[[0-9a-fA-F:]+\\])`;
const repositoryName = new RegExp(
  `^(?:${host}(?::[0-9]+)?/)?${namePart}(?:/${namePart})*$`,
);
const mapping = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const matches = (value: unknown, pattern: RegExp): value is string =>
  typeof value === 'string' && pattern.test(value);
const stringMap = (value: unknown): boolean =>
  mapping(value) && Object.values(value).every((entry) => typeof entry === 'string');
const strings = (value: unknown): boolean =>
  Array.isArray(value) && value.every((entry) => typeof entry === 'string');

function namedDigest(reference: string) {
  const [repository, digest, extra] = reference.split('@');
  if (repositoryName.test(repository) && sha256.test(digest) && extra === undefined)
    return { repository, digest };
}

export interface PublicationBinding {
  job: string;
  step: string;
  reference: string;
  repository: string;
  digest: string;
}
export interface LocalIndex {
  binding: PublicationBinding;
  bindingFile: string;
  file: string;
  bytes: Uint8Array;
}
export interface PublicationPoint extends ExecutionPoint {
  repository: string;
  digest?: string;
  mergeSources?: string[];
}
export interface PlatformTest {
  operation: Operation;
  identity: Identity;
  selector?: string | null;
}

export function parsePublication(raw: unknown): PublicationBinding {
  if (
    mapping(raw) &&
    typeof raw.job === 'string' &&
    raw.job.trim() &&
    typeof raw.step === 'string' &&
    raw.step.trim() &&
    typeof raw.reference === 'string'
  ) {
    const reference = namedDigest(raw.reference);
    if (reference)
      return { job: raw.job, step: raw.step, reference: raw.reference, ...reference };
  }
  throw new Error(
    'Publication binding requires job and step IDs and an exact repository@sha256:<64 lowercase hex digits> reference.',
  );
}

function hasDuplicateJsonKeys(source: string): boolean {
  // JSON.parse keeps the last duplicate property. Check keys after validating
  // the native JSON syntax so that all consumers see an unambiguous binding.
  return parseDocument(source, { schema: 'json', uniqueKeys: true }).errors.some(
    (error) => error.code === 'DUPLICATE_KEY',
  );
}

export function parsePublicationFile(source: string): PublicationBinding {
  const raw: unknown = JSON.parse(source);
  if (hasDuplicateJsonKeys(source))
    throw new Error('Publication binding contains duplicate JSON object keys.');
  return parsePublication(raw);
}

export function publicationRepository(tag: string): string | undefined {
  const end = tag.lastIndexOf(':');
  if (end <= tag.lastIndexOf('/')) return repositoryName.test(tag) ? tag : undefined;
  const repository = tag.slice(0, end);
  if (repositoryName.test(repository) && /^[\w][\w.-]{0,127}$/.test(tag.slice(end + 1)))
    return repository;
}

// A single source is supported as an index promotion. A concrete source
// constrains the digest since Buildx copies an index byte for byte in this case.
export function imagetoolsPublication(
  tokens: string[],
): Omit<PublicationPoint, keyof ExecutionPoint> | undefined {
  if (tokens.slice(0, 4).join(' ') !== 'docker buildx imagetools create') return;
  let repository: string | undefined;
  const sources: Identity[] = [];
  for (let i = 4; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === '-t' || token === '--tag' || token.startsWith('--tag=')) {
      if (repository) return;
      repository = publicationRepository(
        token.startsWith('--tag=') ? token.slice('--tag='.length) : (tokens[++i] ?? ''),
      );
      if (!repository) return;
    } else {
      if (token === '--prefer-index=false' || token === '--prefer-index=true') continue;
      const source = identity({ text: token, trace: [], unknown: false });
      if (
        source.kind !== 'immutable' ||
        !source.repository ||
        !repositoryName.test(source.repository)
      )
        return;
      sources.push(source);
    }
  }
  if (
    !repository ||
    !sources.length ||
    new Set(sources.map((source) => source.key)).size !== sources.length
  )
    return;
  const concreteDigests = sources.flatMap(({ concrete, key }) =>
    concrete && key ? [key] : [],
  );
  return {
    repository,
    digest: sources.length === 1 ? concreteDigests[0] : undefined,
    mergeSources:
      sources.length > 1 && sources.length === concreteDigests.length
        ? concreteDigests
        : undefined,
  };
}

function validData(raw: Record<string, unknown>, digest: string): boolean {
  if (raw.data === undefined) return true;
  if (typeof raw.data !== 'string') return false;
  const bytes = Buffer.from(raw.data, 'base64');
  if (bytes.length !== raw.size || bytes.toString('base64') !== raw.data) return false;
  const algorithm = digest.split(':', 1)[0];
  return (
    (algorithm !== 'sha256' && algorithm !== 'sha512') ||
    `${algorithm}:${createHash(algorithm).update(bytes).digest('hex')}` === digest
  );
}

function validDescriptor(raw: Record<string, unknown>): boolean {
  return (
    matches(raw.mediaType, mediaType) &&
    matches(raw.digest, ociDigest) &&
    (!raw.digest.startsWith('sha256:') || sha256.test(raw.digest)) &&
    (!raw.digest.startsWith('sha512:') || /^sha512:[a-f0-9]{128}$/.test(raw.digest)) &&
    typeof raw.size === 'number' &&
    Number.isSafeInteger(raw.size) &&
    raw.size >= 0 &&
    (raw.annotations === undefined || stringMap(raw.annotations)) &&
    (raw.artifactType === undefined || matches(raw.artifactType, mediaType)) &&
    (raw.urls === undefined || strings(raw.urls)) &&
    validData(raw, raw.digest)
  );
}

function platformIdentifier(raw: unknown): string | undefined {
  if (
    mapping(raw) &&
    matches(raw.os, component) &&
    matches(raw.architecture, component) &&
    (raw.variant === undefined || matches(raw.variant, component)) &&
    (raw['os.version'] === undefined || typeof raw['os.version'] === 'string') &&
    (raw['os.features'] === undefined || strings(raw['os.features'])) &&
    (raw.features === undefined || strings(raw.features))
  ) {
    return [raw.os, raw.architecture, raw.variant].filter(Boolean).join('/');
  }
}

function parseManifest(raw: unknown, position: number): PlatformManifest {
  if (!mapping(raw))
    return {
      position,
      status: 'invalid',
      reason: 'Expected an OCI descriptor object.',
    };
  const platform = platformIdentifier(raw.platform);
  const digest = typeof raw.digest === 'string' ? raw.digest : undefined;
  const descriptor = {
    position,
    platform,
    digest,
    mediaType: typeof raw.mediaType === 'string' ? raw.mediaType : undefined,
  };
  if (!validDescriptor(raw) || (raw.platform !== undefined && platform === undefined))
    return {
      ...descriptor,
      status: 'invalid',
      reason: 'Invalid OCI descriptor fields or platform.',
    };
  if (raw.mediaType !== manifestType)
    return {
      ...descriptor,
      status: 'unsupported',
      reason: 'Only flat OCI image manifests are supported.',
    };
  const attestation =
    raw.artifactType === attestationType ||
    (mapping(raw.annotations) &&
      raw.annotations['vnd.docker.reference.type'] === 'attestation-manifest');
  if (attestation && (!platform || platform === 'unknown/unknown'))
    return {
      ...descriptor,
      status: 'service',
      reason: 'Buildx attestation descriptor.',
    };
  if (attestation || raw.artifactType !== undefined)
    return {
      ...descriptor,
      status: 'unsupported',
      reason: 'Artifact descriptor does not establish a runnable image.',
    };
  if (!platform || platform.split('/').slice(0, 2).includes('unknown'))
    return {
      ...descriptor,
      status: 'unsupported',
      reason: 'No identifiable runtime platform.',
    };
  if (!digest || !sha256.test(digest))
    return {
      ...descriptor,
      status: 'unsupported',
      reason: 'Only SHA-256 image digests are supported.',
    };
  return { ...descriptor, status: 'unknown', reason: 'Insufficient test evidence.' };
}

function readIndex(input: LocalIndex): Pick<PlatformCoverage, 'index' | 'manifests'> {
  const digest = input.binding.digest;
  const actualDigest = `sha256:${createHash('sha256').update(input.bytes).digest('hex')}`;
  const index = { file: input.file, digest, actualDigest };
  if (actualDigest !== digest)
    return {
      index: {
        ...index,
        status: 'mismatch',
        reason: 'Index bytes do not match the publication digest.',
      },
      manifests: [],
    };
  const invalid = (reason: string, manifests: PlatformManifest[] = []) => ({
    index: { ...index, status: 'invalid' as const, reason },
    manifests,
  });
  let raw: unknown;
  try {
    const source = new TextDecoder('utf-8', { fatal: true }).decode(input.bytes);
    raw = JSON.parse(source);
    if (hasDuplicateJsonKeys(source))
      return invalid('Index contains duplicate JSON object keys.');
  } catch {
    return invalid('Index is not valid UTF-8 JSON.');
  }
  if (
    !mapping(raw) ||
    raw.schemaVersion !== 2 ||
    (raw.mediaType !== undefined && raw.mediaType !== indexType) ||
    raw.artifactType !== undefined ||
    !Array.isArray(raw.manifests) ||
    (raw.annotations !== undefined && !stringMap(raw.annotations)) ||
    (raw.subject !== undefined &&
      (!mapping(raw.subject) || !validDescriptor(raw.subject)))
  )
    return invalid(
      'Expected an OCI image index with schemaVersion 2 and a manifests array.',
    );
  const manifests = raw.manifests.map(parseManifest);
  if (manifests.some((manifest) => manifest.status === 'invalid'))
    return invalid('Index contains malformed OCI descriptors.', manifests);
  return { index: { ...index, status: 'verified' }, manifests };
}

function platformKey(platform: string): string {
  const [os, arch, rawVariant, extra] = platform.split('/');
  if (
    !component.test(os) ||
    !arch ||
    !component.test(arch) ||
    (rawVariant !== undefined && !component.test(rawVariant)) ||
    extra !== undefined
  )
    return platform;
  const architecture = architectureAliases.get(arch) ?? arch;
  let variant = rawVariant ?? '';
  if (architecture === 'amd64' && variant === 'v1') variant = '';
  if (arch === 'i386') variant = '';
  if (architecture === 'arm64') {
    if (['8', 'v8', 'v8.0'].includes(variant)) variant = '';
    if (['9', '9.0', 'v9.0'].includes(variant)) variant = 'v9';
  }
  if (architecture === 'arm') {
    if (arch === 'armel') variant = 'v6';
    else if (arch === 'armhf' || variant === 'v7' || variant === '7') variant = '';
    else if (['5', '6', '8'].includes(variant)) variant = `v${variant}`;
  }
  return [os === 'macos' ? 'darwin' : os, architecture, variant]
    .filter(Boolean)
    .join('/');
}
const compatible = (platform: string, selector?: string | null) =>
  selector === undefined ||
  (typeof selector === 'string' && platformKey(selector) === platformKey(platform));

function duplicates(keys: (string | undefined)[]): Set<string> {
  const seen = new Set<string>();
  const repeated = new Set<string>();
  for (const key of keys) {
    if (key === undefined) continue;
    if (seen.has(key)) repeated.add(key);
    seen.add(key);
  }
  return repeated;
}

function testEvidence({
  operation,
  identity,
  selector,
}: PlatformTest): PlatformManifest['test'] {
  return {
    operation: operation.id,
    location: operation.location,
    reference: identity.reference,
    selector,
    ...(operation.call ? { call: operation.call } : {}),
  };
}

export function analyzePlatformCoverage(
  input: LocalIndex,
  point: PublicationPoint | undefined,
  tests: PlatformTest[],
  workflow: Workflow,
  diagnostics: { file: string; message: string }[],
): PlatformCoverage {
  const { binding } = input;
  const { index, manifests } = readIndex(input);
  const mergeSources = point?.mergeSources;
  const imageDigests = new Set(
    manifests.filter((row) => row.mediaType === manifestType).map((row) => row.digest),
  );
  // Standalone manifest sources contribute exactly their own descriptors.
  // A source with unknown contents may itself be an index that Buildx expands.
  const mergeConflict =
    index.status === 'verified' &&
    mergeSources &&
    mergeSources.every((digest) => imageDigests.has(digest)) &&
    (mergeSources.length !== manifests.length ||
      mergeSources.some((digest, i) => digest !== manifests[i].digest));
  const publicationProblem = !point
    ? 'The binding must select a supported publication step in a non-matrix job.'
    : point.repository !== binding.repository
      ? 'The binding repository differs from the publication destination.'
      : point.digest !== undefined && point.digest !== binding.digest
        ? 'The binding digest differs from the digest pinned by the publication step.'
        : mergeConflict
          ? 'Index descriptors differ from the standalone manifest sources of the publication step.'
          : operationIsUnreachable(point, workflow)
            ? 'The selected publication step cannot run.'
            : undefined;
  if (index.reason) diagnostics.push({ file: input.file, message: index.reason });
  if (publicationProblem)
    diagnostics.push({ file: input.bindingFile, message: publicationProblem });
  const result: PlatformCoverage = {
    publication: {
      job: binding.job,
      step: binding.step,
      reference: binding.reference,
      evidence: 'input',
      status: publicationProblem ? 'unresolved' : 'bound',
      reason:
        publicationProblem ??
        'Publication binding supplied as input evidence. Coverage describes the static workflow.',
      location: point?.location,
    },
    index,
    manifests,
  };
  if (!point || diagnostics.length) {
    for (const manifest of manifests)
      if (manifest.status === 'unknown')
        manifest.reason =
          index.reason ?? publicationProblem ?? 'Workflow analysis is incomplete.';
    return result;
  }

  const reachability = new Map<string, boolean>();
  const candidates = tests
    .filter((test) => !operationIsUnreachable(test.operation, workflow, reachability))
    .map((test) => ({
      ...test,
      pinned: test.identity.concrete ? namedDigest(test.identity.reference) : undefined,
      required:
        precedes(test.operation, point, workflow) &&
        checkIsRequired(test.operation, point, workflow),
    }));
  const runtime = manifests.filter((manifest) => manifest.status !== 'service');
  const ambiguousPlatforms = duplicates(
    runtime.map((row) => row.platform && platformKey(row.platform)),
  );
  const ambiguousDigests = duplicates(manifests.map((row) => row.digest));
  for (const manifest of runtime) {
    const { digest, platform } = manifest;
    if (manifest.status !== 'unknown' || !digest || !platform) continue;
    if (ambiguousPlatforms.has(platformKey(platform)) || ambiguousDigests.has(digest)) {
      manifest.reason = 'Platform or child digest occurs in multiple descriptors.';
      continue;
    }
    const exact = candidates.filter(
      (candidate) =>
        candidate.pinned?.repository === binding.repository &&
        candidate.pinned.digest === digest &&
        digest !== binding.digest,
    );
    const proven = exact.find(
      (test) => test.required && compatible(platform, test.selector),
    );
    if (proven) {
      manifest.status = 'proven';
      manifest.reason = 'A required test pins this repository and child digest.';
      manifest.test = testEvidence(proven);
      continue;
    }
    // A different digest can be attributed to a platform only by an explicit
    // selector that identifies it unambiguously.
    const aimedAtPlatform = candidates.filter(
      (test) =>
        typeof test.selector === 'string' && compatible(platform, test.selector),
    );
    const different = aimedAtPlatform.find(
      (test) =>
        test.required &&
        test.pinned?.repository === binding.repository &&
        test.pinned.digest !== digest &&
        test.pinned.digest !== binding.digest,
    );
    if (different) {
      manifest.status = 'mismatch';
      manifest.reason =
        'A required test selects this platform but pins a different digest.';
      manifest.test = testEvidence(different);
      continue;
    }
    const candidate =
      exact[0] ??
      aimedAtPlatform.find((test) => test.identity.repository === binding.repository) ??
      candidates.find(
        (test) =>
          test.pinned?.repository === binding.repository &&
          test.pinned.digest === binding.digest &&
          compatible(platform, test.selector),
      );
    if (candidate) {
      manifest.test = testEvidence(candidate);
      manifest.reason = !compatible(platform, candidate.selector)
        ? 'The test platform selector is unresolved or conflicts with this child manifest.'
        : candidate.pinned?.digest !== digest
          ? 'The test does not pin the expected child digest.'
          : (reusableGateReason(candidate.operation, point, workflow) ??
            'The publication does not require this test to complete successfully.');
    } else {
      manifest.reason = 'No recognized test pins this repository and child digest.';
    }
  }
  return result;
}
