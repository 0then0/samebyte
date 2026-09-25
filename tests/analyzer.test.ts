import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { analyzeWorkflow, validateConfig } from '../src/analyzer.js';
import { identity, resolveValue } from '../src/expressions.js';
import { sarifReport, textReport } from '../src/output.js';
import { parseWorkflow } from '../src/parser.js';

const A = `sha256:${'a'.repeat(64)}`;
const B = `sha256:${'b'.repeat(64)}`;
const image = (digest: string) => `ghcr.io/acme/api@${digest}`;
const analyze = (source: string) =>
  analyzeWorkflow(parseWorkflow(source, resolve('fixture.yml')));
const simple = (...commands: string[]) =>
  analyze(
    `jobs:\n  release:\n    steps:\n${commands.map((command) => `      - run: ${JSON.stringify(command)}`).join('\n')}`,
  );
const fixture = async (name: string) =>
  analyze(await readFile(`tests/fixtures/${name}.yml`, 'utf8'));
test('build once through job outputs, env and GITHUB_OUTPUT is proven', async () => {
  const report = await fixture('correct');
  assert.deepEqual(report.findings, []);
  assert.equal(report.deployments[0].state, 'proven');
  assert.equal(report.artifacts.length, 1);
  assert.equal(report.artifacts[0].consumers.length, 4);
  assert.match(textReport(report), /Artifact lineage verified/);
});
test('source tests followed by production build emit SB001', async () => {
  assert.equal((await fixture('rebuild')).deployments[0].state, 'mismatch');
  assert.deepEqual(
    (await fixture('rebuild')).findings.map((f) => f.ruleId),
    ['SB001'],
  );
});
test('different concrete digests identify test, scan and attestation mismatches', () => {
  const report = simple(
    `docker run --rm ${image(A)} test`,
    `trivy image ${image(A)}`,
    `gh attestation verify oci://${image(A)}`,
    `kubectl set image deployment/api api=${image(B)}`,
  );
  assert.deepEqual(
    report.findings.map((f) => f.ruleId),
    ['SB002', 'SB003', 'SB004'],
  );
});
test('different repositories are not compared as mismatches', () => {
  assert.equal(
    simple(
      `docker run postgres@${A}`,
      `kubectl set image deployment/api api=${image(B)}`,
    ).findings.length,
    0,
  );
});
test('tag and source revision are mutable identities', () => {
  for (const tag of ['latest', '${{ github.sha }}'])
    assert.equal(
      simple(
        `docker run ${image(A)}`,
        `kubectl set image deployment/api api=ghcr.io/acme/api:${tag}`,
      ).findings[0].ruleId,
      'SB005',
    );
});
test('shell transformations lose identity without high-confidence failures', async () => {
  const report = await fixture('unknown');
  assert.equal(report.findings[0].ruleId, 'SB006');
  assert.equal(report.findings[0].confidence, 'medium');
});
test('arbitrary scripts are not inferred from names', () => {
  const report = simple('./deploy.sh');
  assert.equal(report.deployments.length, 0);
  assert.match(textReport(report), /not verified/);
});
test('test after deploy cannot prove a check', () => {
  assert.equal(
    simple(`kubectl set image deployment/api api=${image(A)}`, `docker run ${image(A)}`)
      .deployments[0].checks.test,
    'unknown',
  );
});
test('conditional, matrix and ignored failures do not prove tests', () => {
  for (const guard of [
    "if: github.ref == 'refs/heads/main'",
    'continue-on-error: true',
  ]) {
    const report = analyze(
      `jobs:\n  release:\n    steps:\n      - run: docker run ${image(A)}\n        ${guard}\n      - run: kubectl set image deployment/api api=${image(A)}`,
    );
    assert.equal(report.deployments[0].checks.test, 'unknown');
  }
  const report = analyze(
    `jobs:\n  release:\n    strategy:\n      matrix:\n        node: [20, 22]\n    steps:\n      - run: docker run ${image(A)}\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
});
test('parallel sibling jobs do not establish verification order', () => {
  const report = analyze(
    `jobs:\n  test:\n    steps:\n      - run: docker run ${image(A)}\n  deploy:\n    steps:\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
});
test('shell conditionals and ignored exit statuses cannot prove tests', () => {
  for (const command of [
    `docker run ${image(A)} || true`,
    `if false; then docker run ${image(A)}; fi`,
    `if false\nthen\ndocker run ${image(A)}\nfi`,
  ])
    assert.equal(
      simple(command, `kubectl set image deployment/api api=${image(A)}`).deployments[0]
        .checks.test,
      'unknown',
    );
});
test('unknown shell variables and detached docker runs remain unknown', () => {
  for (const command of ['docker run $MISSING', `docker run -d ${image(A)}`])
    assert.equal(
      simple(command, `kubectl set image deployment/api api=${image(A)}`).deployments[0]
        .checks.test,
      'unknown',
    );
});
test('Helm digest values are consumed', () => {
  assert.equal(
    simple(
      `docker run ${image(A)}`,
      `helm upgrade api ./chart --set image.repository=ghcr.io/acme/api,image.digest=${A}`,
    ).deployments[0].checks.test,
    'proven',
  );
});
test('known scanners parse image operands', () => {
  for (const scan of [
    `trivy image --severity HIGH --exit-code 1 ${image(A)}`,
    `grype ${image(A)} --fail-on high`,
    `docker scout cves --exit-code ${image(A)}`,
  ])
    assert.equal(
      simple(scan, `kubectl set image deployment/api api=${image(A)}`).deployments[0]
        .checks.scan,
      'proven',
    );
});
test('invalid workflow structures and dependencies fail analysis', () => {
  for (const source of [
    'jobs: []',
    'jobs: {a: {needs: missing, steps: []}}',
    'jobs: {a: {needs: b, steps: []}, b: {needs: a, steps: []}}',
    'jobs: {a: {steps: [], steps: []}}',
  ])
    assert.throws(() => analyze(source));
});
test('GitHub expression AST handles bracket notation and case-insensitive contexts', () => {
  const scope = new Map([
    [
      'needs.build.outputs.digest',
      { text: A, unknown: false, trace: ['build digest'] },
    ],
  ]);
  assert.equal(resolveValue("${{ NEEDS['build'].outputs.digest }}", scope).text, A);
  assert.equal(
    resolveValue("${{ format('{0}', needs.build.outputs.digest) }}", scope).unknown,
    true,
  );
});
test('digests require full SHA256 and source sha is not an OCI digest', () => {
  assert.equal(
    identity({ text: 'sha256:abc', unknown: false, trace: [] }).kind,
    'unknown',
  );
  assert.equal(identity(resolveValue('${{ github.sha }}', new Map())).kind, 'mutable');
});
test('explicit annotation resolves custom deployment', () => {
  const workflow = parseWorkflow(
    `jobs:\n  release:\n    steps:\n      - run: docker run ${image(A)}\n      - id: ship\n        run: ./ship.sh`,
    'fixture.yml',
  );
  const report = analyzeWorkflow(
    workflow,
    validateConfig({
      annotations: [
        {
          workflow: 'fixture.yml',
          job: 'release',
          step: 'ship',
          operation: 'deploy',
          image: image(A),
        },
      ],
    }),
  );
  assert.equal(report.deployments[0].checks.test, 'proven');
});
test('SARIF includes finding locations and evidence', () => {
  const sarif = sarifReport(
    simple('kubectl set image deployment/api api=ghcr.io/acme/api:latest'),
  ) as { runs: { results: { locations: unknown[]; properties: unknown }[] }[] };
  assert.equal(sarif.runs[0].results[0].locations.length, 1);
  assert.ok(sarif.runs[0].results[0].properties);
});
test('single quotes and escaped variables do not consume the env image', () => {
  for (const command of ["docker run '$IMAGE'", 'docker run \\$IMAGE']) {
    const report = analyze(
      `env:\n  IMAGE: ${image(A)}\njobs:\n  release:\n    steps:\n      - run: ${JSON.stringify(command)}\n      - run: kubectl set image deployment/api api=${image(A)}`,
    );
    assert.equal(report.deployments[0].checks.test, 'unknown');
  }
});
test('heredocs, sourced files and custom shells cannot establish tests', () => {
  for (const command of [
    `cat <<'EOF'\ndocker run ${image(A)}\nEOF`,
    `. ./vars.sh\ndocker run ${image(A)}`,
    `source ./vars.sh\ndocker run ${image(A)}`,
    `alias docker=echo\ndocker run ${image(A)}`,
  ])
    assert.equal(
      simple(command, `kubectl set image deployment/api api=${image(A)}`).deployments[0]
        .checks.test,
      'unknown',
    );
  assert.equal(
    analyze(
      `jobs:\n  release:\n    steps:\n      - run: docker run ${image(A)}\n        shell: python\n      - run: kubectl set image deployment/api api=${image(A)}`,
    ).deployments[0].checks.test,
    'unknown',
  );
});
test('shell variable names retain case sensitivity', () => {
  const report = analyze(
    `env:\n  IMAGE: ${image(A)}\n  image: ${image(B)}\njobs:\n  release:\n    steps:\n      - run: docker run $IMAGE\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.equal(report.deployments[0].checks.test, 'proven');
});
test('commands within one straight-line step have execution order', () => {
  assert.equal(
    simple(`docker run ${image(A)}\nkubectl set image deployment/api api=${image(A)}`)
      .deployments[0].checks.test,
    'proven',
  );
});
test('intermediate always job cannot establish predecessor checks', () => {
  const report = analyze(
    `jobs:\n  test:\n    steps:\n      - run: docker run ${image(A)}\n  bridge:\n    needs: test\n    if: always()\n    steps:\n      - run: echo bridge\n  deploy:\n    needs: bridge\n    steps:\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
});
test('GITHUB_ENV changes invalidate later environment reads', () => {
  const report = analyze(
    `env:\n  IMAGE: ${image(A)}\njobs:\n  release:\n    steps:\n      - run: echo "IMAGE=${image(B)}" >> "$GITHUB_ENV"\n      - run: docker run $IMAGE\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
});
test('independent symbolic builds do not prove different bytes', () => {
  const report = analyze(
    `jobs:\n  release:\n    steps:\n      - id: first\n        uses: docker/build-push-action@v6\n      - run: docker run ghcr.io/acme/api@\${{ steps.first.outputs.digest }}\n      - id: second\n        uses: docker/build-push-action@v6\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ steps.second.outputs.digest }}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.equal(report.findings.length, 0);
});
test('docker build and buildx producers are recorded', () => {
  for (const command of [
    'docker build -t ghcr.io/acme/api:release .',
    'docker buildx build --tag=ghcr.io/acme/api:release --push .',
  ]) {
    const report = simple(
      'npm test',
      command,
      'kubectl set image deployment/api api=ghcr.io/acme/api:release',
    );
    assert.equal(report.operations.filter((op) => op.kind === 'build').length, 1);
    assert.deepEqual(report.findings.map((f) => f.ruleId).sort(), ['SB001', 'SB005']);
  }
});
test('multiline quoted text and shell builtins cannot establish tests', () => {
  for (const command of [
    `echo "\ndocker run ${image(A)}\n"`,
    `unset IMAGE\ndocker run $IMAGE`,
    `read IMAGE\ndocker run $IMAGE`,
  ]) {
    const report = analyze(
      `env:\n  IMAGE: ${image(A)}\njobs:\n  release:\n    steps:\n      - run: ${JSON.stringify(command)}\n      - run: kubectl set image deployment/api api=${image(A)}`,
    );
    assert.equal(report.deployments[0].checks.test, 'unknown');
  }
});
test('unsupported output writes invalidate previously recognized outputs', () => {
  const command = `echo "image=${image(A)}" >> "$GITHUB_OUTPUT"\nprintf "image=${image(B)}\\n" >> "$GITHUB_OUTPUT"`;
  const report = analyze(
    `jobs:\n  release:\n    steps:\n      - run: docker run ${image(A)}\n      - id: forward\n        run: ${JSON.stringify(command)}\n      - run: kubectl set image deployment/api api=\${{ steps.forward.outputs.image }}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.equal(report.findings[0].ruleId, 'SB006');
});
test('mismatch and mutable deployment fixtures have expected findings', async () => {
  assert.deepEqual(
    (await fixture('mismatch')).findings.map((f) => f.ruleId),
    ['SB002', 'SB003', 'SB004'],
  );
  assert.deepEqual(
    (await fixture('mutable')).findings.map((f) => f.ruleId),
    ['SB005'],
  );
});
test('producer tag is not displayed as immutable artifact identity', async () => {
  const report = await fixture('correct');
  assert.notEqual(report.artifacts[0].identity.reference, 'ghcr.io/acme/api:release');
  assert.equal(report.operations[0].producedReference, 'ghcr.io/acme/api:release');
});
test('dry-run deployments and kubectl selector values are not production images', () => {
  assert.equal(
    simple('kubectl set image deployment/api api=api:latest --dry-run=client')
      .deployments.length,
    0,
  );
  assert.equal(
    simple('helm upgrade api ./chart --set image=api:latest --dry-run').deployments
      .length,
    0,
  );
  const report = simple(
    `kubectl set image deployment/api api=${image(A)} --selector app=api`,
  );
  assert.equal(report.deployments.length, 1);
  assert.equal(report.findings.length, 0);
});
