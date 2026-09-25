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
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n${commands.map((command) => `      - run: ${JSON.stringify(command)}`).join('\n')}`,
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
      `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run ${image(A)}\n        ${guard}\n      - run: kubectl set image deployment/api api=${image(A)}`,
    );
    assert.equal(report.deployments[0].checks.test, 'unknown');
  }
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        node: [20, 22]\n    steps:\n      - run: docker run ${image(A)}\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
});
test('explicit success conditions preserve a required test-to-deploy chain', () => {
  const report = analyze(
    `jobs:\n  build:\n    runs-on: ubuntu-latest\n    outputs:\n      digest: \${{ steps.image.outputs.digest }}\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n  test:\n    runs-on: ubuntu-latest\n    needs: build\n    if: success()\n    steps:\n      - run: docker run ghcr.io/acme/api@\${{ needs.build.outputs.digest }}\n  deploy:\n    runs-on: ubuntu-latest\n    needs: [build, test]\n    steps:\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ needs.build.outputs.digest }}\n        if: success()`,
  );
  assert.equal(report.deployments[0].checks.test, 'proven');
  assert.deepEqual(report.findings, []);
});
test('conditional job does not hide continue-on-error on its test step', () => {
  const digest = image(A);
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    if: github.ref == 'refs/heads/main'\n    steps:\n      - run: docker run ${digest}\n        continue-on-error: true\n      - run: trivy image ${digest}\n      - run: gh attestation verify oci://${digest}\n      - run: kubectl set image deployment/api api=${digest}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.notEqual(report.deployments[0].state, 'proven');
});
test('background operations require a wait before later same-job consumers', () => {
  const digest = 'ghcr.io/acme/api@${{ steps.image.outputs.digest }}';
  const command = `docker run ${digest}`;
  const deploy = `kubectl set image deployment/api api=${digest}`;
  const build = '      - id: image\n        uses: docker/build-push-action@v6\n';
  const pending = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n${build}      - id: test\n        run: ${JSON.stringify(command)}\n        background: true\n      - run: ${JSON.stringify(deploy)}`,
  );
  assert.equal(pending.deployments[0].checks.test, 'unknown');
  assert.equal(
    pending.findings.some((finding) => finding.ruleId === 'SB001'),
    false,
  );

  for (const waiter of ['wait: test', 'wait-all:']) {
    const waited = analyze(
      `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n${build}      - id: test\n        run: ${JSON.stringify(command)}\n        background: true\n      - ${waiter}\n      - run: ${JSON.stringify(deploy)}`,
    );
    assert.equal(waited.deployments[0].checks.test, 'proven', waiter);
  }
  const anonymousBackground = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n${build}      - run: ${JSON.stringify(command)}\n        background: true\n      - wait-all:\n      - run: ${JSON.stringify(deploy)}`,
  );
  assert.equal(anonymousBackground.deployments[0].checks.test, 'proven');
});
test('ignored background failures do not prove that checks passed', () => {
  const digest = 'ghcr.io/acme/api@${{ steps.image.outputs.digest }}';
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n      - id: test\n        run: docker run ${digest}\n        background: true\n      - wait: test\n        continue-on-error: true\n      - run: trivy image ${digest}\n      - run: gh attestation verify oci://${digest}\n      - run: kubectl set image deployment/api api=${digest}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.equal(report.deployments[0].state, 'unknown');
  assert.equal(
    report.findings.some((finding) => finding.severity === 'high'),
    false,
  );
});
test('ignored or cancelled background tests stay unknown in conditional jobs', () => {
  const digest = 'ghcr.io/acme/api@${{ steps.image.outputs.digest }}';
  for (const control of [
    'wait: test\n        continue-on-error: true',
    'cancel: test',
  ]) {
    const report = analyze(
      `jobs:\n  release:\n    runs-on: ubuntu-latest\n    if: github.ref == 'refs/heads/main'\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n      - id: test\n        run: docker run ${digest}\n        background: true\n      - ${control}\n      - run: trivy image ${digest}\n      - run: gh attestation verify oci://${digest}\n      - run: kubectl set image deployment/api api=${digest}`,
    );
    assert.equal(report.deployments[0].checks.test, 'unknown', control);
    assert.notEqual(report.deployments[0].state, 'proven', control);
    assert.equal(
      report.findings.some((finding) => finding.severity === 'high'),
      false,
    );
  }
});
test('an explicit success condition on a background wait preserves the result', () => {
  const digest = 'ghcr.io/acme/api@${{ steps.image.outputs.digest }}';
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n      - id: test\n        run: docker run ${digest}\n        background: true\n      - wait: test\n        if: success()\n      - run: kubectl set image deployment/api api=${digest}`,
  );
  assert.equal(report.deployments[0].checks.test, 'proven');
});
test('background operations finish before dependent jobs start', () => {
  const digest = 'ghcr.io/acme/api@${{ needs.test.outputs.digest }}';
  const report = analyze(
    `jobs:\n  test:\n    runs-on: ubuntu-latest\n    outputs:\n      digest: \${{ steps.image.outputs.digest }}\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n      - id: check\n        run: docker run ghcr.io/acme/api@\${{ steps.image.outputs.digest }}\n        background: true\n  deploy:\n    runs-on: ubuntu-latest\n    needs: test\n    steps:\n      - run: kubectl set image deployment/api api=${digest}`,
  );
  assert.equal(report.deployments[0].checks.test, 'proven');
});
test('background step outputs become available only after waiting', () => {
  const beforeWait = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n      - id: image\n        uses: docker/build-push-action@v6\n        background: true\n      - run: docker run ghcr.io/acme/api@\${{ steps.image.outputs.digest }}\n      - wait: image\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ steps.image.outputs.digest }}`,
  );
  assert.equal(beforeWait.deployments[0].checks.test, 'mismatch');
  assert.ok(beforeWait.findings.some((finding) => finding.ruleId === 'SB001'));

  const afterWait = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n        background: true\n      - wait: image\n      - run: docker run ghcr.io/acme/api@\${{ steps.image.outputs.digest }}\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ steps.image.outputs.digest }}`,
  );
  assert.equal(afterWait.deployments[0].checks.test, 'proven');
});
test('cancelled background tests and parallel blocks never prove lineage', () => {
  const command = `docker run ${image(A)}`;
  const deploy = `kubectl set image deployment/api api=${image(A)}`;
  const cancelled = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - id: test\n        run: ${JSON.stringify(command)}\n        background: true\n      - cancel: test\n      - run: ${JSON.stringify(deploy)}`,
  );
  assert.equal(cancelled.deployments[0].checks.test, 'unknown');

  const parallel = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - parallel:\n          - run: ${JSON.stringify(command)}\n      - run: ${JSON.stringify(deploy)}`,
  );
  assert.equal(parallel.deployments[0].checks.test, 'unknown');
  assert.match(parallel.diagnostics[0]?.message ?? '', /parallel block/);
});
test('multi-platform OCI index digest does not prove a tested platform manifest', () => {
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n        with:\n          platforms: linux/amd64,linux/arm64\n      - run: docker run ghcr.io/acme/api@\${{ steps.image.outputs.digest }}\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ steps.image.outputs.digest }}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.equal(report.deployments[0].state, 'unknown');
  assert.equal(
    report.findings.some((finding) => finding.severity === 'high'),
    false,
  );

  const platformSelected = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run --platform linux/amd64 ${image(A)}\n      - run: trivy image ${image(A)}\n      - run: gh attestation verify oci://${image(A)}\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.equal(platformSelected.deployments[0].checks.test, 'unknown');
  assert.notEqual(platformSelected.deployments[0].state, 'proven');
});
test('an external concrete digest does not prove which OCI index child was tested', () => {
  const digest = image(A);
  const report = analyze(
    `jobs:\n  test:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: docker run ${digest}\n      - run: trivy image ${digest}\n      - run: gh attestation verify oci://${digest}\n  deploy:\n    runs-on: ubuntu-24.04-arm\n    needs: test\n    steps:\n      - run: kubectl set image deployment/api api=${digest}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.notEqual(report.deployments[0].state, 'proven');
  assert.equal(
    report.findings.some((finding) => finding.severity === 'high'),
    false,
  );
  assert.match(
    report.operations.find((operation) => operation.kind === 'test')
      ?.runtimeIdentityUnknown ?? '',
    /OCI index/,
  );
});
test('parallel sibling jobs do not establish verification order', () => {
  const report = analyze(
    `jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run ${image(A)}\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: kubectl set image deployment/api api=${image(A)}`,
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
test('Helm values do not prove what the chart deploys', () => {
  const report = simple(
    `docker run ${image(A)}`,
    `helm upgrade api ./chart --set image.repository=ghcr.io/acme/api,image.digest=${A}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.equal(report.findings.at(-1)?.ruleId, 'SB006');
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
  assert.throws(() =>
    analyze('jobs: {a: {runs-on: ubuntu-latest, steps: [{wait: missing}]}}'),
  );
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
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n      - run: docker run ghcr.io/acme/api@\${{ steps.image.outputs.digest }}\n      - id: ship\n        run: ./ship.sh`,
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
          image: 'ghcr.io/acme/api@${{ steps.image.outputs.digest }}',
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
      `env:\n  IMAGE: ${image(A)}\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${JSON.stringify(command)}\n      - run: kubectl set image deployment/api api=${image(A)}`,
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
      `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run ${image(A)}\n        shell: python\n      - run: kubectl set image deployment/api api=${image(A)}`,
    ).deployments[0].checks.test,
    'unknown',
  );
});
test('shell variable names retain case sensitivity', () => {
  const report = analyze(
    `env:\n  IMAGE: ${image(A)}\n  image: ${image(B)}\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run $IMAGE\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.equal(
    report.operations.find((operation) => operation.kind === 'test')?.identity
      .reference,
    image(A),
  );
});
test('commands within one straight-line step have execution order', () => {
  const digest = 'ghcr.io/acme/api@${{ steps.image.outputs.digest }}';
  assert.equal(
    analyze(
      `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n      - run: ${JSON.stringify(`docker run ${digest}\nkubectl set image deployment/api api=${digest}`)}`,
    ).deployments[0].checks.test,
    'proven',
  );
});
test('intermediate always job cannot establish predecessor checks', () => {
  const report = analyze(
    `jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run ${image(A)}\n  bridge:\n    runs-on: ubuntu-latest\n    needs: test\n    if: always()\n    steps:\n      - run: echo bridge\n  deploy:\n    runs-on: ubuntu-latest\n    needs: bridge\n    steps:\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
});
test('GITHUB_ENV changes invalidate later environment reads', () => {
  const report = analyze(
    `env:\n  IMAGE: ${image(A)}\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "IMAGE=${image(B)}" >> "$GITHUB_ENV"\n      - run: docker run $IMAGE\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
});
test('independent symbolic builds do not prove different bytes', () => {
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - id: first\n        uses: docker/build-push-action@v6\n      - run: docker run ghcr.io/acme/api@\${{ steps.first.outputs.digest }}\n      - id: second\n        uses: docker/build-push-action@v6\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ steps.second.outputs.digest }}`,
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
      `env:\n  IMAGE: ${image(A)}\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${JSON.stringify(command)}\n      - run: kubectl set image deployment/api api=${image(A)}`,
    );
    assert.equal(report.deployments[0].checks.test, 'unknown');
  }
});
test('unsupported output writes invalidate previously recognized outputs', () => {
  const command = `echo "image=${image(A)}" >> "$GITHUB_OUTPUT"\nprintf "image=${image(B)}\\n" >> "$GITHUB_OUTPUT"`;
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run ${image(A)}\n      - id: forward\n        run: ${JSON.stringify(command)}\n      - run: kubectl set image deployment/api api=\${{ steps.forward.outputs.image }}`,
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
test('Docker Scout only counts supported scan commands', () => {
  const imageRef = `ghcr.io/acme/api@${A}`;
  const deploy = `kubectl set image deployment/api api=${imageRef}`;
  const source = `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker/scout-action@v1\n        with:\n          command: environment\n          image: ${imageRef}\n      - run: ${JSON.stringify(deploy)}`;
  const environmentAction = analyze(source);
  assert.equal(
    environmentAction.operations.some((op) => op.kind === 'scan'),
    false,
  );
  assert.equal(environmentAction.deployments[0].checks.scan, 'unknown');

  const cves = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker/scout-action@v1\n        with:\n          command: cves\n          image: ${imageRef}\n          registry-password: DUMMY_SECRET\n      - run: ${JSON.stringify(deploy)}`,
  );
  assert.equal(cves.deployments[0].checks.scan, 'proven');
  assert.equal(JSON.stringify(cves).includes('DUMMY_SECRET'), false);
});
test('SB001 ignores unrelated tests and recognizes a test of the linked digest', () => {
  const unrelated = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    outputs:\n      digest: \${{ steps.build.outputs.digest }}\n    steps:\n      - run: npm test\n      - run: docker run postgres@${A}\n      - id: build\n        uses: docker/build-push-action@v6\n        with:\n          push: true\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ steps.build.outputs.digest }}`,
  );
  assert.deepEqual(
    unrelated.findings.map((finding) => finding.ruleId),
    ['SB001'],
  );
  assert.equal(unrelated.deployments[0].checks.test, 'mismatch');

  const tested = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    outputs:\n      digest: \${{ steps.build.outputs.digest }}\n    steps:\n      - run: npm test\n      - id: build\n        uses: docker/build-push-action@v6\n        with:\n          push: true\n      - run: docker run ghcr.io/acme/api@\${{ steps.build.outputs.digest }}\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ steps.build.outputs.digest }}`,
  );
  assert.equal(
    tested.findings.some((finding) => finding.ruleId === 'SB001'),
    false,
  );
  assert.equal(tested.deployments[0].checks.test, 'proven');
});
test('matching mutable tags only produce a medium confidence SB001 candidate', () => {
  const report = simple(
    'npm test',
    'docker build -t ghcr.io/acme/api:release .',
    'kubectl set image deployment/api api=ghcr.io/acme/api:release',
  );
  const finding = report.findings.find((item) => item.ruleId === 'SB001');
  assert.equal(finding?.severity, 'medium');
  assert.equal(finding?.state, 'unknown');
  assert.equal(finding?.confidence, 'medium');
  assert.ok(report.findings.some((item) => item.ruleId === 'SB005'));
});
test('shell command arguments are excluded from finding evidence', () => {
  const report = simple(
    `docker run --env TOKEN=DUMMY_SHELL_SECRET ${image(A)}`,
    `kubectl set image deployment/api api=${image(B)}`,
  );
  assert.equal(JSON.stringify(report).includes('DUMMY_SHELL_SECRET'), false);
  assert.equal(textReport(report, true).includes('DUMMY_SHELL_SECRET'), false);
  assert.equal(
    JSON.stringify(sarifReport(report)).includes('DUMMY_SHELL_SECRET'),
    false,
  );
});
test('invalid nested inputs and job output values are rejected', () => {
  for (const source of [
    'jobs: {release: {runs-on: ubuntu-latest, outputs: {digest: [sha256, abc]}, steps: [{run: echo ok}]}}',
    'jobs: {release: {runs-on: ubuntu-latest, steps: [{uses: docker/scout-action@v1, with: {image: {repository: ghcr.io/acme/api}}}]}}',
  ])
    assert.throws(() => analyze(source));
});

test('normal jobs accept valid runner forms and require a runner', () => {
  assert.throws(
    () => parseWorkflow('jobs: {release: {steps: [{run: echo ok}]}}', 'fixture.yml'),
    /runs-on is required/,
  );
  assert.doesNotThrow(() =>
    parseWorkflow(
      'jobs: {release: {runs-on: {group: ubuntu-runners, labels: [linux, x64]}, steps: [{run: echo ok}]}}',
      'fixture.yml',
    ),
  );
  assert.throws(
    () =>
      parseWorkflow(
        'jobs: {release: {runs-on: {pool: ubuntu}, steps: [{run: echo ok}]}}',
        'fixture.yml',
      ),
    /runs-on mapping requires group or labels/,
  );
  assert.throws(
    () => parseWorkflow('jobs: {release: {uses: null}}', 'fixture.yml'),
    /uses must be a non-empty string/,
  );
  assert.doesNotThrow(() =>
    parseWorkflow(
      'jobs: {release: {uses: acme/repo/.github/workflows/reuse.yml@main}}',
      'fixture.yml',
    ),
  );
});

test('a conditional required test job proves the deployed digest only when its dependency gates deploy', () => {
  const conditionalTest = [
    'jobs:',
    '  source:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - run: npm test',
    '  build:',
    '    needs: source',
    '    runs-on: ubuntu-latest',
    '    outputs:',
    '      digest: ${{ steps.image.outputs.digest }}',
    '    steps:',
    '      - id: image',
    '        uses: docker/build-push-action@v6',
    '  test:',
    '    needs: build',
    '    runs-on: ubuntu-latest',
    "    if: github.ref == 'refs/heads/main'",
    '    steps:',
    '      - run: docker run ghcr.io/acme/api@${{ needs.build.outputs.digest }}',
    '  deploy:',
    '    needs: [build, test]',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - run: kubectl set image deployment/api api=ghcr.io/acme/api@${{ needs.build.outputs.digest }}',
  ].join('\n');
  const gated = analyze(conditionalTest);
  assert.equal(gated.deployments[0].checks.test, 'proven');
  assert.equal(
    gated.findings.some((item) => item.ruleId === 'SB001'),
    false,
  );

  const bypass = analyze(
    conditionalTest.replace(
      '    needs: [build, test]\n    runs-on: ubuntu-latest\n    steps:',
      '    needs: [build, test]\n    runs-on: ubuntu-latest\n    if: always()\n    steps:',
    ),
  );
  assert.notEqual(bypass.deployments[0].checks.test, 'proven');
  assert.equal(
    bypass.findings.some((item) => item.ruleId === 'SB001'),
    true,
  );

  const stepAlways = analyze(
    conditionalTest.replace(
      '      - run: kubectl set image deployment/api api=ghcr.io/acme/api@${{ needs.build.outputs.digest }}',
      '      - run: kubectl set image deployment/api api=ghcr.io/acme/api@${{ needs.build.outputs.digest }}\n        if: always()',
    ),
  );
  assert.notEqual(stepAlways.deployments[0].checks.test, 'proven');
  assert.equal(
    stepAlways.findings.some((item) => item.ruleId === 'SB001'),
    true,
  );
});
