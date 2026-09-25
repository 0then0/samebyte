import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { analyzeWorkflow, validateConfig } from '../src/analyzer.js';
import { hasStatusCheck, identity, resolveValue } from '../src/expressions.js';
import { graphReport, sarifReport, textReport } from '../src/output.js';
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
test('conditional matching consumers keep test, scan and attestation lineage unknown', () => {
  const kinds = [
    {
      kind: 'test',
      old: `docker run ${image(A)} test`,
      matching: `docker run ${image(B)} test`,
      deployment: `kubectl set image deployment/api api=${image(B)}`,
      finding: 'SB002',
    },
    {
      kind: 'scan',
      old: `trivy image ${image(A)}`,
      matching: `trivy image ${image(B)}`,
      deployment: `kubectl set image deployment/api api=${image(B)}`,
      finding: 'SB003',
    },
    {
      kind: 'attest',
      old: `gh attestation verify oci://${image(A)}`,
      matching: `gh attestation verify oci://${image(B)}`,
      deployment: `kubectl set image deployment/api api=${image(B)}`,
      finding: 'SB004',
    },
  ] as const;
  for (const scenario of kinds) {
    const report = analyze(
      `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${JSON.stringify(scenario.old)}\n      - if: github.ref == 'refs/heads/main'\n        run: ${JSON.stringify(scenario.matching)}\n      - if: github.ref == 'refs/heads/main'\n        run: ${JSON.stringify(scenario.deployment)}`,
    );
    assert.equal(report.deployments[0].checks[scenario.kind], 'unknown', scenario.kind);
    assert.equal(
      report.findings.some((finding) => finding.ruleId === scenario.finding),
      false,
      scenario.kind,
    );
    assert.match(
      report.deployments[0].checkReasons?.[scenario.kind]?.reason ?? '',
      /condition is not proven to run/,
      scenario.kind,
    );
  }
});
test('a conditional OCI test of the deployed digest does not produce SB001', () => {
  const digest = 'ghcr.io/acme/api@${{ steps.image.outputs.digest }}';
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n      - id: image\n        uses: docker/build-push-action@v6\n      - if: github.ref == 'refs/heads/main'\n        run: docker run ${digest}\n      - if: github.ref == 'refs/heads/main'\n        run: kubectl set image deployment/api api=${digest}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.equal(
    report.findings.some((finding) => finding.ruleId === 'SB001'),
    false,
  );
});
test('a matching OCI test with compound success conditions does not produce SB001', () => {
  const digest = 'ghcr.io/acme/api@${{ needs.build.outputs.digest }}';
  const condition = "${{ success() && github.ref == 'refs/heads/main' }}";
  const report = analyze(
    `jobs:\n  build:\n    runs-on: ubuntu-latest\n    outputs:\n      digest: \${{ steps.image.outputs.digest }}\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n  test:\n    needs: build\n    runs-on: ubuntu-latest\n    if: ${JSON.stringify(condition)}\n    steps:\n      - run: docker run ${digest} test\n  deploy:\n    needs: [build, test]\n    runs-on: ubuntu-latest\n    if: ${JSON.stringify(condition)}\n    steps:\n      - run: kubectl set image deployment/api api=${digest}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.equal(
    report.findings.some((finding) => finding.ruleId === 'SB001'),
    false,
  );
});
test('compound success conditions at step level preserve a possible matching OCI test', () => {
  const digest = 'ghcr.io/acme/api@${{ steps.image.outputs.digest }}';
  for (const condition of [
    "${{ success() && github.ref == 'refs/heads/main' }}",
    "${{ !cancelled() && github.ref == 'refs/heads/main' }}",
    'always()',
  ]) {
    const report = analyze(
      `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n      - run: docker run ${digest} test\n        if: ${JSON.stringify(condition)}\n      - run: kubectl set image deployment/api api=${digest}\n        if: ${JSON.stringify(condition)}`,
    );
    assert.equal(report.deployments[0].checks.test, 'unknown', condition);
    assert.equal(
      report.findings.some((finding) => finding.ruleId === 'SB001'),
      false,
      condition,
    );
  }
});
test('a matching consumer with a different dynamic condition keeps lineage unknown', () => {
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: trivy image ${image(A)}\n      - if: github.ref == 'refs/heads/main'\n        run: trivy image ${image(B)}\n      - if: github.ref == 'refs/heads/release'\n        run: kubectl set image deployment/api api=${image(B)}`,
  );
  assert.equal(report.deployments[0].checks.scan, 'unknown');
  assert.equal(
    report.findings.some((finding) => finding.ruleId === 'SB003'),
    false,
  );
});
test('a statically disabled matching consumer does not hide a real mismatch', () => {
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: trivy image ${image(A)}\n      - if: false\n        run: trivy image ${image(B)}\n      - run: kubectl set image deployment/api api=${image(B)}`,
  );
  assert.equal(report.deployments[0].checks.scan, 'mismatch');
  assert.equal(
    report.findings.some((finding) => finding.ruleId === 'SB003'),
    true,
  );
});
test('an unresolved preceding consumer keeps a digest mismatch unknown', () => {
  const cases = [
    {
      kind: 'test',
      known: `docker run ${image(A)}`,
      unknown: `docker run --cap-add NET_ADMIN ${image(B)} test`,
      rule: 'SB002',
    },
    {
      kind: 'scan',
      known: `trivy image ${image(A)}`,
      unknown: `trivy image --input ./image-b.tar ${image(B)}`,
      rule: 'SB003',
    },
    {
      kind: 'attest',
      known: `gh attestation verify oci://${image(A)}`,
      unknown: 'gh attestation verify',
      rule: 'SB004',
    },
  ] as const;
  const deploy = `kubectl set image deployment/api api=${image(B)}`;
  for (const scenario of cases) {
    const report = simple(scenario.known, scenario.unknown, deploy);
    assert.equal(report.deployments[0].checks[scenario.kind], 'unknown', scenario.kind);
    assert.match(
      report.deployments[0].checkReasons?.[scenario.kind]?.reason ?? '',
      /unresolved artifact identity/,
      scenario.kind,
    );
    assert.equal(
      report.findings.some((finding) => finding.ruleId === scenario.rule),
      false,
      scenario.kind,
    );
    assert.match(textReport(report, true), /consumer has unresolved artifact identity/);
  }
});
test('statically disabled consumers do not hide proven digest mismatches', () => {
  const cases = [
    {
      kind: 'test',
      known: `docker run ${image(A)}`,
      disabled: `docker run --cap-add NET_ADMIN ${image(B)} test`,
      rule: 'SB002',
    },
    {
      kind: 'scan',
      known: `trivy image ${image(A)}`,
      disabled: `trivy image --input ./image-b.tar ${image(B)}`,
      rule: 'SB003',
    },
    {
      kind: 'attest',
      known: `gh attestation verify oci://${image(A)}`,
      disabled: 'gh attestation verify',
      rule: 'SB004',
    },
  ] as const;
  const deploy = `kubectl set image deployment/api api=${image(B)}`;
  for (const scenario of cases) {
    const report = analyze(
      `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ${JSON.stringify(scenario.known)}\n      - if: false\n        run: ${JSON.stringify(scenario.disabled)}\n      - run: ${JSON.stringify(deploy)}`,
    );
    assert.equal(
      report.deployments[0].checks[scenario.kind],
      'mismatch',
      scenario.kind,
    );
    assert.equal(
      report.findings.some((finding) => finding.ruleId === scenario.rule),
      true,
      scenario.kind,
    );
  }
});
test('statically disabled deployments do not produce findings', () => {
  const deployment = 'kubectl set image deployment/api api=ghcr.io/acme/api:latest';
  const cases = [
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - if: false\n        run: ${JSON.stringify(deployment)}`,
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    if: false\n    steps:\n      - run: ${JSON.stringify(deployment)}`,
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - if: '\${{ false }}'\n        run: ${JSON.stringify(deployment)}`,
  ];
  for (const workflow of cases) {
    const report = analyze(workflow);
    assert.deepEqual(report.deployments, []);
    assert.deepEqual(report.findings, []);
    assert.deepEqual(report.operations, []);
    assert.deepEqual(report.artifacts, []);
    assert.doesNotMatch(graphReport(report), /deploy/);
  }
});
test('status functions inside string literals do not override skipped prerequisites', () => {
  for (const name of ['success', 'failure', 'cancelled', 'always']) {
    for (const condition of [
      `inputs.mode == '${name}()'`,
      `inputs.mode == 'it''s ${name}()'`,
      `\${{ inputs.mode == '${name}()' }}`,
    ]) {
      const report = analyze(
        `jobs:\n  disabled:\n    if: false\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker build -t api .\n  deploy:\n    needs: disabled\n    if: ${JSON.stringify(condition)}\n    runs-on: ubuntu-latest\n    steps:\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api:latest`,
      );
      assert.deepEqual(report.findings, [], condition);
      assert.deepEqual(report.deployments, [], condition);
      assert.deepEqual(report.operations, [], condition);
      assert.deepEqual(report.artifacts, [], condition);
    }
  }
});
test('status detection recognizes calls and conservatively handles unreadable conditions', () => {
  for (const name of ['success', 'failure', 'cancelled', 'always']) {
    assert.equal(hasStatusCheck(`\${{ ${name}() && inputs.enabled }}`), true);
    assert.equal(hasStatusCheck(`(${name.toUpperCase()} ())`), true);
    assert.equal(hasStatusCheck(`contains(inputs.mode, '${name}()')`), false);
  }
  assert.equal(hasStatusCheck("inputs.mode == 'unterminated"), true);
  assert.equal(hasStatusCheck(undefined), false);
});
test('graph removes disabled consumers without removing their shared active artifact', () => {
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - if: false\n        run: docker run ${image(A)}\n      - run: trivy image ${image(A)}\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.deepEqual(
    report.operations.map((operation) => operation.kind),
    ['scan', 'deploy'],
  );
  assert.equal(report.artifacts.length, 1);
  assert.equal(report.artifacts[0].consumers.length, 2);
  assert.doesNotMatch(graphReport(report), /-> test/);
  assert.equal(report.deployments[0].checks.test, 'unknown');
});
test('unknown conditions retain operations in the graph', () => {
  const report = analyze(
    `jobs:\n  release:\n    if: inputs.enabled\n    runs-on: ubuntu-latest\n    steps:\n      - run: kubectl set image deployment/api api=${image(A)}`,
  );
  assert.equal(report.operations.length, 1);
  assert.equal(report.artifacts.length, 1);
  assert.match(graphReport(report), /deploy/);
});
test('skipped prerequisite jobs make dependent deployments unreachable', () => {
  const direct = analyze(
    `jobs:\n  verify:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run ${image(A)}\n  disabled:\n    runs-on: ubuntu-latest\n    if: false\n    steps:\n      - run: echo disabled\n  deploy:\n    needs: [verify, disabled]\n    runs-on: ubuntu-latest\n    steps:\n      - run: kubectl set image deployment/api api=${image(B)}`,
  );
  assert.deepEqual(direct.deployments, []);
  assert.deepEqual(direct.findings, []);

  const transitive = analyze(
    `jobs:\n  disabled:\n    runs-on: ubuntu-latest\n    if: false\n    steps:\n      - run: echo disabled\n  middle:\n    needs: disabled\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo middle\n  deploy:\n    needs: middle\n    runs-on: ubuntu-latest\n    steps:\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api:latest`,
  );
  assert.deepEqual(transitive.deployments, []);
  assert.deepEqual(transitive.findings, []);
  assert.deepEqual(transitive.operations, []);
  assert.deepEqual(transitive.artifacts, []);
});
test('always-conditioned deployments remain analyzable after skipped needs', () => {
  const report = analyze(
    `jobs:\n  disabled:\n    runs-on: ubuntu-latest\n    if: false\n    steps:\n      - run: echo disabled\n  deploy:\n    needs: disabled\n    runs-on: ubuntu-latest\n    if: always()\n    steps:\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api:latest`,
  );
  assert.equal(report.deployments.length, 1);
  assert.equal(report.operations.length, 1);
  assert.match(graphReport(report), /deploy/);
  assert.deepEqual(
    report.findings.map((finding) => finding.ruleId),
    ['SB005'],
  );
});
test('an unresolved consumer after deployment cannot suppress a known mismatch', () => {
  const report = simple(
    `docker run ${image(A)}`,
    `kubectl set image deployment/api api=${image(B)}`,
    `docker run --cap-add NET_ADMIN ${image(B)} test`,
  );
  assert.equal(report.deployments[0].checks.test, 'mismatch');
  assert.equal(
    report.findings.some((finding) => finding.ruleId === 'SB002'),
    true,
  );
});
test('a matching tested digest is not reported as mismatched because another digest was also tested', () => {
  const report = simple(
    `docker run ${image(A)}`,
    `docker run ${image(B)}`,
    `kubectl set image deployment/api api=${image(B)}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.equal(
    report.findings.some((finding) => finding.ruleId === 'SB002'),
    false,
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
  const report = simple(
    `kubectl set image deployment/api api=${image(A)}`,
    `docker run ${image(A)}`,
  );
  assert.equal(report.deployments[0].checks.test, 'unknown');
  assert.doesNotMatch(textReport(report, true), /test identity unknown/);
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
test('ignored and cancelled background tests in conditional jobs stay unknown', () => {
  const digest = 'ghcr.io/acme/api@${{ needs.build.outputs.digest }}';
  const workflow = (control: string) =>
    `jobs:\n  build:\n    runs-on: ubuntu-latest\n    outputs:\n      digest: \${{ steps.image.outputs.digest }}\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n  verify:\n    needs: build\n    runs-on: ubuntu-latest\n    if: github.ref == 'refs/heads/main'\n    steps:\n      - id: test\n        run: docker run ${digest}\n        background: true\n      - ${control}\n  deploy:\n    needs: [build, verify]\n    runs-on: ubuntu-latest\n    steps:\n      - run: trivy image ${digest}\n      - run: gh attestation verify oci://${digest}\n      - run: kubectl set image deployment/api api=${digest}`;
  for (const control of [
    'wait: test\n        continue-on-error: true',
    'cancel: test',
  ]) {
    const report = analyze(workflow(control));
    assert.equal(report.deployments[0].checks.test, 'unknown', control);
    assert.notEqual(report.deployments[0].state, 'proven', control);
    assert.equal(
      report.findings.some((finding) => finding.severity === 'high'),
      false,
    );
  }
  assert.equal(analyze(workflow('wait: test')).deployments[0].checks.test, 'proven');
});
test('GitHub control steps reject unsupported conditions and argument shapes', () => {
  for (const control of [
    'wait: test\n        if: success()',
    'wait-all: true',
    'wait-all:\n        if: success()',
    'cancel: [test, other]',
    'cancel: test\n        if: success()',
  ]) {
    assert.throws(
      () =>
        parseWorkflow(
          `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - id: test\n        run: docker run ${image(A)}\n        background: true\n      - ${control}`,
          'invalid-control.yml',
        ),
      /Invalid (conditional control step|wait-all value|cancel target)/,
      control,
    );
  }
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
  assert.equal(beforeWait.deployments[0].checks.test, 'unknown');
  assert.equal(
    beforeWait.findings.some((finding) => finding.ruleId === 'SB001'),
    false,
  );

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
  assert.match(textReport(report, true), /selected platform manifest is not tracked/);
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
test('Trivy archive input does not count image-ref as the scanned artifact', () => {
  const digest = image(A);
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run ${digest}\n      - uses: aquasecurity/trivy-action@v0\n        with:\n          image-ref: ${digest}\n          input: ./unrelated-image.tar\n      - run: kubectl set image deployment/api api=${digest}`,
  );
  assert.equal(report.deployments[0].checks.scan, 'unknown');
  assert.equal(
    report.findings.some((finding) => finding.ruleId === 'SB003'),
    false,
  );
});
test('Trivy archive input resolved from an expression also remains unknown', () => {
  const digest = image(A);
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    env:\n      ARCHIVE: ./unrelated-image.tar\n    steps:\n      - uses: aquasecurity/trivy-action@v0\n        with:\n          image-ref: ${digest}\n          input: \${{ env.ARCHIVE }}\n      - run: kubectl set image deployment/api api=${digest}`,
  );
  assert.equal(report.deployments[0].checks.scan, 'unknown');
});
test('Trivy environment archive inputs never prove the deployed image was scanned', () => {
  const digest = image(A);
  const scopes = [
    {
      prefix: 'env:\n  TRIVY_INPUT: ./unrelated-image.tar\n',
      job: '',
      step: '',
    },
    {
      prefix: '',
      job: '    env:\n      TRIVY_INPUT: ./unrelated-image.tar\n',
      step: '',
    },
    {
      prefix: '',
      job: '',
      step: '        env:\n          TRIVY_INPUT: ./unrelated-image.tar\n',
    },
  ];
  for (const scope of scopes) {
    const action = analyze(
      `${scope.prefix}jobs:\n  release:\n    runs-on: ubuntu-latest\n${scope.job}    steps:\n      - run: docker run ${digest}\n      - uses: aquasecurity/trivy-action@v0\n${scope.step}        with:\n          image-ref: ${digest}\n      - run: kubectl set image deployment/api api=${digest}`,
    );
    assert.equal(action.deployments[0].checks.scan, 'unknown');
    assert.equal(action.deployments[0].state, 'unknown');

    const shell = analyze(
      `${scope.prefix}jobs:\n  release:\n    runs-on: ubuntu-latest\n${scope.job}    steps:\n      - run: docker run ${digest}\n      - run: trivy image ${digest}\n${scope.step}      - run: kubectl set image deployment/api api=${digest}`,
    );
    assert.equal(shell.deployments[0].checks.scan, 'unknown');
    assert.equal(shell.deployments[0].state, 'unknown');
  }
});
test('Trivy environment variable names preserve case', () => {
  const digest = image(A);
  for (const command of [
    `      - uses: aquasecurity/trivy-action@v0\n        env:\n          trivy_input: ./unrelated-image.tar\n        with:\n          image-ref: ${digest}\n`,
    `      - run: trivy image ${digest}\n        env:\n          trivy_input: ./unrelated-image.tar\n`,
  ]) {
    const report = analyze(
      `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run ${digest}\n${command}      - run: kubectl set image deployment/api api=${digest}`,
    );
    assert.equal(report.deployments[0].checks.scan, 'proven');
  }
});
test('new TRIVY_INPUT shell assignments cannot prove later scans', () => {
  const digest = image(A);
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          export TRIVY_INPUT=./unrelated-image.tar\n          trivy image ${digest}\n      - run: kubectl set image deployment/api api=${digest}`,
  );
  assert.equal(report.deployments[0].checks.scan, 'unknown');
  assert.notEqual(report.deployments[0].state, 'proven');
});
test('new TRIVY_INPUT written to GITHUB_ENV cannot prove later action scans', () => {
  const digest = image(A);
  const report = analyze(
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "TRIVY_INPUT=./unrelated-image.tar" >> "$GITHUB_ENV"\n      - uses: aquasecurity/trivy-action@v0\n        with:\n          image-ref: ${digest}\n      - run: kubectl set image deployment/api api=${digest}`,
  );
  assert.equal(report.deployments[0].checks.scan, 'unknown');
  assert.notEqual(report.deployments[0].state, 'proven');
});
test('unresolved OCI tests remain unknown instead of producing SB001', () => {
  const digest = 'ghcr.io/acme/api@${{ steps.image.outputs.digest }}';
  const workflow = (testCommand: string, deploymentCondition = '') =>
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n      - id: image\n        uses: docker/build-push-action@v6\n        with:\n          push: true\n      - run: ${JSON.stringify(testCommand)}\n      - run: kubectl set image deployment/api api=${digest}\n${deploymentCondition ? `        if: ${deploymentCondition}\n` : ''}`;

  for (const command of [
    `docker run --cap-add NET_ADMIN ${digest} npm test`,
    `docker run --platform linux/amd64 ${digest} npm test`,
    `docker run ${digest} npm test && echo passed`,
    `docker compose run integration-test`,
  ]) {
    for (const condition of ['', 'always()']) {
      const report = analyze(workflow(command, condition));
      assert.equal(report.deployments[0].checks.test, 'unknown', command);
      assert.notEqual(report.deployments[0].state, 'mismatch', command);
      assert.equal(
        report.findings.some((finding) => finding.ruleId === 'SB001'),
        false,
        `${command} ${condition}`,
      );
    }
  }

  const unrelated = analyze(workflow(`docker run postgres@${B} npm test`));
  assert.ok(unrelated.findings.some((finding) => finding.ruleId === 'SB001'));

  const notAwaited = analyze(
    `jobs:\n  source:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n  build:\n    needs: source\n    runs-on: ubuntu-latest\n    outputs:\n      digest: \${{ steps.image.outputs.digest }}\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n  verify-and-deploy:\n    needs: build\n    runs-on: ubuntu-latest\n    steps:\n      - id: test\n        run: docker run ghcr.io/acme/api@\${{ needs.build.outputs.digest }} npm test\n        background: true\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ needs.build.outputs.digest }}`,
  );
  assert.ok(notAwaited.findings.some((finding) => finding.ruleId === 'SB001'));
});
test('disabled or later matching OCI tests do not suppress SB001', () => {
  const digest = 'ghcr.io/acme/api@${{ steps.image.outputs.digest }}';
  const workflows = [
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n      - id: image\n        uses: docker/build-push-action@v6\n      - if: false\n        run: docker run --cap-add NET_ADMIN ${digest} npm test\n      - if: always()\n        run: kubectl set image deployment/api api=${digest}`,
    `jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n      - id: image\n        uses: docker/build-push-action@v6\n      - if: always()\n        run: kubectl set image deployment/api api=${digest}\n      - run: docker run --cap-add NET_ADMIN ${digest} npm test`,
  ];
  for (const source of workflows) {
    const report = analyze(source);
    assert.ok(report.findings.some((finding) => finding.ruleId === 'SB001'));
  }
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
test('kubectl dry-run none remains a deployment while non-mutating modes are ignored', () => {
  const imageRef = 'ghcr.io/acme/api:release';
  for (const dryRun of ['--dry-run=none', '--dry-run none']) {
    const report = simple(`kubectl set image deployment/api api=${imageRef} ${dryRun}`);
    assert.equal(report.deployments.length, 1, dryRun);
    assert.ok(
      report.findings.some((finding) => finding.ruleId === 'SB005'),
      dryRun,
    );
  }
  for (const dryRun of ['--dry-run=client', '--dry-run=server'])
    assert.equal(
      simple(`kubectl set image deployment/api api=${imageRef} ${dryRun}`).deployments
        .length,
      0,
      dryRun,
    );
  const localFalse = simple(
    `kubectl set image deployment/api api=${imageRef} --local=false`,
  );
  assert.equal(localFalse.deployments.length, 1);
  assert.ok(localFalse.findings.some((finding) => finding.ruleId === 'SB005'));
});
test('unresolved shell variables after a docker image do not erase its identity', () => {
  const report = analyze(
    `jobs:\n  build:\n    runs-on: ubuntu-latest\n    outputs:\n      digest: \${{ steps.image.outputs.digest }}\n    steps:\n      - id: image\n        uses: docker/build-push-action@v6\n        with:\n          push: true\n  test:\n    needs: build\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker run ghcr.io/acme/api@\${{ needs.build.outputs.digest }} sh -c 'echo "$UNAVAILABLE"'\n  deploy:\n    needs: [build, test]\n    runs-on: ubuntu-latest\n    steps:\n      - run: kubectl set image deployment/api api=ghcr.io/acme/api@\${{ needs.build.outputs.digest }}`,
  );
  assert.equal(report.deployments[0].checks.test, 'proven');
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
    false,
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
    false,
  );
});
