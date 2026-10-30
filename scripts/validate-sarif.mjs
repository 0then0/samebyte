// Structural SARIF 2.1.0 check used by the acceptance workflow and tests.
// Usage: node scripts/validate-sarif.mjs <file> [expected-rule-id...]
// With rule ids, the results must contain exactly those rules (order-insensitive).
import { readFile } from 'node:fs/promises';

const [file, ...expected] = process.argv.slice(2);
const fail = (message) => {
  console.error(`Invalid SARIF ${file ?? ''}: ${message}`);
  process.exit(1);
};
if (!file) fail('missing file argument');
let sarif;
try {
  sarif = JSON.parse(await readFile(file, 'utf8'));
} catch (error) {
  fail(error.message);
}
if (sarif.version !== '2.1.0') fail('version must be 2.1.0');
if (!Array.isArray(sarif.runs) || sarif.runs.length !== 1) fail('expected one run');
const [run] = sarif.runs;
if (run.tool?.driver?.name !== 'SameByte') fail('tool.driver.name must be SameByte');
if (!Array.isArray(run.results)) fail('results must be an array');
if (run.invocations?.[0]?.executionSuccessful !== true)
  fail('invocation must be successful');
for (const result of run.results) {
  const location = result.locations?.[0]?.physicalLocation;
  if (!result.ruleId || !result.message?.text || !location?.artifactLocation?.uri)
    fail('every result needs ruleId, message.text and a location uri');
  if (!Number.isInteger(location.region?.startLine))
    fail('every result needs region.startLine');
}
const actual = run.results.map((result) => result.ruleId).sort();
if (expected.length || process.argv.length > 3) {
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort()))
    fail(`expected rules [${expected}] but found [${actual}]`);
}
console.log(`SARIF ok: ${actual.length} result(s) ${actual.join(',')}`);
