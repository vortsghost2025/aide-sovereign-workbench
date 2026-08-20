import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { verifyExternalRun } from '../external-run/verify.mjs';
import { verifyExternalRunWithStructuredClaims } from '../external-run/verify-structured-claims.mjs';

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  if (index < 0) return fallback;
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`--${name} requires a value`);
  return value;
}

async function copyCase(source, destination) {
  await fs.cp(source, destination, { recursive: true, errorOnExist: true, force: false });
}

async function readBundle(root) {
  const file = path.join(root, 'bundle.json');
  return { file, bundle: JSON.parse(await fs.readFile(file, 'utf8')) };
}

async function writeBundle(file, bundle) {
  await fs.writeFile(file, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');
}

async function structuredVerdict(root, workspace) {
  const { file, bundle } = await readBundle(root);
  return verifyExternalRunWithStructuredClaims({ bundle, bundlePath: file, workspace, taskClass: 'explanation' });
}

async function baseVerdict(root, workspace) {
  const { file, bundle } = await readBundle(root);
  return verifyExternalRun({ bundle, bundlePath: file, workspace, taskClass: 'explanation' });
}

function summarize(name, result) {
  console.log(`${name}: ${result.disposition} (${Math.round(result.evidence_score * 100)}%)`);
  if (result.structured_claims?.enabled) {
    console.log(`  structured claims: ${result.structured_claims.passed ? 'PASS' : 'BLOCK'}`);
  }
  if (result.contradictions.length) console.log(`  contradictions: ${result.contradictions.join(' | ')}`);
  if (result.missing_evidence.length) console.log(`  missing: ${result.missing_evidence.join(' | ')}`);
}

async function main() {
  const source = path.resolve(arg('source'));
  const output = path.resolve(arg('output'));
  const workspace = path.resolve(arg('workspace', process.cwd()));
  if (!source) throw new Error('--source is required');
  if (!output) throw new Error('--output is required');

  await fs.access(path.join(source, 'bundle.json'));
  try {
    await fs.access(output);
    throw new Error(`output already exists; refusing to overwrite: ${output}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await fs.mkdir(output, { recursive: true });

  const baseline = await structuredVerdict(source, workspace);
  summarize('00-baseline-structured', baseline);
  assert.equal(baseline.disposition, 'verified');
  assert.equal(baseline.structured_claims?.passed, true);

  const observationTamper = path.join(output, '01-tampered-observation');
  await copyCase(source, observationTamper);
  await fs.appendFile(path.join(observationTamper, 'evidence', 'page-observation.json'), '\nPOST-EXECUTION-TAMPER\n', 'utf8');
  const observationTamperResult = await structuredVerdict(observationTamper, workspace);
  summarize('01-tampered-observation', observationTamperResult);
  assert.equal(observationTamperResult.disposition, 'rejected');

  const missingObservation = path.join(output, '02-missing-observation');
  await copyCase(source, missingObservation);
  await fs.rm(path.join(missingObservation, 'evidence', 'page-observation.json'));
  const missingObservationResult = await structuredVerdict(missingObservation, workspace);
  summarize('02-missing-observation', missingObservationResult);
  assert.equal(missingObservationResult.disposition, 'abstain-needs-evidence');

  const structuredLie = path.join(output, '03-structured-claim-lie');
  await copyCase(source, structuredLie);
  const structured = await readBundle(structuredLie);
  assert.ok(Array.isArray(structured.bundle.evidence_claims) && structured.bundle.evidence_claims.length > 0);
  structured.bundle.evidence_claims[0].expected = 'COMPLETELY FALSE TITLE';
  await writeBundle(structured.file, structured.bundle);

  const oldVerifierResult = await baseVerdict(structuredLie, workspace);
  const structuredLieResult = await structuredVerdict(structuredLie, workspace);
  summarize('03a-old-verifier-on-structured-lie', oldVerifierResult);
  summarize('03b-structured-verifier-on-structured-lie', structuredLieResult);
  assert.equal(oldVerifierResult.disposition, 'verified', 'generic integrity verifier should demonstrate the original semantic blind spot');
  assert.equal(structuredLieResult.disposition, 'rejected', 'structured claim verifier must reject false evidence-bound semantics');

  const proseLie = path.join(output, '04-free-form-prose-lie');
  await copyCase(source, proseLie);
  const prose = await readBundle(proseLie);
  prose.bundle.task.summary = 'Free-form prose says the page title was COMPLETELY FALSE TITLE';
  prose.bundle.claim.summary = 'Descriptive prose claims COMPLETELY FALSE TITLE';
  await writeBundle(prose.file, prose.bundle);
  const proseResult = await structuredVerdict(proseLie, workspace);
  summarize('04-free-form-prose-lie', proseResult);
  assert.equal(proseResult.disposition, 'verified');
  assert.equal(proseResult.structured_claims?.passed, true);

  const finding = {
    schema: 'aide.obscura-structured-claims-adversary/v1',
    baseline: baseline.disposition,
    tampered_observation: observationTamperResult.disposition,
    missing_observation: missingObservationResult.disposition,
    structured_false_claim_old_verifier: oldVerifierResult.disposition,
    structured_false_claim_new_verifier: structuredLieResult.disposition,
    free_form_prose_lie: proseResult.disposition,
    structured_claims_still_pass_with_prose_lie: proseResult.structured_claims?.passed === true,
    semantic_binding_gap_closed_for_declared_machine_claims:
      oldVerifierResult.disposition === 'verified' && structuredLieResult.disposition === 'rejected',
    note: 'Free-form prose remains descriptive metadata by design. Machine-verifiable semantic assertions must be declared in evidence_claims and are independently recomputed from hashed structured evidence.'
  };

  await fs.writeFile(path.join(output, 'matrix.json'), `${JSON.stringify(finding, null, 2)}\n`, 'utf8');

  console.log('');
  console.log(finding.semantic_binding_gap_closed_for_declared_machine_claims
    ? 'STRUCTURED SEMANTIC CLAIM GAP CLOSED'
    : 'STRUCTURED SEMANTIC CLAIM GAP STILL OPEN');
  console.log('Free-form prose is intentionally not treated as a machine-verifiable claim.');
  console.log(`Matrix: ${path.join(output, 'matrix.json')}`);
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
