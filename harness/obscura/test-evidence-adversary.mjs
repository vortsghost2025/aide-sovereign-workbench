import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { verifyExternalRun } from '../external-run/verify.mjs';

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

async function verdict(root, workspace) {
  const { file, bundle } = await readBundle(root);
  return verifyExternalRun({ bundle, bundlePath: file, workspace, taskClass: 'explanation' });
}

function summarize(name, result) {
  console.log(`${name}: ${result.disposition} (${Math.round(result.evidence_score * 100)}%)`);
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

  const baseline = await verdict(source, workspace);
  summarize('00-baseline', baseline);
  assert.equal(baseline.disposition, 'verified', 'source evidence must verify before adversarial mutation');

  const transcriptTamper = path.join(output, '01-tampered-transcript');
  await copyCase(source, transcriptTamper);
  await fs.appendFile(path.join(transcriptTamper, 'evidence', 'mcp-transcript.ndjson'), '{"tampered":true}\n', 'utf8');
  const transcriptResult = await verdict(transcriptTamper, workspace);
  summarize('01-tampered-transcript', transcriptResult);
  assert.equal(transcriptResult.disposition, 'rejected');

  const snapshotTamper = path.join(output, '02-tampered-snapshot');
  await copyCase(source, snapshotTamper);
  await fs.appendFile(path.join(snapshotTamper, 'evidence', 'snapshot.txt'), '\nPOST-EXECUTION-TAMPER\n', 'utf8');
  const snapshotResult = await verdict(snapshotTamper, workspace);
  summarize('02-tampered-snapshot', snapshotResult);
  assert.equal(snapshotResult.disposition, 'rejected');

  const missingSnapshot = path.join(output, '03-missing-snapshot');
  await copyCase(source, missingSnapshot);
  await fs.rm(path.join(missingSnapshot, 'evidence', 'snapshot.txt'));
  const missingResult = await verdict(missingSnapshot, workspace);
  summarize('03-missing-snapshot', missingResult);
  assert.equal(missingResult.disposition, 'abstain-needs-evidence');

  const semanticLie = path.join(output, '04-semantic-claim-lie');
  await copyCase(source, semanticLie);
  const semantic = await readBundle(semanticLie);
  semantic.bundle.task.summary = 'Claim that the browser observed page title COMPLETELY FALSE TITLE';
  semantic.bundle.claim.summary = 'The verified page title was COMPLETELY FALSE TITLE';
  await writeBundle(semantic.file, semantic.bundle);
  const semanticResult = await verdict(semanticLie, workspace);
  summarize('04-semantic-claim-lie', semanticResult);

  const finding = {
    schema: 'aide.obscura-adversary/v1',
    baseline: baseline.disposition,
    tampered_transcript: transcriptResult.disposition,
    tampered_snapshot: snapshotResult.disposition,
    missing_snapshot: missingResult.disposition,
    semantic_false_claim: semanticResult.disposition,
    semantic_claim_gap_observed: semanticResult.disposition === 'verified',
    note: semanticResult.disposition === 'verified'
      ? 'Current external-run verifier authenticates evidence integrity and execution/test consistency, but does not bind free-form task/claim prose to browser observations. Add a structured browser-claim evidence contract before treating semantic page claims as machine-verified.'
      : 'Semantic false claim was already blocked; inspect the blocking checks before adding a new contract.'
  };

  await fs.writeFile(path.join(output, 'matrix.json'), `${JSON.stringify(finding, null, 2)}\n`, 'utf8');

  console.log('');
  if (finding.semantic_claim_gap_observed) {
    console.log('SEMANTIC CLAIM-BINDING GAP OBSERVED');
    console.log('Integrity tamper is rejected and missing evidence abstains, but free-form browser claim prose is not yet evidence-bound.');
  } else {
    console.log('SEMANTIC CLAIM WAS BLOCKED BY CURRENT VERIFIER');
  }
  console.log(`Matrix: ${path.join(output, 'matrix.json')}`);
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
