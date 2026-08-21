import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { verifyExternalRunWithStructuredClaims } from '../external-run/verify-structured-claims.mjs';
import {
  createSignedWriterDomainSeal,
  verifyWorldContactBundleLocal,
  verifyWorldContactWithWriterDomainSeal
} from '../external-run/verify-writer-domain-seal.mjs';

const execFileAsync = promisify(execFile);

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  if (index < 0) return fallback;
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`--${name} requires a value`);
  return value;
}

async function git(workspace, args) {
  const { stdout } = await execFileAsync('git', args, {
    cwd: workspace,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 120_000,
    windowsHide: true
  });
  return String(stdout).replaceAll('\r\n', '\n');
}

async function writeUtf8(file, text) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, text, 'utf8');
}

async function readJson(file) {
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

async function hashFile(file) {
  return crypto.createHash('sha256').update(await fs.readFile(file)).digest('hex');
}

function sha256Text(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

async function regenerateManifest(root) {
  const manifestPath = path.join(root, 'manifest.sha256.json');
  await fs.rm(manifestPath, { force: true });
  const entries = [];
  async function walk(dir) {
    for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else entries.push({ path: path.relative(root, absolute).replaceAll('\\', '/'), sha256: await hashFile(absolute) });
    }
  }
  await walk(root);
  entries.sort((a, b) => a.path.localeCompare(b.path));
  await writeUtf8(manifestPath, `${JSON.stringify(entries, null, 2)}\n`);
}

async function copyCase(source, destination) {
  await fs.cp(source, destination, { recursive: true, errorOnExist: true, force: false });
}

async function loadCase(root) {
  return {
    root,
    bundlePath: path.join(root, 'bundle.json'),
    bundle: await readJson(path.join(root, 'bundle.json')),
    challenge: await readJson(path.join(root, 'coordinator', 'challenge.json')),
    receipt: await readJson(path.join(root, 'coordinator', 'receipt.json')),
    events: await readJson(path.join(root, 'coordinator', 'echo-events.json')),
    observation: await readJson(path.join(root, 'evidence', 'challenge-observation.json'))
  };
}

async function persistMutatedCase(item) {
  const observationPath = path.join(item.root, 'evidence', 'challenge-observation.json');
  const eventPath = path.join(item.root, 'coordinator', 'echo-events.json');
  const receiptPath = path.join(item.root, 'coordinator', 'receipt.json');
  const bundlePath = path.join(item.root, 'bundle.json');

  await writeUtf8(observationPath, `${JSON.stringify(item.observation, null, 2)}\n`);
  await writeUtf8(eventPath, `${JSON.stringify(item.events, null, 2)}\n`);

  const observationSha = await hashFile(observationPath);
  const artifact = item.bundle.artifacts?.find(entry => entry?.path === 'evidence/challenge-observation.json');
  if (!artifact) throw new Error('bundle lacks challenge-observation artifact');
  artifact.sha256 = observationSha;
  item.receipt.observation_sha256 = observationSha;

  await writeUtf8(receiptPath, `${JSON.stringify(item.receipt, null, 2)}\n`);
  await writeUtf8(bundlePath, `${JSON.stringify(item.bundle, null, 2)}\n`);
  await regenerateManifest(item.root);
}

async function verdicts(item, workspace, trustedSeal, trustedPublicKeyPem) {
  const generic = await verifyExternalRunWithStructuredClaims({
    bundle: item.bundle,
    bundlePath: item.bundlePath,
    workspace,
    taskClass: 'explanation'
  });
  const local = await verifyWorldContactBundleLocal({
    bundle: item.bundle,
    bundlePath: item.bundlePath,
    workspace,
    expectedChallenge: item.challenge,
    coordinatorReceipt: item.receipt,
    taskClass: 'explanation'
  });
  const sealed = await verifyWorldContactWithWriterDomainSeal({
    bundle: item.bundle,
    bundlePath: item.bundlePath,
    workspace,
    expectedChallenge: item.challenge,
    coordinatorReceipt: item.receipt,
    trustedSeal,
    trustedPublicKeyPem,
    taskClass: 'explanation'
  });
  return { generic, local, sealed };
}

async function main() {
  const workspace = path.resolve(arg('workspace', process.cwd()));
  const sourceArg = arg('source');
  const outputArg = arg('output');
  const trustedStoreArg = arg('trusted-store');
  if (!sourceArg) throw new Error('--source is required');
  if (!outputArg) throw new Error('--output is required');
  if (!trustedStoreArg) throw new Error('--trusted-store is required');

  const sourceRoot = path.resolve(sourceArg);
  const outputRoot = path.resolve(outputArg);
  const trustedStore = path.resolve(trustedStoreArg);

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before writer-domain adversary');

  await fs.access(path.join(sourceRoot, '01-honest', 'bundle.json'));
  await fs.access(path.join(sourceRoot, '02-liar', 'bundle.json'));
  for (const candidate of [outputRoot, trustedStore]) {
    try {
      await fs.access(candidate);
      throw new Error(`refusing to overwrite existing path: ${candidate}`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }

  await fs.mkdir(outputRoot, { recursive: true });
  await fs.mkdir(trustedStore, { recursive: true });

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const publicKeyFingerprint = sha256Text(publicKeyPem);
  await writeUtf8(path.join(trustedStore, 'coordinator-public-key.pem'), publicKeyPem);
  await writeUtf8(path.join(trustedStore, 'public-key.sha256.txt'), `${publicKeyFingerprint}\n`);

  const honestRoot = path.join(outputRoot, '01-honest-sealed');
  await copyCase(path.join(sourceRoot, '01-honest'), honestRoot);
  let honest = await loadCase(honestRoot);
  const honestEventBytes = await fs.readFile(path.join(honestRoot, 'coordinator', 'echo-events.json'));
  const honestSeal = createSignedWriterDomainSeal({
    privateKey,
    expectedChallenge: honest.challenge,
    eventBytes: honestEventBytes
  });
  await writeUtf8(path.join(trustedStore, '01-honest-world-event.seal.json'), `${JSON.stringify(honestSeal, null, 2)}\n`);
  const honestVerdicts = await verdicts(honest, workspace, honestSeal, publicKeyPem);
  await writeUtf8(path.join(honestRoot, 'verdict-writer-domain-local.json'), `${JSON.stringify(honestVerdicts.local, null, 2)}\n`);
  await writeUtf8(path.join(honestRoot, 'verdict-writer-domain-sealed.json'), `${JSON.stringify(honestVerdicts.sealed, null, 2)}\n`);
  await regenerateManifest(honestRoot);
  console.log(`01 honest: generic=${honestVerdicts.generic.disposition} local=${honestVerdicts.local.disposition} sealed=${honestVerdicts.sealed.disposition}`);

  if (!(honestVerdicts.generic.disposition === 'verified' && honestVerdicts.local.disposition === 'verified' && honestVerdicts.sealed.disposition === 'verified')) {
    await writeUtf8(path.join(outputRoot, 'baseline-failure.json'), `${JSON.stringify({ honest: honestVerdicts }, null, 2)}\n`);
    throw new Error('honest sealed baseline did not verify; stopping before adversarial mutation');
  }

  const rewrittenRoot = path.join(outputRoot, '02-rewritten-honest-event');
  await copyCase(path.join(sourceRoot, '01-honest'), rewrittenRoot);
  let rewritten = await loadCase(rewrittenRoot);
  const rewrittenToken = crypto.randomBytes(32).toString('hex');
  const eventIndex = rewritten.events.findIndex(event => event?.nonce === rewritten.challenge.nonce);
  if (eventIndex < 0) throw new Error('honest source lacks matching coordinator event');
  rewritten.events[eventIndex] = {
    ...rewritten.events[eventIndex],
    response_token: rewrittenToken,
    forged_by_bundle_writer: true
  };
  rewritten.observation.observed.world_token = rewrittenToken;
  await persistMutatedCase(rewritten);
  rewritten = await loadCase(rewrittenRoot);
  const rewrittenVerdicts = await verdicts(rewritten, workspace, honestSeal, publicKeyPem);
  await writeUtf8(path.join(rewrittenRoot, 'verdict-writer-domain-local.json'), `${JSON.stringify(rewrittenVerdicts.local, null, 2)}\n`);
  await writeUtf8(path.join(rewrittenRoot, 'verdict-writer-domain-sealed.json'), `${JSON.stringify(rewrittenVerdicts.sealed, null, 2)}\n`);
  await regenerateManifest(rewrittenRoot);
  console.log(`02 rewritten honest event: generic=${rewrittenVerdicts.generic.disposition} local=${rewrittenVerdicts.local.disposition} sealed=${rewrittenVerdicts.sealed.disposition}`);

  const inventedRoot = path.join(outputRoot, '03-invented-liar-event');
  await copyCase(path.join(sourceRoot, '02-liar'), inventedRoot);
  let invented = await loadCase(inventedRoot);
  const inventedToken = crypto.randomBytes(32).toString('hex');
  const issued = Date.parse(invented.challenge.issued_at);
  invented.events = [{
    at: new Date(issued + 1000).toISOString(),
    method: 'GET',
    path: '/probe',
    nonce: invented.challenge.nonce,
    response_token: inventedToken,
    remote_address: '100.95.40.99',
    user_agent: 'forged-by-bundle-writer',
    forged_by_bundle_writer: true
  }];
  invented.observation.observed.world_token = inventedToken;
  await persistMutatedCase(invented);
  invented = await loadCase(inventedRoot);
  const inventedNoSeal = await verdicts(invented, workspace, null, publicKeyPem);
  const inventedStolenSeal = await verdicts(invented, workspace, honestSeal, publicKeyPem);
  await writeUtf8(path.join(inventedRoot, 'verdict-writer-domain-local.json'), `${JSON.stringify(inventedNoSeal.local, null, 2)}\n`);
  await writeUtf8(path.join(inventedRoot, 'verdict-writer-domain-no-seal.json'), `${JSON.stringify(inventedNoSeal.sealed, null, 2)}\n`);
  await writeUtf8(path.join(inventedRoot, 'verdict-writer-domain-stolen-seal.json'), `${JSON.stringify(inventedStolenSeal.sealed, null, 2)}\n`);
  await regenerateManifest(inventedRoot);
  console.log(`03 invented liar event: generic=${inventedNoSeal.generic.disposition} local=${inventedNoSeal.local.disposition} no-seal=${inventedNoSeal.sealed.disposition} stolen-seal=${inventedStolenSeal.sealed.disposition}`);

  const matrix = {
    schema: 'aide.writer-domain-evidence-root-adversary/v1',
    source_evidence_root: sourceRoot,
    trusted_store: trustedStore,
    coordinator_public_key_sha256: publicKeyFingerprint,
    private_signing_key_persisted: false,
    results: {
      honest: {
        generic: honestVerdicts.generic.disposition,
        bundle_local_world: honestVerdicts.local.disposition,
        sealed_world: honestVerdicts.sealed.disposition
      },
      rewritten_honest_event: {
        generic: rewrittenVerdicts.generic.disposition,
        bundle_local_world: rewrittenVerdicts.local.disposition,
        sealed_world: rewrittenVerdicts.sealed.disposition,
        note: 'attacker changed coordinator event + browser world token and recomputed bundle-local observation/receipt hashes'
      },
      invented_liar_event: {
        generic: inventedNoSeal.generic.disposition,
        bundle_local_world: inventedNoSeal.local.disposition,
        sealed_world_without_seal: inventedNoSeal.sealed.disposition,
        sealed_world_with_stolen_honest_seal: inventedStolenSeal.sealed.disposition,
        note: 'original no-contact liar was given a fabricated coordinator event and matching browser token entirely inside the mutable bundle'
      }
    },
    findings: {
      bundle_local_writer_domain_label_is_not_authority: rewrittenVerdicts.local.disposition === 'verified' && inventedNoSeal.local.disposition === 'verified',
      rewritten_coordinator_artifact_blocked_by_seal: rewrittenVerdicts.sealed.disposition === 'rejected',
      invented_world_contact_cannot_verify_without_seal: inventedNoSeal.sealed.disposition !== 'verified',
      stolen_seal_cannot_cross_task_boundary: inventedStolenSeal.sealed.disposition === 'rejected',
      honest_sealed_world_contact_verified: honestVerdicts.sealed.disposition === 'verified'
    }
  };

  await writeUtf8(path.join(outputRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
  await writeUtf8(path.join(outputRoot, 'report.md'), [
    '# Writer-domain / evidence-root adversary',
    '',
    `Coordinator public-key fingerprint: ${publicKeyFingerprint}`,
    'Private signing key persisted: no',
    '',
    `Honest: generic=${matrix.results.honest.generic} local=${matrix.results.honest.bundle_local_world} sealed=${matrix.results.honest.sealed_world}`,
    `Rewritten honest event: generic=${matrix.results.rewritten_honest_event.generic} local=${matrix.results.rewritten_honest_event.bundle_local_world} sealed=${matrix.results.rewritten_honest_event.sealed_world}`,
    `Invented liar event: generic=${matrix.results.invented_liar_event.generic} local=${matrix.results.invented_liar_event.bundle_local_world} no-seal=${matrix.results.invented_liar_event.sealed_world_without_seal} stolen-seal=${matrix.results.invented_liar_event.sealed_world_with_stolen_honest_seal}`,
    '',
    'A directory or metadata label called coordinator is not a trust boundary. If the executor can rewrite those bytes and recompute bundle-local hashes/receipts, bundle-local world verification can be fooled.',
    'The Ed25519 writer-domain seal authenticates the exact coordinator event bytes independently of the executor bundle. This experiment establishes the protocol requirement only; OS ACL/process isolation of the trusted seal/public-key input remains a separate hardening step.',
    ''
  ].join('\n'));
  await regenerateManifest(outputRoot);

  const expected = matrix.findings.bundle_local_writer_domain_label_is_not_authority &&
    matrix.findings.rewritten_coordinator_artifact_blocked_by_seal &&
    matrix.findings.invented_world_contact_cannot_verify_without_seal &&
    matrix.findings.stolen_seal_cannot_cross_task_boundary &&
    matrix.findings.honest_sealed_world_contact_verified;

  console.log(`Matrix: ${path.join(outputRoot, 'matrix.json')}`);
  console.log(`Trusted store: ${trustedStore}`);
  console.log(`Findings: ${JSON.stringify(matrix.findings)}`);
  if (!expected) process.exitCode = 1;
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
