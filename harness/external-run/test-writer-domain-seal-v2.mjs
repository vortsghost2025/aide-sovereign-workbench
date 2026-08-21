import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  if (index < 0) return fallback;
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`--${name} requires a value`);
  return value;
}

async function sha256File(file) {
  const bytes = await fs.readFile(file);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function sha256Text(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function writerDomain(relative) {
  const normalized = relative.replaceAll('\\', '/');
  if (normalized.startsWith('coordinator/')) return 'COORDINATOR';
  if (normalized.startsWith('evidence/')) return 'EXECUTOR';
  if (normalized.startsWith('verdict-') || normalized === 'report.md' || normalized === 'manifest.sha256.json') return 'VERIFIER';
  if (normalized === 'bundle.json') return 'EXECUTOR';
  return 'UNKNOWN';
}

async function walkFiles(root) {
  const out = [];
  async function walk(directory) {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile()) out.push(absolute);
      else throw new Error(`unsupported non-file entry while sealing: ${absolute}`);
    }
  }
  await walk(root);
  return out;
}

async function manifestFor(root) {
  const entries = [];
  for (const absolute of await walkFiles(root)) {
    const relative = path.relative(root, absolute).replaceAll('\\', '/');
    entries.push({
      path: relative,
      sha256: await sha256File(absolute),
      writer_domain: writerDomain(relative)
    });
  }
  entries.sort((a, b) => a.path.localeCompare(b.path));
  return entries;
}

function treeHash(entries) {
  return sha256Text(entries.map(item => `${item.path}\0${item.sha256}\0${item.writer_domain}\n`).join(''));
}

async function sealRoot(root, sealPath, label) {
  const entries = await manifestFor(root);
  const seal = {
    schema: 'aide.writer-domain-seal/v2',
    label,
    sealed_at: new Date().toISOString(),
    sealer_domain: 'VERIFIER',
    tree_sha256: treeHash(entries),
    artifacts: entries
  };
  await fs.mkdir(path.dirname(sealPath), { recursive: true });
  await fs.writeFile(sealPath, `${JSON.stringify(seal, null, 2)}\n`, 'utf8');
  return seal;
}

async function verifyAgainstSeal(root, seal) {
  let current;
  try {
    current = await manifestFor(root);
  } catch (error) {
    return {
      disposition: 'rejected',
      tree_match: false,
      reason: `unable to enumerate sealed tree: ${error.message || String(error)}`
    };
  }
  const observedHash = treeHash(current);
  const expected = new Map(seal.artifacts.map(item => [item.path, item]));
  const observed = new Map(current.map(item => [item.path, item]));
  const changed = [];
  const missing = [];
  const extra = [];
  for (const [relative, expectedItem] of expected) {
    const actual = observed.get(relative);
    if (!actual) missing.push(relative);
    else if (actual.sha256 !== expectedItem.sha256 || actual.writer_domain !== expectedItem.writer_domain) changed.push(relative);
  }
  for (const relative of observed.keys()) {
    if (!expected.has(relative)) extra.push(relative);
  }
  const passed = observedHash === seal.tree_sha256 && changed.length === 0 && missing.length === 0 && extra.length === 0;
  return {
    disposition: passed ? 'verified' : 'rejected',
    tree_match: observedHash === seal.tree_sha256,
    expected_tree_sha256: seal.tree_sha256,
    observed_tree_sha256: observedHash,
    changed,
    missing,
    extra
  };
}

async function copyCase(source, caseRoot) {
  await fs.cp(source, caseRoot, { recursive: true, errorOnExist: true, force: false });
}

async function mutateJsonFile(file, label) {
  const text = await fs.readFile(file, 'utf8');
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    await fs.appendFile(file, `\n${label}\n`, 'utf8');
    return;
  }

  if (Array.isArray(document)) {
    document.push({ __seal_probe: label });
  } else if (document && typeof document === 'object') {
    document.__seal_probe = label;
  } else {
    document = { original: document, __seal_probe: label };
  }
  await fs.writeFile(file, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
}

async function runCase({ outputRoot, source, name, mutation }) {
  const caseDir = path.join(outputRoot, name);
  const root = path.join(caseDir, 'root');
  const sealPath = path.join(caseDir, 'verifier', 'seal.json');
  await copyCase(source, root);
  const seal = await sealRoot(root, sealPath, name);
  const before = await verifyAgainstSeal(root, seal);
  if (mutation) await mutation(root);
  const after = await verifyAgainstSeal(root, seal);
  await fs.writeFile(path.join(caseDir, 'verdict.json'), `${JSON.stringify({ before, after }, null, 2)}\n`, 'utf8');
  return { before, after, seal_path: path.relative(outputRoot, sealPath).replaceAll('\\', '/') };
}

async function runSealRewriteCase({ outputRoot, source }) {
  const name = '05-same-principal-seal-rewrite';
  const caseDir = path.join(outputRoot, name);
  const root = path.join(caseDir, 'root');
  const sealPath = path.join(caseDir, 'verifier', 'seal.json');
  await copyCase(source, root);

  const originalSeal = await sealRoot(root, sealPath, `${name}-original`);
  const before = await verifyAgainstSeal(root, originalSeal);

  const target = path.join(root, 'coordinator', 'echo-events.json');
  await mutateJsonFile(target, 'same-principal-root-mutation');
  const againstOriginalSeal = await verifyAgainstSeal(root, originalSeal);

  const rewrittenSeal = await sealRoot(root, sealPath, `${name}-rewritten`);
  const againstRewrittenSeal = await verifyAgainstSeal(root, rewrittenSeal);

  const verdict = {
    before,
    against_original_seal: againstOriginalSeal,
    against_rewritten_seal: againstRewrittenSeal,
    same_principal_can_rewrite_seal: againstOriginalSeal.disposition === 'rejected' && againstRewrittenSeal.disposition === 'verified',
    original_tree_sha256: originalSeal.tree_sha256,
    rewritten_tree_sha256: rewrittenSeal.tree_sha256
  };
  await fs.writeFile(path.join(caseDir, 'verdict.json'), `${JSON.stringify(verdict, null, 2)}\n`, 'utf8');
  return verdict;
}

async function probeVerifierWriteAccess(outputRoot) {
  const verifierDir = path.join(outputRoot, 'verifier-domain-probe');
  await fs.mkdir(verifierDir, { recursive: true });
  const probe = path.join(verifierDir, `write-probe-${crypto.randomBytes(6).toString('hex')}.tmp`);
  try {
    await fs.writeFile(probe, 'probe\n', 'utf8');
    const observed = await fs.readFile(probe, 'utf8');
    await fs.rm(probe, { force: true });
    return {
      same_process_can_write_verifier_domain: observed === 'probe\n',
      os_writer_boundary_enforced: false,
      note: 'The current Windows user/process can write a verifier-designated directory. Application-level writer_domain labels are provenance metadata, not OS isolation.'
    };
  } catch (error) {
    return {
      same_process_can_write_verifier_domain: false,
      os_writer_boundary_enforced: true,
      error: error.message || String(error)
    };
  }
}

async function main() {
  const sourceArg = arg('source');
  const outputArg = arg('output');
  if (!sourceArg) throw new Error('--source is required');
  if (!outputArg) throw new Error('--output is required');
  const source = path.resolve(sourceArg);
  const outputRoot = path.resolve(outputArg);

  const sourceStat = await fs.stat(source);
  if (!sourceStat.isDirectory()) throw new Error(`source is not a directory: ${source}`);
  try {
    await fs.access(outputRoot);
    throw new Error(`output path already exists; refusing to overwrite evidence: ${outputRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await fs.mkdir(outputRoot, { recursive: true });

  console.log('01 baseline seal...');
  const baseline = await runCase({ outputRoot, source, name: '01-baseline' });
  console.log(`   before=${baseline.before.disposition} after=${baseline.after.disposition}`);

  console.log('02 executor artifact mutation after seal...');
  const executorMutation = await runCase({
    outputRoot,
    source,
    name: '02-executor-post-seal-mutation',
    mutation: root => mutateJsonFile(path.join(root, 'evidence', 'challenge-observation.json'), 'executor-post-seal-mutation')
  });
  console.log(`   before=${executorMutation.before.disposition} after=${executorMutation.after.disposition}`);

  console.log('03 coordinator artifact mutation after seal...');
  const coordinatorMutation = await runCase({
    outputRoot,
    source,
    name: '03-coordinator-post-seal-mutation',
    mutation: root => mutateJsonFile(path.join(root, 'coordinator', 'echo-events.json'), 'coordinator-post-seal-mutation')
  });
  console.log(`   before=${coordinatorMutation.before.disposition} after=${coordinatorMutation.after.disposition}`);

  console.log('04 cross-run contamination after seal...');
  const contamination = await runCase({
    outputRoot,
    source,
    name: '04-cross-run-contamination',
    mutation: async root => {
      await fs.writeFile(path.join(root, 'evidence', 'foreign-run-artifact.txt'), 'foreign-run-data\n', 'utf8');
    }
  });
  console.log(`   before=${contamination.before.disposition} after=${contamination.after.disposition}`);

  console.log('05 same-principal root + seal rewrite...');
  const sealRewrite = await runSealRewriteCase({ outputRoot, source });
  console.log(`   old-seal=${sealRewrite.against_original_seal.disposition} rewritten-seal=${sealRewrite.against_rewritten_seal.disposition}`);

  console.log('06 verifier-domain OS write-access probe...');
  const isolation = await probeVerifierWriteAccess(outputRoot);
  console.log(`   same-process-write=${isolation.same_process_can_write_verifier_domain} os-boundary=${isolation.os_writer_boundary_enforced}`);

  const matrix = {
    schema: 'aide.writer-domain-seal-matrix/v2',
    source,
    cases: {
      baseline,
      executor_post_seal_mutation: executorMutation,
      coordinator_post_seal_mutation: coordinatorMutation,
      cross_run_contamination: contamination,
      same_principal_seal_rewrite: sealRewrite
    },
    isolation,
    findings: {
      baseline_verified: baseline.after.disposition === 'verified',
      executor_mutation_detected: executorMutation.after.disposition === 'rejected',
      coordinator_mutation_detected: coordinatorMutation.after.disposition === 'rejected',
      cross_run_contamination_detected: contamination.after.disposition === 'rejected',
      immutable_seal_detects_all_tested_root_mutations:
        executorMutation.after.disposition === 'rejected' &&
        coordinatorMutation.after.disposition === 'rejected' &&
        contamination.after.disposition === 'rejected',
      same_principal_can_rewrite_root_and_seal: sealRewrite.same_principal_can_rewrite_seal,
      verifier_domain_os_isolation_proven: isolation.os_writer_boundary_enforced
    }
  };

  await fs.writeFile(path.join(outputRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`, 'utf8');
  const report = [
    '# Writer-Domain / Seal Boundary Probe V2',
    '',
    `Baseline: ${baseline.after.disposition.toUpperCase()}`,
    `Executor artifact mutation vs immutable seal: ${executorMutation.after.disposition.toUpperCase()}`,
    `Coordinator artifact mutation vs immutable seal: ${coordinatorMutation.after.disposition.toUpperCase()}`,
    `Cross-run contamination vs immutable seal: ${contamination.after.disposition.toUpperCase()}`,
    `Mutated root vs original seal: ${sealRewrite.against_original_seal.disposition.toUpperCase()}`,
    `Mutated root vs same-principal rewritten seal: ${sealRewrite.against_rewritten_seal.disposition.toUpperCase()}`,
    `Same process can write verifier-designated directory: ${isolation.same_process_can_write_verifier_domain ? 'YES' : 'NO'}`,
    `OS writer boundary proven: ${isolation.os_writer_boundary_enforced ? 'YES' : 'NO'}`,
    '',
    'Interpretation:',
    '- With an immutable trusted seal, all three tested post-seal root mutations must be detected.',
    '- V1 coordinator mutation was an ineffective array mutation: adding a non-index property to a JavaScript Array is ignored by JSON.stringify. V2 mutates arrays by appending a marker object.',
    '- If the same principal can alter both the evidence root and verifier seal, it can create a new internally consistent seal. That does not forge an externally protected seal; it proves the current Windows path does not yet provide that protection.',
    '- writer_domain remains useful provenance metadata, but CERTIFIED-grade separation requires a seal/store the executor principal cannot rewrite.',
    ''
  ].join('\n');
  await fs.writeFile(path.join(outputRoot, 'report.md'), report, 'utf8');

  const expected =
    matrix.findings.baseline_verified &&
    matrix.findings.executor_mutation_detected &&
    matrix.findings.coordinator_mutation_detected &&
    matrix.findings.cross_run_contamination_detected &&
    matrix.findings.same_principal_can_rewrite_root_and_seal &&
    isolation.same_process_can_write_verifier_domain === true &&
    isolation.os_writer_boundary_enforced === false;

  console.log(`Matrix: ${path.join(outputRoot, 'matrix.json')}`);
  console.log(`Evidence: ${outputRoot}`);
  if (!expected) process.exitCode = 1;
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
