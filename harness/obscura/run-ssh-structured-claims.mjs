import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { renderExternalRunReport } from '../external-run/report.mjs';
import { sha256Buffer } from '../external-run/verify.mjs';
import { verifyExternalRunWithStructuredClaims } from '../external-run/verify-structured-claims.mjs';

const execFileAsync = promisify(execFile);

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  if (index < 0) return fallback;
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`--${name} requires a value`);
  return value;
}

async function writeUtf8(file, text) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, text, 'utf8');
}

async function hashFile(file) {
  return sha256Buffer(await fs.readFile(file));
}

function artifact(name, kind, relativePath, sha256) {
  return { name, kind, path: relativePath.replaceAll('\\', '/'), sha256 };
}

async function regenerateManifest(outputRoot) {
  const manifestPath = path.join(outputRoot, 'manifest.sha256.json');
  await fs.rm(manifestPath, { force: true });
  const entries = [];

  async function walk(directory) {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else entries.push({
        path: path.relative(outputRoot, absolute).replaceAll('\\', '/'),
        sha256: await hashFile(absolute)
      });
    }
  }

  await walk(outputRoot);
  entries.sort((a, b) => a.path.localeCompare(b.path));
  await writeUtf8(manifestPath, `${JSON.stringify(entries, null, 2)}\n`);
}

async function main() {
  const outputRootArg = arg('output');
  if (!outputRootArg) throw new Error('--output is required');
  const outputRoot = path.resolve(outputRootArg);
  const workspace = path.resolve(arg('workspace', process.cwd()));
  const url = arg('url', 'https://example.com');
  const expectedTitle = arg('expect-title', 'Example Domain');
  const expectedH1 = arg('expect-h1', expectedTitle);
  const expectedUrl = new URL(url).href;

  const baseRunner = path.resolve('harness/obscura/run-ssh-mission.mjs');
  const child = await execFileAsync(process.execPath, [baseRunner, ...process.argv.slice(2)], {
    cwd: process.cwd(),
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 180_000,
    windowsHide: true
  }).catch(error => ({
    stdout: error?.stdout || '',
    stderr: error?.stderr || '',
    error,
    failed: true
  }));

  if (child.stdout) process.stdout.write(child.stdout);
  if (child.stderr) process.stderr.write(child.stderr);
  if (child.failed) {
    console.error('Base distributed browser mission did not pass; preserving its evidence without adding structured claims.');
    process.exitCode = 1;
    return;
  }

  const bundlePath = path.join(outputRoot, 'bundle.json');
  const evaluatePath = path.join(outputRoot, 'evidence', 'evaluate.txt');
  const observationPath = path.join(outputRoot, 'evidence', 'page-observation.json');
  const observationRelative = 'evidence/page-observation.json';

  const evaluationText = (await fs.readFile(evaluatePath, 'utf8')).trim();
  let observed;
  try {
    observed = JSON.parse(evaluationText);
  } catch (error) {
    throw new Error(`browser_evaluate evidence was not valid JSON: ${error.message}`);
  }

  const observation = {
    schema: 'aide.browser-observation/v1',
    source: {
      tool: 'browser_evaluate',
      requested_url: url,
      evidence_path: 'evidence/evaluate.txt'
    },
    observed
  };
  await writeUtf8(observationPath, `${JSON.stringify(observation, null, 2)}\n`);

  const bundle = JSON.parse(await fs.readFile(bundlePath, 'utf8'));
  bundle.artifacts = Array.isArray(bundle.artifacts) ? bundle.artifacts : [];
  bundle.artifacts = bundle.artifacts.filter(item => item?.path !== observationRelative);
  bundle.artifacts.push(artifact(
    'browser-page-observation',
    'structured-browser-observation',
    observationRelative,
    await hashFile(observationPath)
  ));

  bundle.evidence_claims = [
    {
      id: 'page-title',
      operator: 'json-equals',
      evidence_path: observationRelative,
      pointer: '/observed/title',
      expected: expectedTitle
    },
    {
      id: 'page-url',
      operator: 'json-equals',
      evidence_path: observationRelative,
      pointer: '/observed/url',
      expected: expectedUrl
    },
    {
      id: 'page-h1',
      operator: 'json-equals',
      evidence_path: observationRelative,
      pointer: '/observed/h1',
      expected: expectedH1
    }
  ];

  bundle.claim = {
    ...bundle.claim,
    summary: bundle.claim?.status === 'success'
      ? `Remote browser mission completed; ${bundle.evidence_claims.length} structured browser claims require independent evidence binding`
      : bundle.claim?.summary
  };

  await writeUtf8(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`);

  const verdict = await verifyExternalRunWithStructuredClaims({
    bundle,
    bundlePath,
    workspace,
    taskClass: 'explanation'
  });

  await writeUtf8(path.join(outputRoot, 'verdict.json'), `${JSON.stringify(verdict, null, 2)}\n`);

  const claimLines = verdict.structured_claims?.results?.map(item =>
    `- ${item.id}: ${item.passed ? 'PASS' : 'BLOCK'} | expected=${JSON.stringify(item.expected)} | observed=${JSON.stringify(item.observed)}`
  ) || [];

  const executor = bundle.executor || {};
  const report = [
    '# AIDE Distributed Browser Run With Structured Claims',
    '',
    `Execution outcome: ${bundle.claim?.status === 'success' ? 'PASS' : 'FAIL'}`,
    `Evidence verification: ${String(verdict.disposition || 'unknown').toUpperCase()}`,
    `Structured claim binding: ${verdict.structured_claims?.passed ? 'PASS' : 'BLOCK'}`,
    `Obscura CLI: ${executor.engine_version || 'unknown'}`,
    `Obscura MCP server: ${executor.mcp_server_version || 'unknown'}`,
    `MCP protocol: ${executor.mcp_protocol_version || 'unknown'}`,
    `Transport: SSH stdio via ${executor.transport_host || 'unknown'}`,
    `Node: ${executor.node || 'unknown'}${executor.tailnet_ip ? ` (${executor.tailnet_ip})` : ''}`,
    '',
    '## Machine-checkable browser claims',
    '',
    ...claimLines,
    '',
    'Free-form task/claim prose is descriptive metadata. Only declarations in `evidence_claims` are presented as machine-verified semantic observations.',
    '',
    '---',
    '',
    renderExternalRunReport(verdict),
    ''
  ].join('\n');

  await writeUtf8(path.join(outputRoot, 'report.md'), report);
  await regenerateManifest(outputRoot);

  console.log(`Structured claim binding: ${verdict.structured_claims?.passed ? 'PASS' : 'BLOCK'}`);
  for (const item of verdict.structured_claims?.results || []) {
    console.log(`  ${item.id}: ${item.passed ? 'PASS' : 'BLOCK'} expected=${JSON.stringify(item.expected)} observed=${JSON.stringify(item.observed)}`);
  }
  console.log(`Final evidence verification: ${verdict.disposition}`);
  console.log(`Final evidence score: ${Math.round(verdict.evidence_score * 100)}%`);
  console.log(`Evidence: ${outputRoot}`);

  if (bundle.claim?.status !== 'success' || verdict.disposition !== 'verified' || !verdict.structured_claims?.passed) {
    process.exitCode = 1;
  }
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
