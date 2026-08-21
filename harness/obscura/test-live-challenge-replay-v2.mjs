import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { SshMcpClient, toolText } from './ssh-mcp-client.mjs';
import { sha256Buffer, sha256Text } from '../external-run/verify.mjs';
import { verifyExternalRunWithStructuredClaims } from '../external-run/verify-structured-claims.mjs';
import { sha256Canonical, verifyExternalRunWithLiveChallenge } from '../external-run/verify-live-challenge.mjs';

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

async function hashFile(file) {
  return sha256Buffer(await fs.readFile(file));
}

function artifact(name, kind, relativePath, sha256) {
  return { name, kind, path: relativePath.replaceAll('\\', '/'), sha256 };
}

function claimsFor({ expectedTitle, expectedUrl, expectedH1 }) {
  return [
    {
      id: 'page-title',
      operator: 'json-equals',
      evidence_path: 'evidence/challenge-observation.json',
      pointer: '/observed/title',
      expected: expectedTitle
    },
    {
      id: 'page-url',
      operator: 'json-equals',
      evidence_path: 'evidence/challenge-observation.json',
      pointer: '/observed/url',
      expected: expectedUrl
    },
    {
      id: 'page-h1',
      operator: 'json-equals',
      evidence_path: 'evidence/challenge-observation.json',
      pointer: '/observed/h1',
      expected: expectedH1
    }
  ];
}

function newChallenge(label, claimContractSha256) {
  const issued = new Date();
  const expires = new Date(issued.getTime() + 10 * 60 * 1000);
  return {
    schema: 'aide.coordinator-challenge/v1',
    task_id: `obscura-challenge-${label}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
    nonce: crypto.randomBytes(32).toString('hex'),
    issued_at: issued.toISOString(),
    expires_at: expires.toISOString(),
    claim_contract_sha256: claimContractSha256
  };
}

async function regenerateManifest(root) {
  const manifestPath = path.join(root, 'manifest.sha256.json');
  await fs.rm(manifestPath, { force: true });
  const entries = [];
  async function walk(dir) {
    for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else entries.push({
        path: path.relative(root, absolute).replaceAll('\\', '/'),
        sha256: await hashFile(absolute)
      });
    }
  }
  await walk(root);
  entries.sort((a, b) => a.path.localeCompare(b.path));
  await writeUtf8(manifestPath, `${JSON.stringify(entries, null, 2)}\n`);
}

async function runLive({
  root,
  workspace,
  host,
  nodeName,
  tailnetIp,
  remoteBinary,
  url,
  expectedTitle,
  expectedH1,
  challenge,
  evidenceClaims
}) {
  const expectedUrl = new URL(url).href;
  const evidenceDir = path.join(root, 'evidence');
  const coordinatorDir = path.join(root, 'coordinator');
  await fs.mkdir(evidenceDir, { recursive: true });
  await fs.mkdir(coordinatorDir, { recursive: true });

  const head = (await git(workspace, ['rev-parse', 'HEAD'])).trim();
  const diffText = await git(workspace, ['diff', '--binary', '--full-index', '--no-ext-diff', `${head}..${head}`, '--']);
  const challengeToken = sha256Canonical(challenge);
  await writeUtf8(path.join(coordinatorDir, 'challenge.json'), `${JSON.stringify(challenge, null, 2)}\n`);

  const startedAt = new Date().toISOString();
  const client = new SshMcpClient({ host, remoteBinary, timeoutMs: 30_000 });
  let initialization;
  let navigate;
  let snapshot;
  let challengeEcho;
  let pageEvaluation;
  let network;
  let missionError = null;

  try {
    initialization = await client.initialize();
    await client.listTools();
    navigate = await client.callTool('browser_navigate', { url, waitUntil: 'load' });
    snapshot = await client.callTool('browser_snapshot', { max_chars: 8000 });

    // Keep freshness proof and page semantics as separate evaluations.
    // The first expression is just a JS string literal, which Obscura returns verbatim.
    challengeEcho = await client.callTool('browser_evaluate', {
      expression: JSON.stringify(challengeToken)
    });

    // This is the same page-observation expression already proven in earlier V3/V4 runs.
    pageEvaluation = await client.callTool('browser_evaluate', {
      expression: 'JSON.stringify({title:document.title,url:location.href,h1:document.querySelector("h1")?.textContent||null})'
    });

    network = await client.callTool('browser_network_requests', {});
    await client.callTool('browser_close', {});
  } catch (error) {
    missionError = error;
  } finally {
    await client.close();
  }

  const finishedAt = new Date().toISOString();
  const transcriptPath = path.join(evidenceDir, 'mcp-transcript.ndjson');
  await writeUtf8(transcriptPath, client.transcript.map(entry => JSON.stringify(entry)).join('\n') + (client.transcript.length ? '\n' : ''));
  if (client.stderr) await writeUtf8(path.join(evidenceDir, 'ssh-stderr.txt'), client.stderr);
  if (initialization) await writeUtf8(path.join(evidenceDir, 'initialize.json'), `${JSON.stringify(initialization, null, 2)}\n`);
  if (navigate) await writeUtf8(path.join(evidenceDir, 'navigate.txt'), `${toolText(navigate)}\n`);
  if (snapshot) await writeUtf8(path.join(evidenceDir, 'snapshot.txt'), `${toolText(snapshot)}\n`);
  if (network) await writeUtf8(path.join(evidenceDir, 'network.txt'), `${toolText(network)}\n`);
  if (missionError) await writeUtf8(path.join(evidenceDir, 'mission-error.txt'), `${missionError.stack || missionError.message}\n`);

  const challengeEchoText = toolText(challengeEcho).trim();
  const pageEvaluationText = toolText(pageEvaluation).trim();
  await writeUtf8(path.join(evidenceDir, 'challenge-echo.txt'), `${challengeEchoText}\n`);
  await writeUtf8(path.join(evidenceDir, 'evaluate.txt'), `${pageEvaluationText}\n`);

  let observed = null;
  try {
    observed = pageEvaluationText ? JSON.parse(pageEvaluationText) : null;
  } catch {}

  const observation = {
    schema: 'aide.browser-challenge-observation/v2',
    source: {
      challenge_tool: 'browser_evaluate',
      page_tool: 'browser_evaluate',
      requested_url: url,
      transcript_path: 'evidence/mcp-transcript.ndjson'
    },
    challenge_echo: challengeEchoText || null,
    observed
  };
  const observationPath = path.join(evidenceDir, 'challenge-observation.json');
  await writeUtf8(observationPath, `${JSON.stringify(observation, null, 2)}\n`);

  const missionPassed = Boolean(
    !missionError &&
    challengeEchoText === challengeToken &&
    observed &&
    observed.title === expectedTitle &&
    observed.url === expectedUrl &&
    observed.h1 === expectedH1
  );

  const missionCheckPath = path.join(evidenceDir, 'mission-check.txt');
  await writeUtf8(missionCheckPath, [
    `challenge-token-match: ${challengeEchoText === challengeToken ? 'PASS' : 'FAIL'}`,
    `page-observation-parsed: ${observed ? 'PASS' : 'FAIL'}`,
    `title-match: ${observed?.title === expectedTitle ? 'PASS' : 'FAIL'}`,
    `url-match: ${observed?.url === expectedUrl ? 'PASS' : 'FAIL'}`,
    `h1-match: ${observed?.h1 === expectedH1 ? 'PASS' : 'FAIL'}`,
    `mission-error: ${missionError ? missionError.message : 'none'}`,
    ''
  ].join('\n'));

  const diffPath = path.join(evidenceDir, 'change.patch');
  await writeUtf8(diffPath, diffText);

  const artifacts = [
    artifact('mcp-transcript', 'mcp-transcript', 'evidence/mcp-transcript.ndjson', await hashFile(transcriptPath)),
    artifact('challenge-echo', 'live-challenge-echo', 'evidence/challenge-echo.txt', await hashFile(path.join(evidenceDir, 'challenge-echo.txt'))),
    artifact('challenge-observation', 'structured-browser-observation', 'evidence/challenge-observation.json', await hashFile(observationPath)),
    artifact('mission-check', 'test-output', 'evidence/mission-check.txt', await hashFile(missionCheckPath)),
    artifact('zero-diff-binding', 'git-diff', 'evidence/change.patch', await hashFile(diffPath))
  ];

  for (const [name, kind, relative] of [
    ['initialize', 'mcp-initialize', 'evidence/initialize.json'],
    ['browser-navigation', 'browser-output', 'evidence/navigate.txt'],
    ['browser-snapshot', 'browser-snapshot', 'evidence/snapshot.txt'],
    ['browser-network', 'browser-network', 'evidence/network.txt'],
    ['browser-evaluation', 'browser-evaluate', 'evidence/evaluate.txt']
  ]) {
    try {
      artifacts.push(artifact(name, kind, relative, await hashFile(path.join(root, relative))));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }

  const bundle = {
    schema: 'aide.external-run/v1',
    task: {
      id: challenge.task_id,
      summary: `Challenge-bound remote Obscura mission against ${url}`
    },
    executor: {
      agent: 'obscura-mcp-over-ssh',
      provider: 'ssh-stdio',
      model: 'none',
      transport_host: host,
      node: nodeName,
      tailnet_ip: tailnetIp,
      engine: 'obscura',
      mcp_server: initialization?.serverInfo?.name || 'unknown',
      mcp_server_version: initialization?.serverInfo?.version || 'unknown',
      mcp_protocol_version: initialization?.protocolVersion || 'unknown'
    },
    timing: { started_at: startedAt, finished_at: finishedAt },
    claim: {
      status: missionPassed ? 'success' : 'failure',
      summary: missionPassed ? 'Live coordinator challenge and page claims were observed during one browser session' : 'Challenge-bound browser mission failed'
    },
    repository: {
      base_commit: head,
      head_commit: head,
      changed_files: [],
      diff_sha256: sha256Text(diffText)
    },
    tests: [{
      name: 'obscura-live-challenge-mission-v2',
      command: `ssh ${host} ${remoteBinary} mcp`,
      exit_code: missionPassed ? 0 : 1,
      output_path: 'evidence/mission-check.txt',
      output_sha256: await hashFile(missionCheckPath)
    }],
    artifacts,
    fallbacks: [],
    evidence_claims: evidenceClaims,
    challenge_binding: {
      schema: 'aide.live-challenge-binding/v1',
      observation_path: 'evidence/challenge-observation.json',
      challenge_pointer: '/challenge_echo',
      transcript_path: 'evidence/mcp-transcript.ndjson'
    }
  };

  const bundlePath = path.join(root, 'bundle.json');
  await writeUtf8(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`);

  const receipt = {
    schema: 'aide.coordinator-receipt/v1',
    task_id: challenge.task_id,
    challenge_token: challengeToken,
    claim_contract_sha256: challenge.claim_contract_sha256,
    transcript_sha256: await hashFile(transcriptPath),
    observation_sha256: await hashFile(observationPath),
    captured_at: finishedAt
  };
  await writeUtf8(path.join(coordinatorDir, 'receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);

  const genericVerdict = await verifyExternalRunWithStructuredClaims({ bundle, bundlePath, workspace, taskClass: 'explanation' });
  const liveVerdict = await verifyExternalRunWithLiveChallenge({
    bundle,
    bundlePath,
    workspace,
    expectedChallenge: challenge,
    coordinatorReceipt: receipt,
    taskClass: 'explanation'
  });

  await writeUtf8(path.join(root, 'verdict-generic.json'), `${JSON.stringify(genericVerdict, null, 2)}\n`);
  await writeUtf8(path.join(root, 'verdict-live-challenge.json'), `${JSON.stringify(liveVerdict, null, 2)}\n`);
  await regenerateManifest(root);

  return {
    root,
    bundle,
    bundlePath,
    challenge,
    challengeToken,
    receipt,
    genericVerdict,
    liveVerdict,
    missionPassed,
    challengeEchoText,
    observed
  };
}

async function copyReplay(sourceRoot, targetRoot) {
  await fs.cp(sourceRoot, targetRoot, { recursive: true, errorOnExist: true, force: false });
  await fs.rm(path.join(targetRoot, 'coordinator'), { recursive: true, force: true });
  await fs.rm(path.join(targetRoot, 'verdict-generic.json'), { force: true });
  await fs.rm(path.join(targetRoot, 'verdict-live-challenge.json'), { force: true });
  await fs.rm(path.join(targetRoot, 'manifest.sha256.json'), { force: true });
}

async function evaluateReplay({ replayRoot, workspace, expectedChallenge, coordinatorReceipt = null }) {
  const bundlePath = path.join(replayRoot, 'bundle.json');
  const bundle = JSON.parse(await fs.readFile(bundlePath, 'utf8'));
  const generic = await verifyExternalRunWithStructuredClaims({ bundle, bundlePath, workspace, taskClass: 'explanation' });
  const live = await verifyExternalRunWithLiveChallenge({
    bundle,
    bundlePath,
    workspace,
    expectedChallenge,
    coordinatorReceipt,
    taskClass: 'explanation'
  });
  await writeUtf8(path.join(replayRoot, 'verdict-generic.json'), `${JSON.stringify(generic, null, 2)}\n`);
  await writeUtf8(path.join(replayRoot, 'verdict-live-challenge.json'), `${JSON.stringify(live, null, 2)}\n`);
  await regenerateManifest(replayRoot);
  return { generic, live };
}

async function main() {
  const host = arg('host', 'headless');
  const nodeName = arg('node', host);
  const tailnetIp = arg('tailnet-ip', null);
  const remoteBinary = arg('remote', '/home/we4free/opt/aide-obscura-v0.2.0/obscura');
  const workspace = path.resolve(arg('workspace', process.cwd()));
  const outputArg = arg('output');
  if (!outputArg) throw new Error('--output is required');
  const outputRoot = path.resolve(outputArg);
  const url = arg('url', 'https://example.com');
  const expectedTitle = arg('expect-title', 'Example Domain');
  const expectedH1 = arg('expect-h1', expectedTitle);
  const expectedUrl = new URL(url).href;

  try {
    await fs.access(outputRoot);
    throw new Error(`output path already exists; refusing to overwrite evidence: ${outputRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before replay experiment');
  await fs.mkdir(outputRoot, { recursive: true });

  const evidenceClaims = claimsFor({ expectedTitle, expectedUrl, expectedH1 });
  const contractHash = sha256Canonical(evidenceClaims);

  console.log('01 fresh live challenge A...');
  const challengeA = newChallenge('a', contractHash);
  const runA = await runLive({
    root: path.join(outputRoot, '01-fresh-a'),
    workspace,
    host,
    nodeName,
    tailnetIp,
    remoteBinary,
    url,
    expectedTitle,
    expectedH1,
    challenge: challengeA,
    evidenceClaims
  });
  console.log(`   mission=${runA.missionPassed ? 'PASS' : 'FAIL'} generic=${runA.genericVerdict.disposition} live=${runA.liveVerdict.disposition}`);

  // Baseline is a prerequisite. Never derive replay conclusions from a broken fresh run.
  if (!runA.missionPassed || runA.genericVerdict.disposition !== 'verified' || runA.liveVerdict.disposition !== 'verified') {
    const baseline = {
      schema: 'aide.obscura-live-challenge-baseline-failure/v1',
      mission_passed: runA.missionPassed,
      generic: runA.genericVerdict.disposition,
      live: runA.liveVerdict.disposition,
      challenge_echo: runA.challengeEchoText || null,
      observed: runA.observed,
      generic_contradictions: runA.genericVerdict.contradictions || [],
      live_contradictions: runA.liveVerdict.contradictions || [],
      generic_missing: runA.genericVerdict.missing_evidence || [],
      live_missing: runA.liveVerdict.missing_evidence || []
    };
    await writeUtf8(path.join(outputRoot, 'baseline-failure.json'), `${JSON.stringify(baseline, null, 2)}\n`);
    await regenerateManifest(outputRoot);
    console.error('Fresh baseline did not verify; replay cases were intentionally NOT executed.');
    process.exitCode = 1;
    return;
  }

  console.log('02 simple replay A under new challenge B...');
  const challengeB = newChallenge('b', contractHash);
  const simpleRoot = path.join(outputRoot, '02-simple-replay-a-as-b');
  await copyReplay(runA.root, simpleRoot);
  {
    const bundlePath = path.join(simpleRoot, 'bundle.json');
    const bundle = JSON.parse(await fs.readFile(bundlePath, 'utf8'));
    // This is deliberately the naive defense: task id + nonce metadata are changed,
    // but the old live observation and transcript remain untouched.
    bundle.task.id = challengeB.task_id;
    bundle.naive_nonce = challengeB.nonce;
    await writeUtf8(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`);
  }
  const simpleReplay = await evaluateReplay({
    replayRoot: simpleRoot,
    workspace,
    expectedChallenge: challengeB,
    coordinatorReceipt: runA.receipt
  });
  console.log(`   generic=${simpleReplay.generic.disposition} live=${simpleReplay.live.disposition}`);

  console.log('03 aggressive post-hoc rewrap A as challenge B...');
  const rewrapRoot = path.join(outputRoot, '03-rewrapped-replay-a-as-b');
  await copyReplay(runA.root, rewrapRoot);
  {
    const bundlePath = path.join(rewrapRoot, 'bundle.json');
    const observationPath = path.join(rewrapRoot, 'evidence', 'challenge-observation.json');
    const transcriptPath = path.join(rewrapRoot, 'evidence', 'mcp-transcript.ndjson');
    const challengeEchoPath = path.join(rewrapRoot, 'evidence', 'challenge-echo.txt');
    const bundle = JSON.parse(await fs.readFile(bundlePath, 'utf8'));
    const observation = JSON.parse(await fs.readFile(observationPath, 'utf8'));
    const tokenB = sha256Canonical(challengeB);

    observation.challenge_echo = tokenB;
    await writeUtf8(observationPath, `${JSON.stringify(observation, null, 2)}\n`);
    await writeUtf8(challengeEchoPath, `${tokenB}\n`);

    const transcript = await fs.readFile(transcriptPath, 'utf8');
    await writeUtf8(transcriptPath, transcript.replaceAll(runA.challengeToken, tokenB));

    bundle.task.id = challengeB.task_id;
    bundle.naive_nonce = challengeB.nonce;
    const issuedMs = Date.parse(challengeB.issued_at);
    bundle.timing.started_at = new Date(issuedMs + 1000).toISOString();
    bundle.timing.finished_at = new Date(issuedMs + 2000).toISOString();

    for (const item of bundle.artifacts || []) {
      if (item.path === 'evidence/challenge-observation.json') item.sha256 = await hashFile(observationPath);
      if (item.path === 'evidence/mcp-transcript.ndjson') item.sha256 = await hashFile(transcriptPath);
      if (item.path === 'evidence/challenge-echo.txt') item.sha256 = await hashFile(challengeEchoPath);
    }
    await writeUtf8(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`);
  }

  const rewrappedReplay = await evaluateReplay({
    replayRoot: rewrapRoot,
    workspace,
    expectedChallenge: challengeB,
    coordinatorReceipt: null
  });
  console.log(`   generic=${rewrappedReplay.generic.disposition} live=${rewrappedReplay.live.disposition}`);

  console.log('04 fresh live execution for challenge B...');
  const runB = await runLive({
    root: path.join(outputRoot, '04-fresh-b'),
    workspace,
    host,
    nodeName,
    tailnetIp,
    remoteBinary,
    url,
    expectedTitle,
    expectedH1,
    challenge: challengeB,
    evidenceClaims
  });
  console.log(`   mission=${runB.missionPassed ? 'PASS' : 'FAIL'} generic=${runB.genericVerdict.disposition} live=${runB.liveVerdict.disposition}`);

  const matrix = {
    schema: 'aide.obscura-live-challenge-replay-matrix/v2',
    results: {
      fresh_a: {
        mission_passed: runA.missionPassed,
        generic: runA.genericVerdict.disposition,
        live_challenge: runA.liveVerdict.disposition
      },
      simple_replay_a_as_b: {
        generic: simpleReplay.generic.disposition,
        live_challenge: simpleReplay.live.disposition
      },
      rewrapped_replay_a_as_b: {
        generic: rewrappedReplay.generic.disposition,
        live_challenge: rewrappedReplay.live.disposition,
        note: 'attacker rewrote challenge echo in observation/transcript and recomputed bundle-local artifact hashes, but has no independent coordinator receipt'
      },
      fresh_b: {
        mission_passed: runB.missionPassed,
        generic: runB.genericVerdict.disposition,
        live_challenge: runB.liveVerdict.disposition
      }
    },
    findings: {
      naive_nonce_defeated: simpleReplay.generic.disposition === 'verified',
      posthoc_rewrap_defeated_generic_integrity_only: rewrappedReplay.generic.disposition === 'verified',
      simple_replay_blocked_by_live_challenge: simpleReplay.live.disposition === 'rejected',
      posthoc_rewrap_not_verified_without_coordinator_receipt: rewrappedReplay.live.disposition !== 'verified',
      fresh_challenge_a_verified: runA.liveVerdict.disposition === 'verified',
      fresh_challenge_b_verified: runB.liveVerdict.disposition === 'verified'
    }
  };

  await writeUtf8(path.join(outputRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);

  const report = [
    '# AIDE × Obscura Live Challenge Replay Matrix V2',
    '',
    `Fresh A: generic=${matrix.results.fresh_a.generic}, live=${matrix.results.fresh_a.live_challenge}`,
    `Simple replay A→B: generic=${matrix.results.simple_replay_a_as_b.generic}, live=${matrix.results.simple_replay_a_as_b.live_challenge}`,
    `Post-hoc rewrap A→B: generic=${matrix.results.rewrapped_replay_a_as_b.generic}, live=${matrix.results.rewrapped_replay_a_as_b.live_challenge}`,
    `Fresh B: generic=${matrix.results.fresh_b.generic}, live=${matrix.results.fresh_b.live_challenge}`,
    '',
    'The generic verifier checks integrity and structured semantics but does not establish freshness. The live challenge verifier additionally requires a coordinator-issued challenge to appear in the live MCP exchange and requires an independent coordinator receipt over the transcript and observation hashes.',
    '',
    'The coordinator receipt still does not prove contact with an external web origin; that is intentionally left for the subsequent consistent-fiction / coordinator-echo falsification experiment.',
    ''
  ].join('\n');
  await writeUtf8(path.join(outputRoot, 'report.md'), report);
  await regenerateManifest(outputRoot);

  const expectations = [
    runA.missionPassed,
    runA.genericVerdict.disposition === 'verified',
    runA.liveVerdict.disposition === 'verified',
    simpleReplay.generic.disposition === 'verified',
    simpleReplay.live.disposition === 'rejected',
    rewrappedReplay.generic.disposition === 'verified',
    rewrappedReplay.live.disposition !== 'verified',
    runB.missionPassed,
    runB.genericVerdict.disposition === 'verified',
    runB.liveVerdict.disposition === 'verified'
  ];

  console.log(`Matrix: ${path.join(outputRoot, 'matrix.json')}`);
  console.log(`Evidence: ${outputRoot}`);
  if (!expectations.every(Boolean)) process.exitCode = 1;
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
