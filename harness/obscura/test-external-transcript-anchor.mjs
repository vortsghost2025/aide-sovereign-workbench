import crypto from 'node:crypto';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { SshMcpClient, toolText } from './ssh-mcp-client.mjs';

const execFileAsync = promisify(execFile);

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  if (index < 0) return fallback;
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`--${name} requires a value`);
  return value;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function shQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

async function git(workspace, args, timeout = 120_000) {
  const { stdout } = await execFileAsync('git', args, {
    cwd: workspace,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout,
    windowsHide: true
  });
  return String(stdout).replaceAll('\r\n', '\n');
}

async function ssh(host, command, timeout = 20_000) {
  const { stdout, stderr } = await execFileAsync('ssh', [
    '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host, command
  ], {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
    timeout,
    windowsHide: true
  });
  return { stdout: String(stdout), stderr: String(stderr) };
}

async function writeUtf8(file, text) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, text, 'utf8');
}

function sha256Bytes(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function sha256Text(text) {
  return sha256Bytes(Buffer.from(String(text), 'utf8'));
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = stableValue(value[key]);
    return out;
  }
  return value;
}

function stableStringify(value) {
  return JSON.stringify(stableValue(value));
}

function transcriptText(transcript) {
  return `${(transcript || []).map(entry => JSON.stringify(entry)).join('\n')}\n`;
}

function normalizeAddress(value) {
  if (!value) return null;
  if (value.startsWith('::ffff:')) return value.slice('::ffff:'.length);
  return value;
}

async function inspectPid(host, pid) {
  const script = [
    `pid=${Number(pid)}`,
    'printf "EXE="',
    'readlink -f "/proc/$pid/exe" 2>/dev/null || true',
    'printf "\\nCMD="',
    'tr "\\000" " " < "/proc/$pid/cmdline" 2>/dev/null || true',
    'printf "\\nSTART="',
    'awk "{print \\$22}" "/proc/$pid/stat" 2>/dev/null || true',
    'printf "\\n"'
  ].join('; ');
  const { stdout, stderr } = await ssh(host, script);
  return {
    pid: Number(pid),
    exe: stdout.match(/^EXE=(.*)$/m)?.[1]?.trim() || null,
    cmdline: stdout.match(/^CMD=(.*)$/m)?.[1]?.trim() || null,
    proc_start_ticks: stdout.match(/^START=(.*)$/m)?.[1]?.trim() || null,
    stderr: stderr.trim() || null
  };
}

async function waitForPidFile(host, pidFile, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const { stdout } = await ssh(host, `cat ${shQuote(pidFile)} 2>/dev/null || true`, 5_000);
      const pid = Number(stdout.trim());
      if (Number.isInteger(pid) && pid > 1) return pid;
    } catch {}
    await sleep(100);
  }
  return null;
}

async function observeSocketOwner({ host, sourcePort, destinationPort, expectedRemoteIp }) {
  let snapshot;
  try {
    snapshot = await ssh(host, 'ss -ntpH 2>&1 || true');
  } catch (error) {
    return {
      observed: false,
      disposition: 'abstain-needs-evidence',
      reason: `unable to read socket table: ${error.message || String(error)}`
    };
  }

  const sourceNeedle = `:${sourcePort}`;
  const destinationNeedle = `:${destinationPort}`;
  const lines = snapshot.stdout
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .filter(line => line.includes(sourceNeedle) && line.includes(destinationNeedle));

  const matchedLine = lines.find(line => !expectedRemoteIp || line.includes(expectedRemoteIp)) || lines[0] || null;
  if (!matchedLine) {
    return {
      observed: false,
      disposition: 'abstain-needs-evidence',
      reason: 'coordinator saw the request but no matching held-open remote socket was observed',
      source_port: sourcePort,
      destination_port: destinationPort,
      ss_excerpt: snapshot.stdout.slice(0, 16_384)
    };
  }

  const pidMatch = matchedLine.match(/pid=(\d+)/);
  if (!pidMatch) {
    return {
      observed: false,
      disposition: 'abstain-needs-evidence',
      reason: 'matching socket was observed but process pid was unavailable',
      socket_line: matchedLine
    };
  }

  const identity = await inspectPid(host, Number(pidMatch[1]));
  return {
    observed: Boolean(identity.exe),
    disposition: identity.exe ? 'observed' : 'abstain-needs-evidence',
    reason: identity.exe ? 'matching socket mapped to a live process identity' : 'pid visible but executable identity unavailable',
    source_port: sourcePort,
    destination_port: destinationPort,
    socket_line: matchedLine,
    ...identity
  };
}

function sameProcessIdentity(expected, observed) {
  if (!expected?.exe || !expected?.pid || !expected?.proc_start_ticks || !observed?.exe || !observed?.pid || !observed?.proc_start_ticks) {
    return {
      disposition: 'abstain-needs-evidence',
      exact_executable_match: null,
      exact_pid_match: null,
      proc_start_match: null,
      reason: 'required process identity fields unavailable'
    };
  }
  const exeMatch = expected.exe === observed.exe;
  const pidMatch = expected.pid === observed.pid;
  const startMatch = expected.proc_start_ticks === observed.proc_start_ticks;
  return {
    disposition: exeMatch && pidMatch && startMatch ? 'verified' : 'rejected',
    expected,
    observed,
    exact_executable_match: exeMatch,
    exact_pid_match: pidMatch,
    proc_start_match: startMatch,
    reason: exeMatch && pidMatch && startMatch
      ? 'process identity matches the independently tracked execution instance'
      : 'process identity differs from the independently tracked execution instance'
  };
}

function parseObjectText(text) {
  if (!text) return null;
  const trimmed = String(text).trim();
  try {
    const first = JSON.parse(trimmed);
    if (first && typeof first === 'object') return first;
    if (typeof first === 'string') {
      const second = JSON.parse(first);
      if (second && typeof second === 'object') return second;
    }
  } catch {}
  const match = trimmed.match(/\{[\s\S]*\}/);
  if (!match) return null;
  try {
    const value = JSON.parse(match[0]);
    return value && typeof value === 'object' ? value : null;
  } catch {
    return null;
  }
}

function evaluateRequestIds(transcript) {
  const ids = new Set();
  for (const entry of transcript || []) {
    const message = entry?.message;
    if (entry?.direction === 'out' && message?.method === 'tools/call' && message?.params?.name === 'browser_evaluate') {
      ids.add(String(message.id));
    }
  }
  return ids;
}

function findEvaluateObservation(transcript) {
  const requestIds = evaluateRequestIds(transcript);
  for (const entry of transcript || []) {
    const message = entry?.message;
    if (entry?.direction !== 'in' || message?.id === undefined || !requestIds.has(String(message.id))) continue;
    const text = toolText(message.result);
    const observation = parseObjectText(text);
    if (observation) return { rpc_id: message.id, observation, response_text: text };
  }
  return null;
}

function exactSemanticVerdict(observed, claimed) {
  if (!observed || !claimed) {
    return { disposition: 'abstain-needs-evidence', reason: 'semantic observation or claim unavailable' };
  }
  const keys = ['title', 'url', 'h1', 'world_token'];
  const comparisons = Object.fromEntries(keys.map(key => [key, {
    observed: observed[key] ?? null,
    claimed: claimed[key] ?? null,
    match: (observed[key] ?? null) === (claimed[key] ?? null)
  }]));
  const passed = Object.values(comparisons).every(item => item.match);
  return {
    disposition: passed ? 'verified' : 'rejected',
    comparisons,
    reason: passed ? 'claimed semantics exactly match the selected MCP transcript' : 'claimed semantics diverge from the selected MCP transcript'
  };
}

function mutateEvaluateTranscript(transcript, fabricatedTitle) {
  const clone = JSON.parse(JSON.stringify(transcript || []));
  const requestIds = evaluateRequestIds(clone);
  for (const entry of clone) {
    const message = entry?.message;
    if (entry?.direction !== 'in' || message?.id === undefined || !requestIds.has(String(message.id))) continue;
    const currentText = toolText(message.result);
    const current = parseObjectText(currentText);
    if (!current) continue;
    const mutated = { ...current, title: fabricatedTitle, h1: fabricatedTitle };
    const content = message.result?.content;
    if (!Array.isArray(content)) continue;
    const textItem = content.find(item => item?.type === 'text');
    if (!textItem) continue;
    textItem.text = JSON.stringify(mutated);
    return { transcript: clone, rpc_id: message.id, mutated_observation: mutated };
  }
  return { transcript: clone, rpc_id: null, mutated_observation: null };
}

async function startWitness({ bindIp, host, expectedRemoteIp, expectedTitle }) {
  const events = [];
  const responseToken = crypto.randomBytes(32).toString('hex');
  const server = http.createServer(async (req, res) => {
    try {
      const parsed = new URL(req.url || '/', `http://${req.headers.host || bindIp}`);
      if (parsed.pathname !== '/probe') {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('not found');
        return;
      }
      const nonce = parsed.searchParams.get('n') || '';
      const remoteAddress = normalizeAddress(req.socket.remoteAddress || null);
      const remotePort = req.socket.remotePort || null;
      const localPort = req.socket.localPort || null;
      const event = {
        at: new Date().toISOString(),
        nonce,
        method: req.method || 'GET',
        path: parsed.pathname,
        response_token: responseToken,
        remote_address: remoteAddress,
        remote_port: remotePort,
        local_port: localPort,
        user_agent: req.headers['user-agent'] || null,
        socket_owner_probe: null
      };
      events.push(event);

      if (remotePort && localPort) {
        event.socket_owner_probe = await observeSocketOwner({
          host,
          sourcePort: remotePort,
          destinationPort: localPort,
          expectedRemoteIp
        });
      }

      const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="aide-world-token" content="${responseToken}"><title>${expectedTitle}</title></head><body><h1>${expectedTitle}</h1></body></html>`;
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'content-length': Buffer.byteLength(html),
        'cache-control': 'no-store'
      });
      res.end(html);
    } catch (error) {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end(`witness error: ${error.message || String(error)}`);
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, bindIp, resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('unexpected witness address');
  return {
    events,
    port: address.port,
    responseToken,
    close: () => new Promise(resolve => server.close(resolve))
  };
}

async function installTrackedWrapper(host, remoteBinary) {
  const token = crypto.randomBytes(8).toString('hex');
  const wrapper = `/tmp/aide-obscura-external-anchor-${token}.sh`;
  const pidFile = `/tmp/aide-obscura-external-anchor-${token}.pid`;
  const body = `#!/bin/sh\nprintf '%s\\n' "$$" > ${shQuote(pidFile)}\nexec ${shQuote(remoteBinary)} "$@"\n`;
  const encoded = Buffer.from(body, 'utf8').toString('base64');
  await ssh(host, `printf %s ${shQuote(encoded)} | base64 -d > ${shQuote(wrapper)} && chmod 700 ${shQuote(wrapper)}`);
  return { wrapper, pidFile };
}

async function regenerateManifest(root) {
  const files = [];
  async function walk(dir) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile()) files.push(absolute);
    }
  }
  await walk(root);
  const manifest = [];
  for (const absolute of files) {
    const relative = path.relative(root, absolute).replaceAll('\\', '/');
    if (relative === 'manifest.sha256.json') continue;
    const bytes = await fs.readFile(absolute);
    manifest.push({ path: relative, sha256: sha256Bytes(bytes) });
  }
  await writeUtf8(path.join(root, 'manifest.sha256.json'), `${JSON.stringify(manifest, null, 2)}\n`);
}

function createAnchorRequest({ sourceCommit, transcript, processIdentity, challengeNonce, responseToken, coordinatorEvent, semanticObservation }) {
  const body = {
    schema: 'aide.external-transcript-anchor-request/v1',
    captured_at: new Date().toISOString(),
    source_commit: sourceCommit,
    transcript_sha256: sha256Text(transcriptText(transcript)),
    process_identity: processIdentity,
    process_identity_sha256: sha256Text(stableStringify(processIdentity)),
    challenge_nonce: challengeNonce,
    response_token: responseToken,
    world_event_sha256: sha256Text(stableStringify(coordinatorEvent)),
    semantic_observation_sha256: sha256Text(stableStringify(semanticObservation))
  };
  return {
    ...body,
    request_sha256: sha256Text(stableStringify(body))
  };
}

function verifyAnchorRequest(request) {
  if (!request || request.schema !== 'aide.external-transcript-anchor-request/v1') {
    return { disposition: 'rejected', reason: 'anchor request schema missing or unsupported' };
  }
  const { request_sha256: declared, ...body } = request;
  const observed = sha256Text(stableStringify(body));
  return {
    disposition: declared === observed ? 'verified' : 'rejected',
    declared_sha256: declared || null,
    observed_sha256: observed,
    match: declared === observed,
    reason: declared === observed ? 'anchor request bytes match their self-digest' : 'anchor request bytes diverge from their declared digest'
  };
}

function createLocalCommitment(transcript, request) {
  const body = {
    schema: 'aide.local-rewritable-transcript-commitment/v1',
    captured_at: new Date().toISOString(),
    transcript_sha256: sha256Text(transcriptText(transcript)),
    process_identity: request.process_identity,
    challenge_nonce: request.challenge_nonce,
    response_token: request.response_token
  };
  return { ...body, commitment_sha256: sha256Text(stableStringify(body)) };
}

function verifyLocalCommitment(transcript, commitment) {
  const transcriptHash = sha256Text(transcriptText(transcript));
  const { commitment_sha256: declaredCommitment, ...body } = commitment || {};
  const observedCommitment = sha256Text(stableStringify(body));
  const transcriptMatch = Boolean(commitment) && transcriptHash === commitment.transcript_sha256;
  const commitmentMatch = Boolean(commitment) && declaredCommitment === observedCommitment;
  return {
    disposition: transcriptMatch && commitmentMatch ? 'verified' : 'rejected',
    transcript_match: transcriptMatch,
    commitment_match: commitmentMatch,
    expected_transcript_sha256: commitment?.transcript_sha256 || null,
    observed_transcript_sha256: transcriptHash,
    reason: transcriptMatch && commitmentMatch
      ? 'transcript matches the locally rewritten commitment'
      : 'transcript or commitment digest does not match the local commitment'
  };
}

function verifyExternalAnchorAgainstPrepare(anchor, request, originalTranscript) {
  if (!anchor || anchor.schema !== 'aide.external-transcript-anchor/v1') {
    return { disposition: 'rejected', reason: 'external anchor schema missing or unsupported' };
  }
  const checks = {
    request_sha256: anchor.anchor_request_sha256 === request.request_sha256,
    transcript_sha256: anchor.transcript_sha256 === sha256Text(transcriptText(originalTranscript)),
    source_commit: anchor.source_commit === request.source_commit,
    challenge_nonce: anchor.challenge_nonce === request.challenge_nonce,
    response_token: anchor.response_token === request.response_token,
    process_identity_sha256: anchor.process_identity_sha256 === request.process_identity_sha256,
    world_event_sha256: anchor.world_event_sha256 === request.world_event_sha256,
    semantic_observation_sha256: anchor.semantic_observation_sha256 === request.semantic_observation_sha256
  };
  const passed = Object.values(checks).every(Boolean);
  return {
    disposition: passed ? 'verified' : 'rejected',
    checks,
    reason: passed ? 'pinned external anchor matches the prepared run commitment' : 'pinned external anchor does not match the prepared run commitment'
  };
}

function verifyExternalAnchorAgainstTranscript(anchor, transcript) {
  if (!anchor?.transcript_sha256) {
    return { disposition: 'abstain-needs-evidence', reason: 'external anchor transcript hash unavailable' };
  }
  const observed = sha256Text(transcriptText(transcript));
  const match = observed === anchor.transcript_sha256;
  return {
    disposition: match ? 'verified' : 'rejected',
    expected_sha256: anchor.transcript_sha256,
    observed_sha256: observed,
    match,
    reason: match ? 'transcript bytes match the pinned external anchor' : 'transcript bytes diverge from the pinned external anchor'
  };
}

async function preparePhase({ host, tailnetIp, coordinatorIp, remoteBinary, workspace, outputRoot, expectedTitle }) {
  try {
    await fs.access(outputRoot);
    throw new Error(`output path already exists; refusing to overwrite: ${outputRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before external-anchor prepare phase');
  await fs.mkdir(path.join(outputRoot, 'prepare'), { recursive: true });

  const sourceCommit = (await git(workspace, ['rev-parse', 'HEAD'])).trim();
  const tracked = await installTrackedWrapper(host, remoteBinary);
  const witness = await startWitness({
    bindIp: coordinatorIp,
    host,
    expectedRemoteIp: tailnetIp,
    expectedTitle
  });

  const nonce = crypto.randomBytes(32).toString('hex');
  const url = `http://${coordinatorIp}:${witness.port}/probe?n=${nonce}`;
  let client;

  try {
    console.log('01 start independently tracked Obscura MCP session...');
    client = new SshMcpClient({ host, remoteBinary: tracked.wrapper, timeoutMs: 45_000 });
    await client.initialize();
    await client.listTools();

    const trackedPid = await waitForPidFile(host, tracked.pidFile);
    const trackedIdentity = trackedPid ? await inspectPid(host, trackedPid) : null;
    console.log(`   tracked pid=${trackedPid || 'unavailable'} exe=${trackedIdentity?.exe || 'unavailable'}`);

    console.log('02 tracked session makes world-witness contact and emits semantics...');
    await client.callTool('browser_navigate', { url, waitUntil: 'load' });
    const expression = `JSON.stringify({title:document.title,url:location.href,h1:document.querySelector('h1')?.textContent||null,world_token:document.querySelector('meta[name="aide-world-token"]')?.content||null})`;
    await client.callTool('browser_evaluate', { expression });

    const transcript = JSON.parse(JSON.stringify(client.transcript));
    const bound = findEvaluateObservation(transcript);
    const event = witness.events.find(candidate => candidate.nonce === nonce) || null;
    const worldVerdict = sameProcessIdentity(trackedIdentity, event?.socket_owner_probe || null);
    const semanticVerdict = exactSemanticVerdict(bound?.observation, bound?.observation || null);

    console.log('03 create anchor request but do not mutate transcript...');
    const request = createAnchorRequest({
      sourceCommit,
      transcript,
      processIdentity: trackedIdentity,
      challengeNonce: nonce,
      responseToken: witness.responseToken,
      coordinatorEvent: event,
      semanticObservation: bound?.observation || null
    });
    const requestVerdict = verifyAnchorRequest(request);

    const matrix = {
      schema: 'aide.external-transcript-anchor-prepare/v1',
      host,
      tailnet_ip: tailnetIp,
      coordinator_ip: coordinatorIp,
      source_commit: sourceCommit,
      tracked_process: trackedIdentity,
      coordinator_event: event,
      world_contact_process_binding: worldVerdict,
      bound_observation: bound,
      semantic_verdict: semanticVerdict,
      anchor_request: request,
      anchor_request_verdict: requestVerdict,
      findings: {
        tracked_world_contact_verified: worldVerdict.disposition === 'verified',
        transcript_semantics_verified: semanticVerdict.disposition === 'verified',
        anchor_request_self_digest_verified: requestVerdict.disposition === 'verified',
        transcript_left_unmodified_for_external_anchor: true
      }
    };

    const prepareRoot = path.join(outputRoot, 'prepare');
    await writeUtf8(path.join(prepareRoot, 'tracked-session.json'), `${JSON.stringify({ pid: trackedPid, identity: trackedIdentity }, null, 2)}\n`);
    await writeUtf8(path.join(prepareRoot, 'events.json'), `${JSON.stringify(witness.events, null, 2)}\n`);
    await writeUtf8(path.join(prepareRoot, 'original-mcp-transcript.ndjson'), transcriptText(transcript));
    await writeUtf8(path.join(prepareRoot, 'anchor-request.json'), `${JSON.stringify(request, null, 2)}\n`);
    await writeUtf8(path.join(prepareRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
    await writeUtf8(path.join(prepareRoot, 'report.md'), [
      '# CAUSAL-6A — External transcript anchor prepare',
      '',
      `Tracked world contact: ${worldVerdict.disposition}`,
      `Transcript semantics: ${semanticVerdict.disposition}`,
      `Anchor request self-digest: ${requestVerdict.disposition}`,
      '',
      'Interpretation:',
      '- This phase captures a live Obscura transcript and emits a deterministic anchor request before any adversarial transcript mutation.',
      '- It intentionally stops before mutation so an out-of-band control plane can publish the request digest/transcript hash into a content-addressed external commit object.',
      '- No claim of writer isolation is made yet. The next phase must pin an exact external commit SHA supplied by the control plane and then attempt same-principal local re-sealing.',
      ''
    ].join('\n'));
    await regenerateManifest(prepareRoot);

    console.log(`Tracked world contact: ${worldVerdict.disposition}`);
    console.log(`Transcript semantics: ${semanticVerdict.disposition}`);
    console.log(`Anchor request self-digest: ${requestVerdict.disposition}`);
    console.log(`Anchor request SHA256: ${request.request_sha256}`);
    console.log(`Transcript SHA256: ${request.transcript_sha256}`);
    console.log(`Challenge nonce: ${request.challenge_nonce}`);
    console.log(`Evidence: ${outputRoot}`);

    const expected =
      matrix.findings.tracked_world_contact_verified &&
      matrix.findings.transcript_semantics_verified &&
      matrix.findings.anchor_request_self_digest_verified;
    if (!expected) process.exitCode = 1;
  } finally {
    if (client) {
      await client.callTool('browser_close', {}).catch(() => undefined);
      await client.close().catch(() => undefined);
    }
    await witness.close().catch(() => undefined);
    await ssh(host, `rm -f ${shQuote(tracked.wrapper)} ${shQuote(tracked.pidFile)}`, 10_000).catch(() => undefined);
  }
}

async function verifyPhase({ workspace, outputRoot, fabricatedTitle, anchorRemote, anchorRef, anchorCommit, anchorPath }) {
  const prepareRoot = path.join(outputRoot, 'prepare');
  const verifyRoot = path.join(outputRoot, 'verify');
  await fs.access(path.join(prepareRoot, 'anchor-request.json'));
  await fs.access(path.join(prepareRoot, 'original-mcp-transcript.ndjson'));
  try {
    await fs.access(verifyRoot);
    throw new Error(`verify path already exists; refusing to overwrite: ${verifyRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before external-anchor verify phase');
  if (!anchorCommit || !anchorPath) throw new Error('--anchor-commit and --anchor-path are required for verify phase');

  console.log('01 fetch external anchor ref and require the exact pinned commit...');
  if (anchorRef) await git(workspace, ['fetch', '--no-tags', anchorRemote, anchorRef]);
  await git(workspace, ['cat-file', '-e', `${anchorCommit}^{commit}`]);
  const anchorText = await git(workspace, ['show', `${anchorCommit}:${anchorPath}`]);
  const anchor = JSON.parse(anchorText);

  console.log('02 verify prepared bytes against the pinned external anchor...');
  const request = JSON.parse(await fs.readFile(path.join(prepareRoot, 'anchor-request.json'), 'utf8'));
  const originalTranscript = (await fs.readFile(path.join(prepareRoot, 'original-mcp-transcript.ndjson'), 'utf8'))
    .split(/\r?\n/)
    .filter(Boolean)
    .map(line => JSON.parse(line));
  const requestVerdict = verifyAnchorRequest(request);
  const originalAnchorVerdict = verifyExternalAnchorAgainstPrepare(anchor, request, originalTranscript);
  const originalTranscriptVerdict = verifyExternalAnchorAgainstTranscript(anchor, originalTranscript);

  console.log('03 mutate transcript post-hoc while preserving the prepared process/session metadata...');
  const mutation = mutateEvaluateTranscript(originalTranscript, fabricatedTitle);
  const mutatedTranscript = mutation.transcript;
  const mutatedBound = findEvaluateObservation(mutatedTranscript);
  const mutatedClaims = mutatedBound?.observation ? { ...mutatedBound.observation } : null;
  const mutatedSemanticVerdict = exactSemanticVerdict(mutatedBound?.observation, mutatedClaims);
  const sameSessionVerdict = sameProcessIdentity(request.process_identity, request.process_identity);

  console.log('04 rewrite a local commitment for the mutated transcript...');
  const rewrittenLocalCommitment = createLocalCommitment(mutatedTranscript, request);
  const rewrittenLocalVerdict = verifyLocalCommitment(mutatedTranscript, rewrittenLocalCommitment);
  const naiveLocalResealComposite = {
    disposition:
      mutatedSemanticVerdict.disposition === 'verified' &&
      sameSessionVerdict.disposition === 'verified' &&
      rewrittenLocalVerdict.disposition === 'verified'
        ? 'verified'
        : 'rejected',
    reason: 'same-principal local re-seal accepts the mutated transcript when no pinned external anchor is consulted'
  };

  console.log('05 compare the mutated transcript to the pinned external commit anchor...');
  const mutatedExternalVerdict = verifyExternalAnchorAgainstTranscript(anchor, mutatedTranscript);
  const externalAnchorComposite = {
    disposition:
      naiveLocalResealComposite.disposition === 'verified' && mutatedExternalVerdict.disposition === 'verified'
        ? 'verified'
        : 'rejected',
    reason: mutatedExternalVerdict.disposition === 'verified'
      ? 'mutated transcript still matches the pinned external anchor'
      : 'mutated transcript was locally re-sealed but diverges from the transcript hash pinned in the exact external commit object'
  };

  const matrix = {
    schema: 'aide.external-transcript-anchor-verify/v1',
    anchor: {
      remote: anchorRemote,
      ref: anchorRef || null,
      commit: anchorCommit,
      path: anchorPath,
      document: anchor
    },
    anchor_request_verdict: requestVerdict,
    original_external_anchor_verdict: originalAnchorVerdict,
    original_transcript_external_anchor_verdict: originalTranscriptVerdict,
    posthoc_mutation: {
      rpc_id: mutation.rpc_id,
      fabricated_title: fabricatedTitle,
      bound_observation: mutatedBound,
      semantic_verdict: mutatedSemanticVerdict,
      session_binding_verdict: sameSessionVerdict,
      rewritten_local_commitment: rewrittenLocalCommitment,
      rewritten_local_commitment_verdict: rewrittenLocalVerdict,
      naive_local_reseal_composite_verdict: naiveLocalResealComposite,
      external_anchor_transcript_verdict: mutatedExternalVerdict,
      external_anchor_composite_verdict: externalAnchorComposite
    },
    findings: {
      anchor_request_self_digest_verified: requestVerdict.disposition === 'verified',
      pinned_external_anchor_matches_prepared_run: originalAnchorVerdict.disposition === 'verified',
      original_transcript_matches_external_anchor: originalTranscriptVerdict.disposition === 'verified',
      posthoc_mutation_semantics_self_consistent: mutatedSemanticVerdict.disposition === 'verified',
      posthoc_mutation_preserves_session_identity_metadata: sameSessionVerdict.disposition === 'verified',
      same_principal_local_reseal_accepts_mutation: rewrittenLocalVerdict.disposition === 'verified',
      naive_local_reseal_composite_accepts_mutation: naiveLocalResealComposite.disposition === 'verified',
      pinned_external_anchor_rejects_mutated_transcript: mutatedExternalVerdict.disposition === 'rejected',
      external_anchor_composite_rejects_mutation: externalAnchorComposite.disposition === 'rejected',
      external_content_addressed_anchor_adds_discrimination:
        naiveLocalResealComposite.disposition === 'verified' && externalAnchorComposite.disposition === 'rejected'
    }
  };

  await fs.mkdir(verifyRoot, { recursive: true });
  await writeUtf8(path.join(verifyRoot, 'external-anchor.json'), `${JSON.stringify(anchor, null, 2)}\n`);
  await writeUtf8(path.join(verifyRoot, 'mutated-mcp-transcript.ndjson'), transcriptText(mutatedTranscript));
  await writeUtf8(path.join(verifyRoot, 'rewritten-local-commitment.json'), `${JSON.stringify(rewrittenLocalCommitment, null, 2)}\n`);
  await writeUtf8(path.join(verifyRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
  await writeUtf8(path.join(verifyRoot, 'report.md'), [
    '# CAUSAL-6B — External transcript anchor verification',
    '',
    `Pinned external anchor matches prepared run: ${originalAnchorVerdict.disposition}`,
    `Original transcript vs external anchor: ${originalTranscriptVerdict.disposition}`,
    `Mutated transcript semantics: ${mutatedSemanticVerdict.disposition}`,
    `Mutated transcript/session metadata: ${sameSessionVerdict.disposition}`,
    `Rewritten local commitment: ${rewrittenLocalVerdict.disposition}`,
    `Naive local re-seal composite: ${naiveLocalResealComposite.disposition}`,
    `Mutated transcript vs pinned external anchor: ${mutatedExternalVerdict.disposition}`,
    `External-anchor-bound composite: ${externalAnchorComposite.disposition}`,
    '',
    'Interpretation:',
    '- Writer-domain V2 showed that same-principal application seals can be rewritten. CAUSAL-5 showed that a pre-mutation transcript commitment detects post-hoc transcript rewriting if the commitment itself is trusted.',
    '- This two-phase probe moves the pre-mutation transcript hash into an exact content-addressed Git commit before the mutation phase proceeds.',
    '- A same-principal local re-seal can still accept the fabricated transcript, while comparison to the pinned external commit should reject different transcript bytes.',
    '- This proves only content immutability of the exact pinned external commit object in this lab. It does not prove independent writer authorization: if the executor is allowed to choose a different anchor commit, anchor substitution remains a separate threat and must be bound by the coordinator/verifier.',
    ''
  ].join('\n'));
  await regenerateManifest(verifyRoot);

  console.log(`Pinned external anchor baseline: ${originalAnchorVerdict.disposition}`);
  console.log(`Mutated transcript semantics: ${mutatedSemanticVerdict.disposition}`);
  console.log(`Rewritten local commitment: ${rewrittenLocalVerdict.disposition}`);
  console.log(`Naive local re-seal composite: ${naiveLocalResealComposite.disposition}`);
  console.log(`Mutated transcript external anchor: ${mutatedExternalVerdict.disposition}`);
  console.log(`External-anchor composite: ${externalAnchorComposite.disposition}`);
  console.log(`External-anchor discriminator: ${matrix.findings.external_content_addressed_anchor_adds_discrimination}`);
  console.log(`Evidence: ${outputRoot}`);

  const expected =
    matrix.findings.anchor_request_self_digest_verified &&
    matrix.findings.pinned_external_anchor_matches_prepared_run &&
    matrix.findings.original_transcript_matches_external_anchor &&
    matrix.findings.posthoc_mutation_semantics_self_consistent &&
    matrix.findings.posthoc_mutation_preserves_session_identity_metadata &&
    matrix.findings.same_principal_local_reseal_accepts_mutation &&
    matrix.findings.naive_local_reseal_composite_accepts_mutation &&
    matrix.findings.pinned_external_anchor_rejects_mutated_transcript &&
    matrix.findings.external_anchor_composite_rejects_mutation &&
    matrix.findings.external_content_addressed_anchor_adds_discrimination;
  if (!expected) process.exitCode = 1;
}

async function main() {
  const phase = arg('phase', 'prepare');
  const host = arg('host', 'headless');
  const tailnetIp = arg('tailnet-ip', null);
  const coordinatorIp = arg('coordinator-ip', '100.95.92.117');
  const remoteBinary = arg('remote', '/home/we4free/opt/aide-obscura-v0.2.0/obscura');
  const workspace = path.resolve(arg('workspace', process.cwd()));
  const outputArg = arg('output');
  if (!outputArg) throw new Error('--output is required');
  const outputRoot = path.resolve(outputArg);
  const expectedTitle = arg('expect-title', 'AIDE External Anchor Probe');
  const fabricatedTitle = arg('fabricated-title', 'POSTHOC EXTERNAL-ANCHOR FABRICATION');
  const anchorRemote = arg('anchor-remote', 'fork');
  const anchorRef = arg('anchor-ref', null);
  const anchorCommit = arg('anchor-commit', null);
  const anchorPath = arg('anchor-path', null);

  if (phase === 'prepare') {
    await preparePhase({
      host,
      tailnetIp,
      coordinatorIp,
      remoteBinary,
      workspace,
      outputRoot,
      expectedTitle
    });
    return;
  }

  if (phase === 'verify') {
    await verifyPhase({
      workspace,
      outputRoot,
      fabricatedTitle,
      anchorRemote,
      anchorRef,
      anchorCommit,
      anchorPath
    });
    return;
  }

  throw new Error(`unsupported --phase ${phase}; expected prepare or verify`);
}

main().catch(error => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
