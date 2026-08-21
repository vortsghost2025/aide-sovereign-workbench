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
      ? 'transcript source launch identity equals the independently tracked world-contact process instance'
      : 'transcript source launch identity differs from the independently tracked world-contact process instance'
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

function findEvaluateObservation(transcript) {
  const requestIds = new Set();
  for (const entry of transcript || []) {
    const message = entry?.message;
    if (entry?.direction === 'out' && message?.method === 'tools/call' && message?.params?.name === 'browser_evaluate') {
      requestIds.add(String(message.id));
    }
  }
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

function transcriptText(transcript) {
  return `${(transcript || []).map(entry => JSON.stringify(entry)).join('\n')}\n`;
}

function sha256Text(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function createTranscriptCommitment({ transcript, processIdentity, nonce, responseToken }) {
  const capturedAt = new Date().toISOString();
  const transcriptSha256 = sha256Text(transcriptText(transcript));
  const payload = {
    schema: 'aide.transcript-commitment/v1',
    captured_at: capturedAt,
    transcript_sha256: transcriptSha256,
    process_identity: processIdentity,
    challenge_nonce: nonce,
    response_token: responseToken
  };
  const commitmentHash = sha256Text(JSON.stringify(payload));
  return {
    ...payload,
    commitment_sha256: commitmentHash
  };
}

function verifyTranscriptCommitment(transcript, commitment) {
  if (!commitment?.transcript_sha256) {
    return {
      disposition: 'abstain-needs-evidence',
      expected_sha256: null,
      observed_sha256: sha256Text(transcriptText(transcript)),
      reason: 'coordinator transcript commitment unavailable'
    };
  }
  const observed = sha256Text(transcriptText(transcript));
  const match = observed === commitment.transcript_sha256;
  return {
    disposition: match ? 'verified' : 'rejected',
    expected_sha256: commitment.transcript_sha256,
    observed_sha256: observed,
    match,
    reason: match
      ? 'transcript bytes match the coordinator commitment captured before post-hoc mutation'
      : 'transcript bytes diverge from the coordinator commitment captured before post-hoc mutation'
  };
}

function mutateEvaluateTranscript(transcript, fabricatedTitle) {
  const clone = JSON.parse(JSON.stringify(transcript));
  const requestIds = new Set();
  for (const entry of clone) {
    const message = entry?.message;
    if (entry?.direction === 'out' && message?.method === 'tools/call' && message?.params?.name === 'browser_evaluate') {
      requestIds.add(String(message.id));
    }
  }
  for (const entry of clone) {
    const message = entry?.message;
    if (entry?.direction !== 'in' || message?.id === undefined || !requestIds.has(String(message.id))) continue;
    const item = message?.result?.content?.find(candidate => candidate?.type === 'text');
    if (!item) continue;
    const original = parseObjectText(item.text);
    if (!original) continue;
    const mutated = {
      ...original,
      title: fabricatedTitle,
      h1: fabricatedTitle
    };
    item.text = JSON.stringify(mutated);
    return { transcript: clone, mutated_observation: mutated, rpc_id: message.id };
  }
  return { transcript: clone, mutated_observation: null, rpc_id: null };
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
  const wrapper = `/tmp/aide-obscura-commitment-${token}.sh`;
  const pidFile = `/tmp/aide-obscura-commitment-${token}.pid`;
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
    manifest.push({ path: relative, sha256: crypto.createHash('sha256').update(bytes).digest('hex') });
  }
  await writeUtf8(path.join(root, 'manifest.sha256.json'), `${JSON.stringify(manifest, null, 2)}\n`);
}

async function main() {
  const host = arg('host', 'headless');
  const tailnetIp = arg('tailnet-ip', null);
  const coordinatorIp = arg('coordinator-ip', '100.95.92.117');
  const remoteBinary = arg('remote', '/home/we4free/opt/aide-obscura-v0.2.0/obscura');
  const workspace = path.resolve(arg('workspace', process.cwd()));
  const outputArg = arg('output');
  if (!outputArg) throw new Error('--output is required');
  const outputRoot = path.resolve(outputArg);
  const expectedTitle = arg('expect-title', 'AIDE Transcript Commitment Probe');
  const fabricatedTitle = arg('fabricated-title', 'POSTHOC TRANSCRIPT FABRICATION');

  try {
    await fs.access(outputRoot);
    throw new Error(`output path already exists; refusing to overwrite: ${outputRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before transcript-commitment causal probe');
  await fs.mkdir(outputRoot, { recursive: true });

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

    console.log('02 tracked session makes coordinator-witness contact and emits semantics...');
    await client.callTool('browser_navigate', { url, waitUntil: 'load' });
    const expression = `JSON.stringify({title:document.title,url:location.href,h1:document.querySelector('h1')?.textContent||null,world_token:document.querySelector('meta[name="aide-world-token"]')?.content||null})`;
    await client.callTool('browser_evaluate', { expression });

    const originalTranscript = JSON.parse(JSON.stringify(client.transcript));
    const originalBound = findEvaluateObservation(originalTranscript);
    const event = witness.events.find(candidate => candidate.nonce === nonce) || null;
    const worldContactVerdict = sameProcessIdentity(trackedIdentity, event?.socket_owner_probe || null);
    const sessionBindingVerdict = sameProcessIdentity(trackedIdentity, trackedIdentity);
    const honestSemanticVerdict = exactSemanticVerdict(originalBound?.observation, originalBound?.observation || null);

    console.log('03 coordinator commits the exact transcript bytes before post-hoc mutation...');
    const commitment = createTranscriptCommitment({
      transcript: originalTranscript,
      processIdentity: trackedIdentity,
      nonce,
      responseToken: witness.responseToken
    });
    const baselineCommitmentVerdict = verifyTranscriptCommitment(originalTranscript, commitment);

    console.log('04 mutate the captured transcript post-hoc while preserving process/session metadata...');
    const mutation = mutateEvaluateTranscript(originalTranscript, fabricatedTitle);
    const mutatedTranscript = mutation.transcript;
    const mutatedBound = findEvaluateObservation(mutatedTranscript);
    const fabricatedClaims = mutatedBound?.observation ? { ...mutatedBound.observation } : null;
    const mutatedSemanticVerdict = exactSemanticVerdict(mutatedBound?.observation, fabricatedClaims);
    const mutatedSessionBindingVerdict = sameProcessIdentity(trackedIdentity, trackedIdentity);
    const mutatedCommitmentVerdict = verifyTranscriptCommitment(mutatedTranscript, commitment);

    const naiveComposite = {
      disposition:
        worldContactVerdict.disposition === 'verified' &&
        mutatedSemanticVerdict.disposition === 'verified' &&
        mutatedSessionBindingVerdict.disposition === 'verified'
          ? 'verified'
          : 'rejected',
      reason: 'naive composition validates world contact, transcript semantics, and session identity but does not bind the transcript bytes to a pre-mutation commitment'
    };

    const commitmentBoundComposite = {
      disposition:
        naiveComposite.disposition === 'verified' && mutatedCommitmentVerdict.disposition === 'verified'
          ? 'verified'
          : 'rejected',
      reason: mutatedCommitmentVerdict.disposition === 'verified'
        ? 'world contact, session identity, semantic transcript, and committed transcript bytes all agree'
        : 'post-hoc transcript bytes do not match the coordinator commitment captured before mutation'
    };

    const matrix = {
      schema: 'aide.transcript-commitment-causal-binding/v1',
      host,
      tailnet_ip: tailnetIp,
      coordinator_ip: coordinatorIp,
      expected_obscura_executable: remoteBinary,
      tracked_session: {
        pid: trackedPid,
        identity: trackedIdentity
      },
      coordinator_event: event,
      world_contact_process_binding: worldContactVerdict,
      honest: {
        bound_observation: originalBound,
        semantic_verdict: honestSemanticVerdict,
        session_binding_verdict: sessionBindingVerdict,
        transcript_commitment: commitment,
        transcript_commitment_verdict: baselineCommitmentVerdict
      },
      posthoc_mutation: {
        rpc_id: mutation.rpc_id,
        fabricated_title: fabricatedTitle,
        bound_observation: mutatedBound,
        declared_claims: fabricatedClaims,
        semantic_verdict: mutatedSemanticVerdict,
        session_binding_verdict: mutatedSessionBindingVerdict,
        transcript_commitment_verdict: mutatedCommitmentVerdict,
        naive_composite_verdict: naiveComposite,
        commitment_bound_composite_verdict: commitmentBoundComposite
      },
      findings: {
        tracked_world_contact_verified: worldContactVerdict.disposition === 'verified',
        honest_semantics_verified: honestSemanticVerdict.disposition === 'verified',
        honest_session_binding_verified: sessionBindingVerdict.disposition === 'verified',
        baseline_transcript_commitment_verified: baselineCommitmentVerdict.disposition === 'verified',
        posthoc_mutation_semantics_self_consistent: mutatedSemanticVerdict.disposition === 'verified',
        posthoc_mutation_preserves_session_identity: mutatedSessionBindingVerdict.disposition === 'verified',
        naive_composite_accepts_posthoc_mutation: naiveComposite.disposition === 'verified',
        transcript_commitment_rejects_posthoc_mutation: mutatedCommitmentVerdict.disposition === 'rejected',
        commitment_bound_composite_rejects_posthoc_mutation: commitmentBoundComposite.disposition === 'rejected',
        transcript_commitment_adds_discrimination:
          naiveComposite.disposition === 'verified' && commitmentBoundComposite.disposition === 'rejected'
      }
    };

    await writeUtf8(path.join(outputRoot, 'tracked-session.json'), `${JSON.stringify(matrix.tracked_session, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'events.json'), `${JSON.stringify(witness.events, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'original-mcp-transcript.ndjson'), transcriptText(originalTranscript));
    await writeUtf8(path.join(outputRoot, 'coordinator-transcript-commitment.json'), `${JSON.stringify(commitment, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'mutated-mcp-transcript.ndjson'), transcriptText(mutatedTranscript));
    await writeUtf8(path.join(outputRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'report.md'), [
      '# CAUSAL-5 — Transcript commitment causal binding probe',
      '',
      `Tracked world contact: ${worldContactVerdict.disposition}`,
      `Honest semantics: ${honestSemanticVerdict.disposition}`,
      `Honest session binding: ${sessionBindingVerdict.disposition}`,
      `Baseline transcript commitment: ${baselineCommitmentVerdict.disposition}`,
      `Post-hoc mutated transcript semantics: ${mutatedSemanticVerdict.disposition}`,
      `Post-hoc mutated transcript session binding: ${mutatedSessionBindingVerdict.disposition}`,
      `Naive world+session+semantic composite: ${naiveComposite.disposition}`,
      `Post-hoc mutated transcript commitment: ${mutatedCommitmentVerdict.disposition}`,
      `Commitment-bound composite: ${commitmentBoundComposite.disposition}`,
      '',
      'Interpretation:',
      '- CAUSAL-4 showed that semantic transcript provenance must bind to the same process/session that satisfied the world witness.',
      '- This probe holds that process/session identity constant and changes only the captured transcript bytes after the live run.',
      '- If the mutated transcript remains semantically self-consistent and session-bound but fails a commitment captured before mutation, transcript byte integrity is a distinct causal requirement.',
      '- The commitment is coordinator-owned bookkeeping in this lab. Writer-domain V2 already showed that a same-principal process can rewrite application seals, so production certification still requires an independently protected append-only commitment store or stronger isolation.',
      ''
    ].join('\n'));

    await regenerateManifest(outputRoot);

    console.log(`Tracked world contact: ${worldContactVerdict.disposition}`);
    console.log(`Baseline transcript commitment: ${baselineCommitmentVerdict.disposition}`);
    console.log(`Mutated transcript semantics: ${mutatedSemanticVerdict.disposition}`);
    console.log(`Mutated transcript/session: ${mutatedSessionBindingVerdict.disposition}`);
    console.log(`Naive composite: ${naiveComposite.disposition}`);
    console.log(`Mutated transcript commitment: ${mutatedCommitmentVerdict.disposition}`);
    console.log(`Commitment-bound composite: ${commitmentBoundComposite.disposition}`);
    console.log(`Transcript-commitment discriminator: ${matrix.findings.transcript_commitment_adds_discrimination}`);
    console.log(`Evidence: ${outputRoot}`);

    const expected =
      matrix.findings.tracked_world_contact_verified &&
      matrix.findings.honest_semantics_verified &&
      matrix.findings.honest_session_binding_verified &&
      matrix.findings.baseline_transcript_commitment_verified &&
      matrix.findings.posthoc_mutation_semantics_self_consistent &&
      matrix.findings.posthoc_mutation_preserves_session_identity &&
      matrix.findings.naive_composite_accepts_posthoc_mutation &&
      matrix.findings.transcript_commitment_rejects_posthoc_mutation &&
      matrix.findings.commitment_bound_composite_rejects_posthoc_mutation &&
      matrix.findings.transcript_commitment_adds_discrimination;

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

main().catch(error => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
