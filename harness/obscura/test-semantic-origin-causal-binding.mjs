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

function classifyInstanceBound(probe, expectedIdentity) {
  if (!probe?.observed || !probe.exe || !expectedIdentity?.pid || !expectedIdentity?.exe) {
    return {
      disposition: 'abstain-needs-evidence',
      reason: 'required process-instance observation was unavailable'
    };
  }
  const exeMatch = probe.exe === expectedIdentity.exe;
  const pidMatch = probe.pid === expectedIdentity.pid;
  const startMatch = probe.proc_start_ticks && expectedIdentity.proc_start_ticks
    ? probe.proc_start_ticks === expectedIdentity.proc_start_ticks
    : null;
  const verified = exeMatch && pidMatch && startMatch !== false;
  return {
    disposition: verified ? 'verified' : 'rejected',
    expected_executable: expectedIdentity.exe,
    expected_pid: expectedIdentity.pid,
    expected_proc_start_ticks: expectedIdentity.proc_start_ticks,
    observed_executable: probe.exe,
    observed_pid: probe.pid,
    observed_proc_start_ticks: probe.proc_start_ticks,
    exact_executable_match: exeMatch,
    exact_pid_match: pidMatch,
    proc_start_match: startMatch,
    reason: verified
      ? 'witness connection belongs to the exact independently tracked Obscura process instance'
      : 'witness connection does not belong to the exact independently tracked Obscura process instance'
  };
}

function parseObjectText(text) {
  const trimmed = String(text || '').trim();
  if (!trimmed) return null;
  const attempts = [trimmed];
  const firstBrace = trimmed.indexOf('{');
  const lastBrace = trimmed.lastIndexOf('}');
  if (firstBrace >= 0 && lastBrace > firstBrace) attempts.push(trimmed.slice(firstBrace, lastBrace + 1));
  for (const candidate of attempts) {
    try {
      let value = JSON.parse(candidate);
      if (typeof value === 'string') value = JSON.parse(value);
      if (value && typeof value === 'object' && !Array.isArray(value)) return value;
    } catch {}
  }
  return null;
}

function exactSemanticVerdict(observed, claimed) {
  if (!observed || !claimed) {
    return {
      disposition: 'abstain-needs-evidence',
      reason: 'semantic observation unavailable'
    };
  }
  const fields = ['title', 'url', 'h1', 'world_token'];
  const comparisons = Object.fromEntries(fields.map(field => [field, {
    observed: observed[field] ?? null,
    claimed: claimed[field] ?? null,
    match: (observed[field] ?? null) === (claimed[field] ?? null)
  }]));
  const passed = fields.every(field => comparisons[field].match);
  return {
    disposition: passed ? 'verified' : 'rejected',
    comparisons,
    reason: passed
      ? 'claimed semantics exactly match the bound MCP evaluate result'
      : 'claimed semantics diverge from the bound MCP evaluate result'
  };
}

function detachedSemanticVerdict(observation, claims) {
  if (!observation || !claims) {
    return { disposition: 'abstain-needs-evidence', reason: 'detached observation or claims missing' };
  }
  const fields = ['title', 'url', 'h1', 'world_token'];
  const passed = fields.every(field => (observation[field] ?? null) === (claims[field] ?? null));
  return {
    disposition: passed ? 'verified' : 'rejected',
    reason: passed
      ? 'detached observation bytes are self-consistent with the declared claims'
      : 'detached observation bytes contradict the declared claims'
  };
}

function findBoundEvaluateObservation(transcript) {
  for (const entry of transcript || []) {
    if (entry?.direction !== 'out') continue;
    const message = entry.message || {};
    if (message.method !== 'tools/call') continue;
    if (message.params?.name !== 'browser_evaluate') continue;
    const id = message.id;
    const inbound = (transcript || []).find(candidate =>
      candidate?.direction === 'in' && candidate?.message?.id === id
    );
    const text = inbound?.message?.result?.content?.find(item => item?.type === 'text')?.text || '';
    const parsed = parseObjectText(text);
    if (parsed) return { rpc_id: id, observation: parsed, response_text: text };
  }
  return null;
}

async function startWitness({ bindIp, host, expectedRemoteIp, expectedTitle }) {
  const events = [];
  const server = http.createServer(async (req, res) => {
    try {
      const parsed = new URL(req.url || '/', `http://${req.headers.host || bindIp}`);
      if (parsed.pathname !== '/probe') {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('not found');
        return;
      }

      const nonce = parsed.searchParams.get('n') || '';
      const responseToken = crypto.randomBytes(32).toString('hex');
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
      } else {
        event.socket_owner_probe = {
          observed: false,
          disposition: 'abstain-needs-evidence',
          reason: 'socket endpoint ports unavailable'
        };
      }

      const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="aide-world-token" content="${responseToken}"><title>${expectedTitle}</title></head><body><h1>${expectedTitle}</h1><p>${nonce}</p></body></html>`;
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
  return { events, port: address.port, close: () => new Promise(resolve => server.close(resolve)) };
}

async function installTrackedWrapper(host, remoteBinary) {
  const token = crypto.randomBytes(8).toString('hex');
  const wrapper = `/tmp/aide-obscura-semantic-${token}.sh`;
  const pidFile = `/tmp/aide-obscura-semantic-${token}.pid`;
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
  const expectedTitle = arg('expect-title', 'AIDE Semantic Origin Probe');
  const fabricatedTitle = arg('fabricated-title', 'FABRICATED SEMANTIC CLAIM');

  try {
    await fs.access(outputRoot);
    throw new Error(`output path already exists; refusing to overwrite: ${outputRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before semantic-origin causal probe');
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
    console.log('01 start independently tracked Obscura MCP process...');
    client = new SshMcpClient({ host, remoteBinary: tracked.wrapper, timeoutMs: 45_000 });
    await client.initialize();
    await client.listTools();

    const intendedPid = await waitForPidFile(host, tracked.pidFile);
    const intendedIdentity = intendedPid ? await inspectPid(host, intendedPid) : null;
    console.log(`   tracked pid=${intendedPid || 'unavailable'} exe=${intendedIdentity?.exe || 'unavailable'}`);

    console.log('02 tracked process contacts coordinator witness...');
    await client.callTool('browser_navigate', { url, waitUntil: 'load' });

    console.log('03 capture semantics through the same tracked MCP process...');
    const expression = `JSON.stringify({title:document.title,url:location.href,h1:document.querySelector('h1')?.textContent||null,world_token:document.querySelector('meta[name="aide-world-token"]')?.content||null})`;
    const evaluateResult = await client.callTool('browser_evaluate', { expression });
    const directObservation = parseObjectText(toolText(evaluateResult));
    const transcriptSnapshot = JSON.parse(JSON.stringify(client.transcript));
    const transcriptBound = findBoundEvaluateObservation(transcriptSnapshot);

    const event = witness.events.find(candidate => candidate.nonce === nonce) || null;
    const instanceVerdict = classifyInstanceBound(event?.socket_owner_probe, intendedIdentity);

    const honestClaims = directObservation ? { ...directObservation } : null;
    const honestDetached = detachedSemanticVerdict(directObservation, honestClaims);
    const honestTranscript = exactSemanticVerdict(transcriptBound?.observation, honestClaims);

    const fabricatedObservation = directObservation ? {
      ...directObservation,
      title: fabricatedTitle,
      h1: fabricatedTitle
    } : null;
    const fabricatedClaims = fabricatedObservation ? { ...fabricatedObservation } : null;
    const fabricatedDetached = detachedSemanticVerdict(fabricatedObservation, fabricatedClaims);
    const fabricatedTranscript = exactSemanticVerdict(transcriptBound?.observation, fabricatedClaims);

    const matrix = {
      schema: 'aide.semantic-origin-causal-binding/v1',
      host,
      tailnet_ip: tailnetIp,
      coordinator_ip: coordinatorIp,
      expected_obscura_executable: remoteBinary,
      tracked_process: {
        pid: intendedPid,
        identity: intendedIdentity
      },
      coordinator_event: event,
      process_instance_verdict: instanceVerdict,
      honest: {
        direct_observation: directObservation,
        transcript_bound_observation: transcriptBound,
        detached_semantic_verdict: honestDetached,
        transcript_semantic_verdict: honestTranscript
      },
      fabricated_semantics: {
        fabricated_observation: fabricatedObservation,
        declared_claims: fabricatedClaims,
        detached_semantic_verdict: fabricatedDetached,
        same_process_instance_world_contact_verdict: instanceVerdict,
        transcript_semantic_verdict: fabricatedTranscript
      },
      findings: {
        tracked_process_world_contact_verified: instanceVerdict.disposition === 'verified',
        honest_semantics_bound_to_same_mcp_transcript: honestTranscript.disposition === 'verified',
        fabricated_semantics_self_consistent_detached: fabricatedDetached.disposition === 'verified',
        fabricated_semantics_would_coexist_with_verified_same_process_world_contact:
          fabricatedDetached.disposition === 'verified' && instanceVerdict.disposition === 'verified',
        transcript_binding_rejects_fabricated_semantics: fabricatedTranscript.disposition === 'rejected',
        semantic_origin_binding_adds_discrimination:
          fabricatedDetached.disposition === 'verified' &&
          instanceVerdict.disposition === 'verified' &&
          fabricatedTranscript.disposition === 'rejected'
      }
    };

    await writeUtf8(path.join(outputRoot, 'tracked-process.json'), `${JSON.stringify({ intended_pid: intendedPid, identity: intendedIdentity }, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'events.json'), `${JSON.stringify(witness.events, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'mcp-transcript.ndjson'), `${transcriptSnapshot.map(entry => JSON.stringify(entry)).join('\n')}\n`);
    await writeUtf8(path.join(outputRoot, 'honest-observation.json'), `${JSON.stringify(directObservation, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'fabricated-observation.json'), `${JSON.stringify(fabricatedObservation, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'report.md'), [
      '# CAUSAL-3 — Semantic-origin causal binding probe',
      '',
      `Tracked process world contact: ${instanceVerdict.disposition}`,
      `Honest detached semantics: ${honestDetached.disposition}`,
      `Honest transcript-bound semantics: ${honestTranscript.disposition}`,
      `Fabricated detached semantics: ${fabricatedDetached.disposition}`,
      `Fabricated same-process world contact: ${instanceVerdict.disposition}`,
      `Fabricated transcript-bound semantics: ${fabricatedTranscript.disposition}`,
      '',
      'Interpretation:',
      '- Process-instance binding proves which process owned the witnessed network contact.',
      '- A separately written semantic observation can still be internally self-consistent while containing fabricated title/H1 values.',
      '- Therefore exact process-bound world contact and detached semantic consistency can both pass without proving that the claimed semantics came from that process.',
      '- Binding the semantic claim to the actual browser_evaluate response in the same tracked MCP transcript rejects the fabricated observation.',
      '- This is still a lab observability primitive, not a non-forgeable production trust boundary; transcript authority and same-principal tampering remain separate concerns.',
      ''
    ].join('\n'));

    await regenerateManifest(outputRoot);

    console.log(`World contact instance-bound: ${instanceVerdict.disposition}`);
    console.log(`Honest transcript semantics: ${honestTranscript.disposition}`);
    console.log(`Fabricated detached semantics: ${fabricatedDetached.disposition}`);
    console.log(`Fabricated transcript semantics: ${fabricatedTranscript.disposition}`);
    console.log(`Semantic-origin discriminator: ${matrix.findings.semantic_origin_binding_adds_discrimination}`);
    console.log(`Evidence: ${outputRoot}`);

    const expected =
      matrix.findings.tracked_process_world_contact_verified &&
      matrix.findings.honest_semantics_bound_to_same_mcp_transcript &&
      matrix.findings.fabricated_semantics_self_consistent_detached &&
      matrix.findings.fabricated_semantics_would_coexist_with_verified_same_process_world_contact &&
      matrix.findings.transcript_binding_rejects_fabricated_semantics &&
      matrix.findings.semantic_origin_binding_adds_discrimination;

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
