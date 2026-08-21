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

async function installTrackedWrapper(host, remoteBinary, prefix) {
  const token = crypto.randomBytes(8).toString('hex');
  const wrapper = `/tmp/${prefix}-${token}.sh`;
  const pidFile = `/tmp/${prefix}-${token}.pid`;
  const body = `#!/bin/sh\nprintf '%s\\n' "$$" > ${shQuote(pidFile)}\nexec ${shQuote(remoteBinary)} "$@"\n`;
  const encoded = Buffer.from(body, 'utf8').toString('base64');
  await ssh(host, `printf %s ${shQuote(encoded)} | base64 -d > ${shQuote(wrapper)} && chmod 700 ${shQuote(wrapper)}`);
  return { wrapper, pidFile };
}

async function installFakeWorker(host, observation) {
  const token = crypto.randomBytes(8).toString('hex');
  const script = `/tmp/aide-fake-mcp-${token}.py`;
  const wrapper = `/tmp/aide-fake-mcp-${token}.sh`;
  const pidFile = `/tmp/aide-fake-mcp-${token}.pid`;
  const observationJson = JSON.stringify(observation);
  const python = `import json,sys\nOBS=${JSON.stringify(observationJson)}\nfor line in sys.stdin:\n    try:\n        m=json.loads(line)\n    except Exception:\n        continue\n    if 'id' not in m:\n        continue\n    method=m.get('method')\n    if method=='initialize':\n        result={'protocolVersion':'2024-11-05','capabilities':{'tools':{}},'serverInfo':{'name':'aide-fake-mcp','version':'1'}}\n    elif method=='tools/list':\n        result={'tools':[{'name':'browser_evaluate','description':'fabricated test worker','inputSchema':{'type':'object'}}]}\n    elif method=='tools/call':\n        result={'content':[{'type':'text','text':OBS}],'isError':False}\n    else:\n        result={}\n    sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':result})+'\\n')\n    sys.stdout.flush()\n`;
  const wrapperBody = `#!/bin/sh\nprintf '%s\\n' "$$" > ${shQuote(pidFile)}\nexec python3 -u ${shQuote(script)} "$@"\n`;
  const scriptEncoded = Buffer.from(python, 'utf8').toString('base64');
  const wrapperEncoded = Buffer.from(wrapperBody, 'utf8').toString('base64');
  await ssh(host, [
    `printf %s ${shQuote(scriptEncoded)} | base64 -d > ${shQuote(script)}`,
    `printf %s ${shQuote(wrapperEncoded)} | base64 -d > ${shQuote(wrapper)}`,
    `chmod 700 ${shQuote(script)} ${shQuote(wrapper)}`
  ].join(' && '));
  return { script, wrapper, pidFile };
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
  const expectedTitle = arg('expect-title', 'AIDE Transcript Session Probe');
  const fabricatedTitle = arg('fabricated-title', 'FOREIGN TRANSCRIPT FABRICATION');

  try {
    await fs.access(outputRoot);
    throw new Error(`output path already exists; refusing to overwrite: ${outputRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before transcript-session causal probe');
  await fs.mkdir(outputRoot, { recursive: true });

  const tracked = await installTrackedWrapper(host, remoteBinary, 'aide-obscura-session');
  const witness = await startWitness({
    bindIp: coordinatorIp,
    host,
    expectedRemoteIp: tailnetIp,
    expectedTitle
  });

  const nonce = crypto.randomBytes(32).toString('hex');
  const url = `http://${coordinatorIp}:${witness.port}/probe?n=${nonce}`;
  let realClient;
  let fakeClient;
  let fakeWorker;

  try {
    console.log('01 start independently tracked Obscura MCP session...');
    realClient = new SshMcpClient({ host, remoteBinary: tracked.wrapper, timeoutMs: 45_000 });
    await realClient.initialize();
    await realClient.listTools();

    const trackedPid = await waitForPidFile(host, tracked.pidFile);
    const trackedIdentity = trackedPid ? await inspectPid(host, trackedPid) : null;
    console.log(`   tracked pid=${trackedPid || 'unavailable'} exe=${trackedIdentity?.exe || 'unavailable'}`);

    console.log('02 tracked Obscura session makes coordinator-witness contact...');
    await realClient.callTool('browser_navigate', { url, waitUntil: 'load' });

    const expression = `JSON.stringify({title:document.title,url:location.href,h1:document.querySelector('h1')?.textContent||null,world_token:document.querySelector('meta[name="aide-world-token"]')?.content||null})`;
    await realClient.callTool('browser_evaluate', { expression });
    const realTranscript = JSON.parse(JSON.stringify(realClient.transcript));
    const realBound = findEvaluateObservation(realTranscript);

    const event = witness.events.find(candidate => candidate.nonce === nonce) || null;
    const worldContactIdentity = event?.socket_owner_probe || null;
    const worldContactVerdict = sameProcessIdentity(trackedIdentity, worldContactIdentity);

    const fabricatedClaims = {
      title: fabricatedTitle,
      url,
      h1: fabricatedTitle,
      world_token: witness.responseToken
    };

    console.log('03 start separate fake MCP session and capture a self-consistent fabricated transcript...');
    fakeWorker = await installFakeWorker(host, fabricatedClaims);
    fakeClient = new SshMcpClient({ host, remoteBinary: fakeWorker.wrapper, timeoutMs: 20_000 });
    await fakeClient.initialize();
    await fakeClient.listTools();
    await fakeClient.callTool('browser_evaluate', { expression });

    const fakePid = await waitForPidFile(host, fakeWorker.pidFile);
    const fakeIdentity = fakePid ? await inspectPid(host, fakePid) : null;
    const fakeTranscript = JSON.parse(JSON.stringify(fakeClient.transcript));
    const fakeBound = findEvaluateObservation(fakeTranscript);

    const honestSemanticVerdict = exactSemanticVerdict(realBound?.observation, realBound?.observation || null);
    const foreignSemanticVerdict = exactSemanticVerdict(fakeBound?.observation, fabricatedClaims);

    const honestSessionBinding = sameProcessIdentity(trackedIdentity, trackedIdentity);
    const foreignSessionBinding = sameProcessIdentity(trackedIdentity, fakeIdentity);

    const naiveComposite = {
      disposition:
        worldContactVerdict.disposition === 'verified' && foreignSemanticVerdict.disposition === 'verified'
          ? 'verified'
          : 'rejected',
      reason: 'naive composition checks exact-process world contact and semantic transcript independently without proving they came from the same launch/session'
    };

    const sessionBoundComposite = {
      disposition:
        worldContactVerdict.disposition === 'verified' &&
        foreignSemanticVerdict.disposition === 'verified' &&
        foreignSessionBinding.disposition === 'verified'
          ? 'verified'
          : 'rejected',
      reason: foreignSessionBinding.disposition === 'verified'
        ? 'world contact, semantic transcript, and transcript-source launch identity all bind to the tracked process instance'
        : 'semantic transcript came from a different launch/process session than the process that satisfied the world witness'
    };

    const matrix = {
      schema: 'aide.transcript-session-causal-binding/v1',
      host,
      tailnet_ip: tailnetIp,
      coordinator_ip: coordinatorIp,
      expected_obscura_executable: remoteBinary,
      tracked_session: {
        pid: trackedPid,
        identity: trackedIdentity,
        transcript_source_identity: trackedIdentity
      },
      coordinator_event: event,
      world_contact_process_binding: worldContactVerdict,
      honest_transcript: {
        source_identity: trackedIdentity,
        bound_observation: realBound,
        semantic_verdict: honestSemanticVerdict,
        transcript_session_binding: honestSessionBinding
      },
      foreign_fake_transcript: {
        source_identity: fakeIdentity,
        bound_observation: fakeBound,
        declared_claims: fabricatedClaims,
        semantic_verdict: foreignSemanticVerdict,
        transcript_session_binding: foreignSessionBinding,
        naive_composite_verdict: naiveComposite,
        session_bound_composite_verdict: sessionBoundComposite
      },
      findings: {
        tracked_world_contact_verified: worldContactVerdict.disposition === 'verified',
        honest_transcript_semantics_verified: honestSemanticVerdict.disposition === 'verified',
        honest_transcript_session_bound: honestSessionBinding.disposition === 'verified',
        foreign_transcript_semantics_self_consistent: foreignSemanticVerdict.disposition === 'verified',
        naive_composite_accepts_foreign_transcript: naiveComposite.disposition === 'verified',
        foreign_transcript_source_rejected_by_session_binding: foreignSessionBinding.disposition === 'rejected',
        session_bound_composite_rejects_foreign_transcript: sessionBoundComposite.disposition === 'rejected',
        transcript_session_binding_adds_discrimination:
          naiveComposite.disposition === 'verified' && sessionBoundComposite.disposition === 'rejected'
      }
    };

    await writeUtf8(path.join(outputRoot, 'tracked-session.json'), `${JSON.stringify(matrix.tracked_session, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'fake-session.json'), `${JSON.stringify({ pid: fakePid, identity: fakeIdentity }, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'events.json'), `${JSON.stringify(witness.events, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'real-mcp-transcript.ndjson'), `${realTranscript.map(entry => JSON.stringify(entry)).join('\n')}\n`);
    await writeUtf8(path.join(outputRoot, 'foreign-fake-mcp-transcript.ndjson'), `${fakeTranscript.map(entry => JSON.stringify(entry)).join('\n')}\n`);
    await writeUtf8(path.join(outputRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'report.md'), [
      '# CAUSAL-4 — Transcript-session causal binding probe',
      '',
      `Tracked world contact: ${worldContactVerdict.disposition}`,
      `Honest transcript semantics: ${honestSemanticVerdict.disposition}`,
      `Honest transcript/session binding: ${honestSessionBinding.disposition}`,
      `Foreign fake transcript semantics: ${foreignSemanticVerdict.disposition}`,
      `Naive world+transcript composite: ${naiveComposite.disposition}`,
      `Foreign transcript/session binding: ${foreignSessionBinding.disposition}`,
      `Session-bound composite: ${sessionBoundComposite.disposition}`,
      '',
      'Interpretation:',
      '- CAUSAL-3 showed that semantic claims must bind to an MCP transcript rather than a detached observation file.',
      '- This probe asks whether an otherwise valid transcript can be borrowed from a different MCP launch/session and paired with a real world-contact event from the tracked Obscura process.',
      '- If naive composition accepts the foreign transcript but launch/session binding rejects it, transcript provenance is a distinct causal requirement.',
      '- The launch receipt here is coordinator bookkeeping over PID/executable/proc-start identity. It is still a lab primitive, not hardware attestation or an OS-isolated production trust boundary.',
      ''
    ].join('\n'));

    await regenerateManifest(outputRoot);

    console.log(`Tracked world contact: ${worldContactVerdict.disposition}`);
    console.log(`Honest transcript/session: ${honestSessionBinding.disposition}`);
    console.log(`Foreign transcript semantics: ${foreignSemanticVerdict.disposition}`);
    console.log(`Naive composite: ${naiveComposite.disposition}`);
    console.log(`Foreign transcript/session: ${foreignSessionBinding.disposition}`);
    console.log(`Session-bound composite: ${sessionBoundComposite.disposition}`);
    console.log(`Transcript-session discriminator: ${matrix.findings.transcript_session_binding_adds_discrimination}`);
    console.log(`Evidence: ${outputRoot}`);

    const expected =
      matrix.findings.tracked_world_contact_verified &&
      matrix.findings.honest_transcript_semantics_verified &&
      matrix.findings.honest_transcript_session_bound &&
      matrix.findings.foreign_transcript_semantics_self_consistent &&
      matrix.findings.naive_composite_accepts_foreign_transcript &&
      matrix.findings.foreign_transcript_source_rejected_by_session_binding &&
      matrix.findings.session_bound_composite_rejects_foreign_transcript &&
      matrix.findings.transcript_session_binding_adds_discrimination;

    if (!expected) process.exitCode = 1;
  } finally {
    if (fakeClient) await fakeClient.close().catch(() => undefined);
    if (realClient) {
      await realClient.callTool('browser_close', {}).catch(() => undefined);
      await realClient.close().catch(() => undefined);
    }
    await witness.close().catch(() => undefined);
    const cleanup = [tracked.wrapper, tracked.pidFile, fakeWorker?.wrapper, fakeWorker?.pidFile, fakeWorker?.script]
      .filter(Boolean)
      .map(shQuote)
      .join(' ');
    if (cleanup) await ssh(host, `rm -f ${cleanup}`, 10_000).catch(() => undefined);
  }
}

main().catch(error => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});