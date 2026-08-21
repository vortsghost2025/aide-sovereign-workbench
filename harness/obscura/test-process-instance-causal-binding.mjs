import crypto from 'node:crypto';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { SshMcpClient } from './ssh-mcp-client.mjs';

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
    'printf "\\n"'
  ].join('; ');
  const { stdout, stderr } = await ssh(host, script);
  return {
    pid: Number(pid),
    exe: stdout.match(/^EXE=(.*)$/m)?.[1]?.trim() || null,
    cmdline: stdout.match(/^CMD=(.*)$/m)?.[1]?.trim() || null,
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

function classifyBinaryOnly(probe, expectedBinary) {
  if (!probe?.observed || !probe.exe) {
    return {
      disposition: 'abstain-needs-evidence',
      exact_executable_match: null,
      expected_executable: expectedBinary,
      observed_executable: probe?.exe || null
    };
  }
  const exact = probe.exe === expectedBinary;
  return {
    disposition: exact ? 'verified' : 'rejected',
    exact_executable_match: exact,
    expected_executable: expectedBinary,
    observed_executable: probe.exe,
    observed_pid: probe.pid
  };
}

function classifyInstanceBound(probe, expectedBinary, expectedPid) {
  if (!probe?.observed || !probe.exe || !expectedPid) {
    return {
      disposition: 'abstain-needs-evidence',
      expected_executable: expectedBinary,
      expected_pid: expectedPid || null,
      observed_executable: probe?.exe || null,
      observed_pid: probe?.pid || null,
      reason: 'required process-instance observation was unavailable'
    };
  }
  const exeMatch = probe.exe === expectedBinary;
  const pidMatch = probe.pid === expectedPid;
  return {
    disposition: exeMatch && pidMatch ? 'verified' : 'rejected',
    expected_executable: expectedBinary,
    expected_pid: expectedPid,
    observed_executable: probe.exe,
    observed_pid: probe.pid,
    exact_executable_match: exeMatch,
    exact_pid_match: pidMatch,
    reason: exeMatch && pidMatch
      ? 'witness connection belongs to the exact tracked Obscura MCP process instance'
      : exeMatch
        ? 'witness connection belongs to the expected executable but a different process instance'
        : 'witness connection belongs to a different executable'
  };
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

      const kind = parsed.searchParams.get('kind') || 'unknown';
      const nonce = parsed.searchParams.get('n') || '';
      const responseToken = crypto.randomBytes(32).toString('hex');
      const remoteAddress = normalizeAddress(req.socket.remoteAddress || null);
      const remotePort = req.socket.remotePort || null;
      const localPort = req.socket.localPort || null;
      const event = {
        at: new Date().toISOString(), kind, nonce,
        method: req.method || 'GET', path: parsed.pathname,
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

      const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="aide-world-token" content="${responseToken}"><title>${expectedTitle}</title></head><body><h1>${expectedTitle}</h1><p>${kind} ${nonce}</p></body></html>`;
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
  const wrapper = `/tmp/aide-obscura-tracked-${token}.sh`;
  const pidFile = `/tmp/aide-obscura-tracked-${token}.pid`;
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
  const expectedTitle = arg('expect-title', 'AIDE Process Instance Probe');

  try {
    await fs.access(outputRoot);
    throw new Error(`output path already exists; refusing to overwrite: ${outputRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before process-instance causal probe');
  await fs.mkdir(outputRoot, { recursive: true });

  const tracked = await installTrackedWrapper(host, remoteBinary);
  const witness = await startWitness({
    bindIp: coordinatorIp,
    host,
    expectedRemoteIp: tailnetIp,
    expectedTitle
  });

  const honestNonce = crypto.randomBytes(32).toString('hex');
  const decoyNonce = crypto.randomBytes(32).toString('hex');
  const honestUrl = `http://${coordinatorIp}:${witness.port}/probe?kind=tracked&n=${honestNonce}`;
  const decoyUrl = `http://${coordinatorIp}:${witness.port}/probe?kind=decoy&n=${decoyNonce}`;

  let intendedClient;
  let decoyClient;
  try {
    console.log('01 start tracked intended Obscura MCP process...');
    intendedClient = new SshMcpClient({ host, remoteBinary: tracked.wrapper, timeoutMs: 45_000 });
    await intendedClient.initialize();
    await intendedClient.listTools();

    const intendedPid = await waitForPidFile(host, tracked.pidFile);
    const intendedIdentity = intendedPid ? await inspectPid(host, intendedPid) : null;
    await writeUtf8(path.join(outputRoot, 'tracked-process.json'), `${JSON.stringify({ intended_pid: intendedPid, identity: intendedIdentity }, null, 2)}\n`);

    console.log(`   tracked pid=${intendedPid || 'unavailable'} exe=${intendedIdentity?.exe || 'unavailable'}`);
    console.log('02 tracked process makes witness contact...');
    await intendedClient.callTool('browser_navigate', { url: honestUrl, waitUntil: 'load' });

    console.log('03 separate decoy Obscura process makes witness contact while tracked process remains alive...');
    decoyClient = new SshMcpClient({ host, remoteBinary, timeoutMs: 45_000 });
    await decoyClient.initialize();
    await decoyClient.listTools();
    await decoyClient.callTool('browser_navigate', { url: decoyUrl, waitUntil: 'load' });

    const honestEvent = witness.events.find(event => event.kind === 'tracked' && event.nonce === honestNonce) || null;
    const decoyEvent = witness.events.find(event => event.kind === 'decoy' && event.nonce === decoyNonce) || null;

    const honestBinary = classifyBinaryOnly(honestEvent?.socket_owner_probe, remoteBinary);
    const honestInstance = classifyInstanceBound(honestEvent?.socket_owner_probe, remoteBinary, intendedPid);
    const decoyBinary = classifyBinaryOnly(decoyEvent?.socket_owner_probe, remoteBinary);
    const decoyInstance = classifyInstanceBound(decoyEvent?.socket_owner_probe, remoteBinary, intendedPid);

    const matrix = {
      schema: 'aide.process-instance-causal-binding/v1',
      host,
      tailnet_ip: tailnetIp,
      coordinator_ip: coordinatorIp,
      expected_obscura_executable: remoteBinary,
      tracked_process: { pid: intendedPid, identity: intendedIdentity },
      honest: {
        coordinator_event_present: Boolean(honestEvent),
        event: honestEvent,
        binary_only_verdict: honestBinary,
        instance_bound_verdict: honestInstance
      },
      decoy_same_binary: {
        coordinator_event_present: Boolean(decoyEvent),
        event: decoyEvent,
        binary_only_verdict: decoyBinary,
        instance_bound_verdict: decoyInstance
      },
      findings: {
        tracked_process_identity_exact: Boolean(intendedPid && intendedIdentity?.exe === remoteBinary),
        honest_instance_verified: honestInstance.disposition === 'verified',
        decoy_same_binary_passes_binary_only: decoyBinary.disposition === 'verified',
        decoy_same_binary_rejected_by_instance_binding: decoyInstance.disposition === 'rejected',
        process_instance_binding_adds_discrimination:
          honestInstance.disposition === 'verified' &&
          decoyBinary.disposition === 'verified' &&
          decoyInstance.disposition === 'rejected'
      }
    };

    await writeUtf8(path.join(outputRoot, 'events.json'), `${JSON.stringify(witness.events, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'honest-mcp-transcript.ndjson'), intendedClient.transcript.map(entry => JSON.stringify(entry)).join('\n') + '\n');
    await writeUtf8(path.join(outputRoot, 'decoy-mcp-transcript.ndjson'), decoyClient.transcript.map(entry => JSON.stringify(entry)).join('\n') + '\n');
    await writeUtf8(path.join(outputRoot, 'report.md'), [
      '# CAUSAL-2 — Process-instance causal binding probe',
      '',
      `Tracked intended PID: ${intendedPid || 'unavailable'}`,
      `Tracked intended executable: ${intendedIdentity?.exe || 'unavailable'}`,
      `Honest binary-only verdict: ${honestBinary.disposition}`,
      `Honest instance-bound verdict: ${honestInstance.disposition}`,
      `Decoy same-binary binary-only verdict: ${decoyBinary.disposition}`,
      `Decoy same-binary instance-bound verdict: ${decoyInstance.disposition}`,
      '',
      'Interpretation:',
      '- Binary identity alone asks only whether some process using the expected executable contacted the witness.',
      '- Process-instance binding additionally requires the socket-owning PID to equal the independently tracked intended MCP process PID.',
      '- If a second Obscura instance passes binary-only verification but fails instance-bound verification, exact executable identity is necessary but insufficient for causal attribution.',
      '- This still does not make the process trustworthy. A malicious or compromised tracked process can itself contact the witness while fabricating other semantics; that remains a separate falsification target.',
      ''
    ].join('\n'));
    await regenerateManifest(outputRoot);

    console.log(`Honest binary-only: ${honestBinary.disposition}`);
    console.log(`Honest instance-bound: ${honestInstance.disposition}`);
    console.log(`Decoy binary-only: ${decoyBinary.disposition}`);
    console.log(`Decoy instance-bound: ${decoyInstance.disposition}`);
    console.log(`Instance binding adds discrimination: ${matrix.findings.process_instance_binding_adds_discrimination}`);
    console.log(`Evidence: ${outputRoot}`);

    if (!matrix.findings.process_instance_binding_adds_discrimination) process.exitCode = 1;
  } finally {
    await decoyClient?.callTool('browser_close', {}).catch(() => undefined);
    await decoyClient?.close().catch(() => undefined);
    await intendedClient?.callTool('browser_close', {}).catch(() => undefined);
    await intendedClient?.close().catch(() => undefined);
    await witness.close().catch(() => undefined);
    await ssh(host, `rm -f ${shQuote(tracked.wrapper)} ${shQuote(tracked.pidFile)}`).catch(() => undefined);
  }
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
