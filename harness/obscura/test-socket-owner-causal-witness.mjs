import crypto from 'node:crypto';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { SshMcpClient } from './ssh-mcp-client.mjs';

const execFileAsync = promisify(execFile);
const RAW_HTTP_UA = 'AIDE-CAUSAL-SOCKET-RAW-HTTP/1';

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

async function ssh(host, command, timeout = 15_000) {
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
  const exe = stdout.match(/^EXE=(.*)$/m)?.[1]?.trim() || null;
  const cmdline = stdout.match(/^CMD=(.*)$/m)?.[1]?.trim() || null;
  return { pid: Number(pid), exe, cmdline, stderr: stderr.trim() || null };
}

async function observeSocketOwner({ host, sourcePort, destinationPort, expectedRemoteIp }) {
  let snapshot;
  try {
    snapshot = await ssh(host, 'ss -ntpH 2>&1 || true');
  } catch (error) {
    return {
      observed: false,
      disposition: 'abstain-needs-evidence',
      reason: `unable to read remote socket table: ${error.message || String(error)}`,
      source_port: sourcePort,
      destination_port: destinationPort
    };
  }

  const sourceNeedle = `:${sourcePort}`;
  const destinationNeedle = `:${destinationPort}`;
  const lines = snapshot.stdout
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .filter(line => line.includes(sourceNeedle) && line.includes(destinationNeedle));

  let matchedLine = lines.find(line => !expectedRemoteIp || line.includes(expectedRemoteIp)) || lines[0] || null;
  if (!matchedLine) {
    return {
      observed: false,
      disposition: 'abstain-needs-evidence',
      reason: 'request was visible to the coordinator but no matching established socket was observed on the remote host during the held-open response window',
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
      reason: 'matching socket was observed but ss did not expose a process pid',
      source_port: sourcePort,
      destination_port: destinationPort,
      socket_line: matchedLine
    };
  }

  const identity = await inspectPid(host, Number(pidMatch[1]));
  return {
    observed: Boolean(identity.exe),
    disposition: identity.exe ? 'observed' : 'abstain-needs-evidence',
    reason: identity.exe ? 'matching held-open TCP socket mapped to a live process identity' : 'pid was visible but /proc identity could not be resolved',
    source_port: sourcePort,
    destination_port: destinationPort,
    socket_line: matchedLine,
    ...identity
  };
}

function classifyOwner(probe, expectedBinary) {
  if (!probe?.observed || !probe.exe) {
    return {
      disposition: 'abstain-needs-evidence',
      expected_executable: expectedBinary,
      observed_executable: probe?.exe || null,
      exact_executable_match: null,
      reason: probe?.reason || 'socket owner was not observable'
    };
  }
  const exact = probe.exe === expectedBinary;
  return {
    disposition: exact ? 'verified' : 'rejected',
    expected_executable: expectedBinary,
    observed_executable: probe.exe,
    exact_executable_match: exact,
    pid: probe.pid,
    cmdline: probe.cmdline,
    reason: exact
      ? 'the process owning the witnessed TCP connection is the exact expected Obscura executable'
      : 'the witnessed TCP connection belongs to a different executable'
  };
}

async function startWitnessServer({ bindIp, host, expectedRemoteIp, expectedTitle }) {
  const events = [];
  const server = http.createServer(async (req, res) => {
    try {
      const base = `http://${req.headers.host || bindIp}`;
      const parsed = new URL(req.url || '/', base);
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
        at: new Date().toISOString(),
        kind,
        method: req.method || 'GET',
        path: parsed.pathname,
        nonce,
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
          expectedRemoteIp: bindIp
        });
      } else {
        event.socket_owner_probe = {
          observed: false,
          disposition: 'abstain-needs-evidence',
          reason: 'coordinator socket did not expose both endpoint ports'
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
  if (!address || typeof address === 'string') throw new Error('unexpected witness server address');
  return {
    events,
    port: address.port,
    close: () => new Promise(resolve => server.close(resolve))
  };
}

async function rawHttp(host, url) {
  const script = String.raw`import urllib.request
url=${JSON.stringify(url)}
req=urllib.request.Request(url,headers={'User-Agent':${JSON.stringify(RAW_HTTP_UA)}})
with urllib.request.urlopen(req,timeout=15) as r:
    body=r.read()
    print(r.status)
    print(len(body))
`;
  const encoded = Buffer.from(script, 'utf8').toString('base64');
  return ssh(host, `python3 -u -c "import base64;exec(base64.b64decode('${encoded}'))"`, 30_000);
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
    manifest.push({
      path: relative,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex')
    });
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
  const expectedTitle = arg('expect-title', 'AIDE Socket Owner Probe');

  try {
    await fs.access(outputRoot);
    throw new Error(`output path already exists; refusing to overwrite: ${outputRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before socket-owner causal witness probe');
  await fs.mkdir(outputRoot, { recursive: true });

  const witness = await startWitnessServer({
    bindIp: coordinatorIp,
    host,
    expectedRemoteIp: tailnetIp,
    expectedTitle
  });

  const honestNonce = crypto.randomBytes(32).toString('hex');
  const liarNonce = crypto.randomBytes(32).toString('hex');
  const honestUrl = `http://${coordinatorIp}:${witness.port}/probe?kind=honest&n=${honestNonce}`;
  const liarUrl = `http://${coordinatorIp}:${witness.port}/probe?kind=raw-http&n=${liarNonce}`;

  let client;
  let rawResult = null;
  try {
    console.log('01 honest Obscura contact with held-open socket-owner observation...');
    client = new SshMcpClient({ host, remoteBinary, timeoutMs: 45_000 });
    await client.initialize();
    await client.listTools();
    await client.callTool('browser_navigate', { url: honestUrl, waitUntil: 'load' });
    await client.callTool('browser_close', {}).catch(() => undefined);
    await client.close();
    client = null;

    await writeUtf8(
      path.join(outputRoot, 'honest-mcp-transcript.ndjson'),
      client?.transcript?.map(entry => JSON.stringify(entry)).join('\n') || ''
    ).catch(() => undefined);

    console.log('02 raw Python HTTP contact with held-open socket-owner observation...');
    rawResult = await rawHttp(host, liarUrl);

    const honestEvent = witness.events.find(event => event.kind === 'honest' && event.nonce === honestNonce) || null;
    const liarEvent = witness.events.find(event => event.kind === 'raw-http' && event.nonce === liarNonce) || null;
    const honestOwner = classifyOwner(honestEvent?.socket_owner_probe, remoteBinary);
    const liarOwner = classifyOwner(liarEvent?.socket_owner_probe, remoteBinary);

    const matrix = {
      schema: 'aide.socket-owner-causal-witness/v1',
      host,
      tailnet_ip: tailnetIp,
      coordinator_ip: coordinatorIp,
      expected_obscura_executable: remoteBinary,
      honest: {
        coordinator_event_present: Boolean(honestEvent),
        event: honestEvent,
        owner_verdict: honestOwner
      },
      raw_http: {
        coordinator_event_present: Boolean(liarEvent),
        event: liarEvent,
        owner_verdict: liarOwner,
        expected_user_agent: RAW_HTTP_UA
      },
      findings: {
        socket_owner_observation_available: Boolean(honestEvent?.socket_owner_probe?.observed && liarEvent?.socket_owner_probe?.observed),
        honest_contact_owned_by_expected_obscura: honestOwner.disposition === 'verified',
        raw_http_contact_rejected_as_obscura: liarOwner.disposition === 'rejected',
        falsify2_raw_http_distinguished_by_socket_owner:
          honestOwner.disposition === 'verified' && liarOwner.disposition === 'rejected'
      }
    };

    await writeUtf8(path.join(outputRoot, 'events.json'), `${JSON.stringify(witness.events, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'raw-http-stdout.txt'), rawResult?.stdout || '');
    await writeUtf8(path.join(outputRoot, 'raw-http-stderr.txt'), rawResult?.stderr || '');
    await writeUtf8(path.join(outputRoot, 'report.md'), [
      '# Socket-owner causal witness probe',
      '',
      `Honest coordinator event: ${honestEvent ? 'YES' : 'NO'}`,
      `Honest socket owner: ${honestOwner.disposition}`,
      `Honest observed executable: ${honestOwner.observed_executable || 'none'}`,
      `Raw-HTTP coordinator event: ${liarEvent ? 'YES' : 'NO'}`,
      `Raw-HTTP socket owner as Obscura: ${liarOwner.disposition}`,
      `Raw-HTTP observed executable: ${liarOwner.observed_executable || 'none'}`,
      '',
      'Interpretation:',
      '- The coordinator holds each HTTP response open while independently querying the Ubuntu socket table over SSH.',
      '- The witnessed TCP source port is mapped to a remote PID and /proc executable identity.',
      '- VERIFIED means the exact expected Obscura executable owned the witnessed connection.',
      '- REJECTED means a different executable owned the witnessed connection.',
      '- ABSTAIN-NEEDS-EVIDENCE means the process owner could not be observed reliably; absence is not converted into a false contradiction.',
      '- This is a causal-path observability probe, not yet a non-forgeable production trust boundary. A same-principal adversary and deliberate Obscura-as-relay attack remain future falsification targets.',
      ''
    ].join('\n'));

    await regenerateManifest(outputRoot);

    console.log(`Honest owner: ${honestOwner.disposition} exe=${honestOwner.observed_executable || 'none'}`);
    console.log(`Raw HTTP owner as Obscura: ${liarOwner.disposition} exe=${liarOwner.observed_executable || 'none'}`);
    console.log(`Socket-owner discriminator: ${matrix.findings.falsify2_raw_http_distinguished_by_socket_owner}`);
    console.log(`Evidence: ${outputRoot}`);

    const expected =
      matrix.findings.socket_owner_observation_available &&
      matrix.findings.honest_contact_owned_by_expected_obscura &&
      matrix.findings.raw_http_contact_rejected_as_obscura;
    if (!expected) process.exitCode = 1;
  } finally {
    if (client) await client.close().catch(() => undefined);
    await witness.close().catch(() => undefined);
  }
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
