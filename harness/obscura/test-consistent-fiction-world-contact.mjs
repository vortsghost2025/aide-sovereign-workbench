import crypto from 'node:crypto';
import http from 'node:http';
import { once } from 'node:events';
import { spawn, execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { promisify } from 'node:util';
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

class RemoteMcpClient {
  constructor({ host, command, timeoutMs = 30_000 }) {
    this.host = host;
    this.command = command;
    this.timeoutMs = timeoutMs;
    this.proc = null;
    this.reader = null;
    this.nextId = 1;
    this.pending = new Map();
    this.transcript = [];
    this.stderr = '';
  }

  #record(direction, message) {
    this.transcript.push({ at: new Date().toISOString(), direction, message: JSON.parse(JSON.stringify(message)) });
  }

  #line(line) {
    const trimmed = line.trim();
    if (!trimmed) return;
    let message;
    try { message = JSON.parse(trimmed); }
    catch {
      this.transcript.push({ at: new Date().toISOString(), direction: 'in-non-json', text: trimmed });
      return;
    }
    this.#record('in', message);
    if (message.id === undefined || message.id === null) return;
    const pending = this.pending.get(String(message.id));
    if (!pending) return;
    this.pending.delete(String(message.id));
    clearTimeout(pending.timer);
    if (message.error) pending.reject(new Error(`MCP ${message.error.code}: ${message.error.message}`));
    else pending.resolve(message.result);
  }

  async start() {
    if (this.proc) return;
    this.proc = spawn('ssh', [
      '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
      '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
      this.host, this.command
    ], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    this.proc.stderr.setEncoding('utf8');
    this.proc.stderr.on('data', chunk => { this.stderr += chunk; });
    this.reader = readline.createInterface({ input: this.proc.stdout, crlfDelay: Infinity });
    this.reader.on('line', line => this.#line(line));
    this.proc.on('exit', (code, signal) => {
      const error = new Error(`remote MCP exited code=${code} signal=${signal || 'none'}`);
      for (const item of this.pending.values()) {
        clearTimeout(item.timer);
        item.reject(error);
      }
      this.pending.clear();
    });
    await Promise.race([
      once(this.proc, 'spawn'),
      once(this.proc, 'error').then(([error]) => Promise.reject(error))
    ]);
  }

  async request(method, params = {}) {
    await this.start();
    const id = this.nextId++;
    const message = { jsonrpc: '2.0', id, method, params };
    this.#record('out', message);
    const result = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(String(id));
        reject(new Error(`MCP timeout: ${method}`));
      }, this.timeoutMs);
      this.pending.set(String(id), { resolve, reject, timer });
    });
    if (!this.proc.stdin.write(`${JSON.stringify(message)}\n`)) await once(this.proc.stdin, 'drain');
    return result;
  }

  async notify(method, params = {}) {
    await this.start();
    const message = { jsonrpc: '2.0', method, params };
    this.#record('out', message);
    if (!this.proc.stdin.write(`${JSON.stringify(message)}\n`)) await once(this.proc.stdin, 'drain');
  }

  async initialize() {
    const result = await this.request('initialize', {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'aide-world-contact-lab', version: '1' }
    });
    await this.notify('notifications/initialized', {});
    return result;
  }

  async listTools() { return this.request('tools/list', {}); }

  async callTool(name, args = {}) {
    const result = await this.request('tools/call', { name, arguments: args });
    if (result?.isError) {
      const text = result?.content?.find(item => item?.type === 'text')?.text || 'unknown tool error';
      throw new Error(`${name}: ${text}`);
    }
    return result;
  }

  async close() {
    if (!this.proc) return;
    const proc = this.proc;
    if (!proc.stdin.destroyed) proc.stdin.end();
    await Promise.race([once(proc, 'exit').catch(() => undefined), new Promise(r => setTimeout(r, 2000))]);
    if (proc.exitCode === null && proc.signalCode === null) proc.kill();
    this.reader?.close();
    this.proc = null;
  }
}

function toolText(result) {
  return result?.content?.find(item => item?.type === 'text')?.text || '';
}

function newChallenge(label, claimContractSha256) {
  const issued = new Date();
  return {
    schema: 'aide.coordinator-challenge/v1',
    task_id: `world-contact-${label}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
    nonce: crypto.randomBytes(32).toString('hex'),
    issued_at: issued.toISOString(),
    expires_at: new Date(issued.getTime() + 10 * 60 * 1000).toISOString(),
    claim_contract_sha256: claimContractSha256
  };
}

function claimsFor({ title, url, h1 }) {
  return [
    { id: 'page-title', operator: 'json-equals', evidence_path: 'evidence/challenge-observation.json', pointer: '/observed/title', expected: title },
    { id: 'page-url', operator: 'json-equals', evidence_path: 'evidence/challenge-observation.json', pointer: '/observed/url', expected: url },
    { id: 'page-h1', operator: 'json-equals', evidence_path: 'evidence/challenge-observation.json', pointer: '/observed/h1', expected: h1 }
  ];
}

async function startEchoServer(bindIp, expectedTitle) {
  const events = [];
  const server = http.createServer((req, res) => {
    const base = `http://${req.headers.host || bindIp}`;
    const parsed = new URL(req.url || '/', base);
    if (parsed.pathname !== '/probe') {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
      return;
    }
    const nonce = parsed.searchParams.get('n') || '';
    const responseToken = crypto.randomBytes(32).toString('hex');
    events.push({
      at: new Date().toISOString(),
      method: req.method || 'GET',
      path: parsed.pathname,
      nonce,
      response_token: responseToken,
      remote_address: req.socket.remoteAddress || null,
      user_agent: req.headers['user-agent'] || null
    });
    const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="aide-world-token" content="${responseToken}"><title>${expectedTitle}</title></head><body><h1>${expectedTitle}</h1><p>challenge ${nonce}</p></body></html>`;
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': Buffer.byteLength(html),
      'cache-control': 'no-store'
    });
    res.end(html);
  });
  server.on('clientError', (err, socket) => socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, bindIp, () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('unexpected echo server address');
  return {
    server,
    events,
    port: address.port,
    close: () => new Promise(resolve => server.close(() => resolve()))
  };
}

function fakeWorkerCommand(expectedTitle) {
  const script = String.raw`import sys,json,re
url=''
title=${JSON.stringify(expectedTitle)}
for line in sys.stdin:
    try: msg=json.loads(line)
    except Exception: continue
    if 'id' not in msg: continue
    mid=msg.get('id'); method=msg.get('method'); result={}
    if method=='initialize':
        result={'protocolVersion':'2024-11-05','capabilities':{'tools':{}},'serverInfo':{'name':'obscura-mcp','version':'0.1.0-fake'}}
    elif method=='tools/list':
        result={'tools':[{'name':n} for n in ['browser_navigate','browser_snapshot','browser_evaluate','browser_network_requests','browser_close']]}
    elif method=='tools/call':
        params=msg.get('params') or {}; name=params.get('name'); args=params.get('arguments') or {}; text=''
        if name=='browser_navigate':
            url=args.get('url',''); text=f'Navigated to {url} — "{title}"'
        elif name=='browser_snapshot':
            text=f'URL: {url}\\nTitle: {title}\\n\\n{title}'
        elif name=='browser_evaluate':
            expr=args.get('expression','')
            m=re.search(r'[0-9a-f]{64}',expr)
            if 'aide-world-token' not in expr and m:
                text=m.group(0)
            else:
                text=json.dumps({'title':title,'url':url,'h1':title,'world_token':None},separators=(',',':'))
        elif name=='browser_network_requests':
            text=f'[200] GET {url} (0B)'
        elif name=='browser_close':
            text='All browser tabs closed.'
        else:
            result={'content':[{'type':'text','text':f'Error: Unknown tool: {name}'}],'isError':True}
        if not result: result={'content':[{'type':'text','text':text}]}
    else:
        result={}
    print(json.dumps({'jsonrpc':'2.0','id':mid,'result':result},separators=(',',':')),flush=True)
`;
  const encoded = Buffer.from(script, 'utf8').toString('base64');
  return `python3 -u -c "import base64;exec(base64.b64decode('${encoded}'))"`;
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

async function runTrial({ root, workspace, client, challenge, url, expectedTitle, expectedH1, evidenceClaims, serverEvents, kind, nodeName, tailnetIp }) {
  const evidenceDir = path.join(root, 'evidence');
  const coordinatorDir = path.join(root, 'coordinator');
  await fs.mkdir(evidenceDir, { recursive: true });
  await fs.mkdir(coordinatorDir, { recursive: true });
  await writeUtf8(path.join(coordinatorDir, 'challenge.json'), `${JSON.stringify(challenge, null, 2)}\n`);

  const head = (await git(workspace, ['rev-parse', 'HEAD'])).trim();
  const diffText = await git(workspace, ['diff', '--binary', '--full-index', '--no-ext-diff', `${head}..${head}`, '--']);
  const challengeToken = sha256Canonical(challenge);
  const startedAt = new Date().toISOString();
  const eventStart = serverEvents.length;
  let initialization, navigate, snapshot, echo, evaluation, network;
  let missionError = null;
  try {
    initialization = await client.initialize();
    await client.listTools();
    navigate = await client.callTool('browser_navigate', { url, waitUntil: 'load' });
    snapshot = await client.callTool('browser_snapshot', { max_chars: 8000 });
    echo = await client.callTool('browser_evaluate', { expression: JSON.stringify(challengeToken) });
    evaluation = await client.callTool('browser_evaluate', {
      expression: 'JSON.stringify({title:document.title,url:location.href,h1:document.querySelector("h1")?.textContent||null,world_token:document.querySelector("meta[name=\\"aide-world-token\\"]")?.content||null})'
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
  if (echo) await writeUtf8(path.join(evidenceDir, 'challenge-echo.txt'), `${toolText(echo).trim()}\n`);
  if (evaluation) await writeUtf8(path.join(evidenceDir, 'evaluate.txt'), `${toolText(evaluation).trim()}\n`);
  if (missionError) await writeUtf8(path.join(evidenceDir, 'mission-error.txt'), `${missionError.stack || missionError.message}\n`);

  let page = null;
  try { page = JSON.parse(toolText(evaluation).trim()); } catch {}
  const observed = {
    challenge: toolText(echo).trim() || null,
    title: page?.title ?? null,
    url: page?.url ?? null,
    h1: page?.h1 ?? null,
    world_token: page?.world_token ?? null
  };
  const observationPath = path.join(evidenceDir, 'challenge-observation.json');
  await writeUtf8(observationPath, `${JSON.stringify({ schema: 'aide.browser-world-contact-observation/v1', observed }, null, 2)}\n`);

  const missionPassed = !missionError && observed.challenge === challengeToken && observed.title === expectedTitle && observed.url === url && observed.h1 === expectedH1;
  const missionCheckPath = path.join(evidenceDir, 'mission-check.txt');
  await writeUtf8(missionCheckPath, [
    `kind: ${kind}`,
    `challenge-token-match: ${observed.challenge === challengeToken ? 'PASS' : 'FAIL'}`,
    `page-observation-parsed: ${page ? 'PASS' : 'FAIL'}`,
    `title-match: ${observed.title === expectedTitle ? 'PASS' : 'FAIL'}`,
    `url-match: ${observed.url === url ? 'PASS' : 'FAIL'}`,
    `h1-match: ${observed.h1 === expectedH1 ? 'PASS' : 'FAIL'}`,
    `mission-error: ${missionError ? missionError.message : 'none'}`,
    ''
  ].join('\n'));
  const diffPath = path.join(evidenceDir, 'change.patch');
  await writeUtf8(diffPath, diffText);

  const artifacts = [
    artifact('mcp-transcript', 'mcp-transcript', 'evidence/mcp-transcript.ndjson', await hashFile(transcriptPath)),
    artifact('challenge-observation', 'structured-browser-observation', 'evidence/challenge-observation.json', await hashFile(observationPath)),
    artifact('mission-check', 'test-output', 'evidence/mission-check.txt', await hashFile(missionCheckPath)),
    artifact('zero-diff-binding', 'git-diff', 'evidence/change.patch', await hashFile(diffPath))
  ];
  for (const [name, kindName, relative] of [
    ['initialize', 'mcp-initialize', 'evidence/initialize.json'],
    ['navigate', 'browser-output', 'evidence/navigate.txt'],
    ['snapshot', 'browser-snapshot', 'evidence/snapshot.txt'],
    ['challenge-echo', 'browser-evaluate', 'evidence/challenge-echo.txt'],
    ['page-evaluate', 'browser-evaluate', 'evidence/evaluate.txt'],
    ['network', 'browser-network', 'evidence/network.txt']
  ]) {
    try { artifacts.push(artifact(name, kindName, relative, await hashFile(path.join(root, relative)))); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }

  const bundle = {
    schema: 'aide.external-run/v1',
    task: { id: challenge.task_id, summary: `${kind} world-contact browser trial against coordinator echo` },
    executor: { agent: kind === 'honest' ? 'obscura-mcp-over-ssh' : 'fabricated-mcp-worker', provider: 'ssh-stdio', model: 'none', node: nodeName, tailnet_ip: tailnetIp },
    timing: { started_at: startedAt, finished_at: finishedAt },
    claim: { status: missionPassed ? 'success' : 'failure', summary: missionPassed ? 'Challenge-bound browser-shaped mission completed' : 'Mission assertions failed' },
    repository: { base_commit: head, head_commit: head, changed_files: [], diff_sha256: sha256Text(diffText) },
    tests: [{ name: 'world-contact-shape-mission', command: kind, exit_code: missionPassed ? 0 : 1, output_path: 'evidence/mission-check.txt', output_sha256: await hashFile(missionCheckPath) }],
    artifacts,
    fallbacks: [],
    evidence_claims: evidenceClaims,
    challenge_binding: {
      schema: 'aide.live-challenge-binding/v1',
      observation_path: 'evidence/challenge-observation.json',
      challenge_pointer: '/observed/challenge',
      transcript_path: 'evidence/mcp-transcript.ndjson'
    }
  };
  const bundlePath = path.join(root, 'bundle.json');
  await writeUtf8(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`);

  const coordinatorReceipt = {
    schema: 'aide.coordinator-receipt/v1',
    task_id: challenge.task_id,
    challenge_token: challengeToken,
    claim_contract_sha256: challenge.claim_contract_sha256,
    transcript_sha256: await hashFile(transcriptPath),
    observation_sha256: await hashFile(observationPath),
    captured_at: finishedAt
  };
  await writeUtf8(path.join(coordinatorDir, 'receipt.json'), `${JSON.stringify(coordinatorReceipt, null, 2)}\n`);

  const generic = await verifyExternalRunWithStructuredClaims({ bundle, bundlePath, workspace, taskClass: 'explanation' });
  const live = await verifyExternalRunWithLiveChallenge({ bundle, bundlePath, workspace, expectedChallenge: challenge, coordinatorReceipt, taskClass: 'explanation' });

  const newEvents = serverEvents.slice(eventStart).filter(event => event.nonce === challenge.nonce);
  const worldEvent = newEvents.at(-1) || null;
  const issued = Date.parse(challenge.issued_at);
  const expires = Date.parse(challenge.expires_at);
  const eventTime = worldEvent ? Date.parse(worldEvent.at) : null;
  const world = {
    disposition: 'abstain-needs-evidence',
    passed: false,
    coordinator_event_present: Boolean(worldEvent),
    nonce_match: Boolean(worldEvent && worldEvent.nonce === challenge.nonce),
    response_token_match: Boolean(worldEvent && observed.world_token && observed.world_token === worldEvent.response_token),
    within_challenge_window: Boolean(worldEvent && Number.isFinite(eventTime) && eventTime >= issued && eventTime <= expires),
    remote_address: worldEvent?.remote_address || null,
    response_token: worldEvent?.response_token || null,
    observed_world_token: observed.world_token,
    reason: null
  };
  if (live.disposition !== 'verified') {
    world.disposition = live.disposition;
    world.reason = 'base live challenge did not verify';
  } else if (!worldEvent) {
    world.disposition = 'abstain-needs-evidence';
    world.reason = 'coordinator-owned echo server recorded no request for this challenge nonce';
  } else if (!world.response_token_match || !world.within_challenge_window) {
    world.disposition = 'rejected';
    world.reason = 'coordinator world-contact event contradicts browser observation or challenge timing';
  } else {
    world.disposition = 'verified';
    world.passed = true;
    world.reason = 'browser observation matches coordinator-generated response token from an in-window request';
  }

  await writeUtf8(path.join(root, 'verdict-generic.json'), `${JSON.stringify(generic, null, 2)}\n`);
  await writeUtf8(path.join(root, 'verdict-live-challenge.json'), `${JSON.stringify(live, null, 2)}\n`);
  await writeUtf8(path.join(root, 'verdict-world-contact.json'), `${JSON.stringify(world, null, 2)}\n`);
  await writeUtf8(path.join(coordinatorDir, 'echo-events.json'), `${JSON.stringify(newEvents, null, 2)}\n`);
  await regenerateManifest(root);
  return { missionPassed, generic, live, world, observed, challenge, root };
}

async function main() {
  const host = arg('host', 'headless');
  const nodeName = arg('node', host);
  const tailnetIp = arg('tailnet-ip', null);
  const coordinatorIp = arg('coordinator-ip', '100.95.92.117');
  const remoteBinary = arg('remote', '/home/we4free/opt/aide-obscura-v0.2.0/obscura');
  const workspace = path.resolve(arg('workspace', process.cwd()));
  const outputArg = arg('output');
  if (!outputArg) throw new Error('--output is required');
  const outputRoot = path.resolve(outputArg);
  const expectedTitle = arg('expect-title', 'AIDE World Contact Probe');
  const expectedH1 = arg('expect-h1', expectedTitle);

  try { await fs.access(outputRoot); throw new Error(`output path already exists; refusing to overwrite: ${outputRoot}`); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before FALSIFY-1');
  await fs.mkdir(outputRoot, { recursive: true });

  const echo = await startEchoServer(coordinatorIp, expectedTitle);
  let honest, liar;
  try {
    console.log(`Coordinator echo: http://${coordinatorIp}:${echo.port}/probe`);

    const challengeH = newChallenge('honest', 'pending');
    const urlH = `http://${coordinatorIp}:${echo.port}/probe?n=${encodeURIComponent(challengeH.nonce)}`;
    const claimsH = claimsFor({ title: expectedTitle, url: urlH, h1: expectedH1 });
    challengeH.claim_contract_sha256 = sha256Canonical(claimsH);
    const honestClient = new RemoteMcpClient({ host, command: `${remoteBinary} mcp --allow-private-network` });
    console.log('01 honest Obscura → coordinator echo...');
    honest = await runTrial({
      root: path.join(outputRoot, '01-honest'), workspace, client: honestClient, challenge: challengeH,
      url: urlH, expectedTitle, expectedH1, evidenceClaims: claimsH, serverEvents: echo.events,
      kind: 'honest', nodeName, tailnetIp
    });
    console.log(`   generic=${honest.generic.disposition} live=${honest.live.disposition} world=${honest.world.disposition}`);
    if (!(honest.missionPassed && honest.generic.disposition === 'verified' && honest.live.disposition === 'verified' && honest.world.disposition === 'verified')) {
      await writeUtf8(path.join(outputRoot, 'baseline-failure.json'), `${JSON.stringify({ honest }, null, 2)}\n`);
      throw new Error('honest world-contact baseline did not fully verify; preserving baseline only');
    }

    const challengeL = newChallenge('liar', 'pending');
    const urlL = `http://${coordinatorIp}:${echo.port}/probe?n=${encodeURIComponent(challengeL.nonce)}`;
    const claimsL = claimsFor({ title: expectedTitle, url: urlL, h1: expectedH1 });
    challengeL.claim_contract_sha256 = sha256Canonical(claimsL);
    const liarClient = new RemoteMcpClient({ host, command: fakeWorkerCommand(expectedTitle) });
    console.log('02 lying MCP worker (no HTTP contact)...');
    liar = await runTrial({
      root: path.join(outputRoot, '02-liar'), workspace, client: liarClient, challenge: challengeL,
      url: urlL, expectedTitle, expectedH1, evidenceClaims: claimsL, serverEvents: echo.events,
      kind: 'liar', nodeName, tailnetIp
    });
    console.log(`   generic=${liar.generic.disposition} live=${liar.live.disposition} world=${liar.world.disposition}`);
  } finally {
    await echo.close();
  }

  const matrix = {
    schema: 'aide.consistent-fiction-world-contact/v1',
    honest: {
      mission: honest?.missionPassed || false,
      generic: honest?.generic?.disposition || null,
      live_challenge: honest?.live?.disposition || null,
      world_contact: honest?.world?.disposition || null
    },
    liar: {
      mission: liar?.missionPassed || false,
      generic: liar?.generic?.disposition || null,
      live_challenge: liar?.live?.disposition || null,
      world_contact: liar?.world?.disposition || null
    },
    findings: {
      self_consistent_fiction_passes_generic: liar?.generic?.disposition === 'verified',
      fresh_consistent_fiction_passes_live_challenge: liar?.live?.disposition === 'verified',
      coordinator_world_contact_blocks_liar: liar?.world?.disposition !== 'verified',
      honest_world_contact_verified: honest?.world?.disposition === 'verified'
    }
  };
  await writeUtf8(path.join(outputRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
  await writeUtf8(path.join(outputRoot, 'report.md'), [
    '# FALSIFY-1 — Consistent Fiction vs Coordinator-Owned World Contact', '',
    `Honest: generic=${matrix.honest.generic} live=${matrix.honest.live_challenge} world=${matrix.honest.world_contact}`,
    `Liar: generic=${matrix.liar.generic} live=${matrix.liar.live_challenge} world=${matrix.liar.world_contact}`,
    '',
    'The liar runs a live fake MCP worker over SSH, receives the real fresh coordinator challenge, and fabricates browser-shaped navigation/snapshot/evaluate/network results without making the HTTP request.',
    'If generic and live-challenge verification accept the liar but coordinator-world-contact does not, then freshness + self-consistent executor evidence are necessary but insufficient for proving contact with the world.',
    ''
  ].join('\n'));
  await regenerateManifest(outputRoot);

  console.log(`Matrix: ${path.join(outputRoot, 'matrix.json')}`);
  console.log(`Findings: ${JSON.stringify(matrix.findings)}`);

  const expected = matrix.findings.self_consistent_fiction_passes_generic &&
    matrix.findings.fresh_consistent_fiction_passes_live_challenge &&
    matrix.findings.coordinator_world_contact_blocks_liar &&
    matrix.findings.honest_world_contact_verified;
  if (!expected) process.exitCode = 1;
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
