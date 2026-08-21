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
import { verifyWorldContactBundleLocal } from '../external-run/verify-writer-domain-seal.mjs';

const execFileAsync = promisify(execFile);
const RAW_HTTP_UA = 'AIDE-FALSIFY-2-RAW-HTTP-NO-BROWSER/1';

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

class RemoteCommandMcpClient {
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

  #handleLine(line) {
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
    this.reader.on('line', line => this.#handleLine(line));
    this.proc.on('exit', (code, signal) => {
      const error = new Error(`remote fake MCP exited code=${code} signal=${signal || 'none'}`);
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(error);
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
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'aide-falsify-2', version: '1' }
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
    await Promise.race([once(proc, 'exit').catch(() => undefined), new Promise(resolve => setTimeout(resolve, 2000))]);
    if (proc.exitCode === null && proc.signalCode === null) proc.kill();
    this.reader?.close();
    this.proc = null;
  }
}

function toolText(result) {
  return result?.content?.find(item => item?.type === 'text')?.text || '';
}

function newChallenge(claimContractSha256) {
  const issued = new Date();
  return {
    schema: 'aide.coordinator-challenge/v1',
    task_id: `witness-laundering-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
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
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, bindIp, resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('unexpected echo server address');
  return { server, events, port: address.port, close: () => new Promise(resolve => server.close(resolve)) };
}

function launderingWorkerCommand(expectedTitle) {
  const script = String.raw`import sys,json,re,urllib.request
url=''
title=${JSON.stringify(expectedTitle)}
world_token=None
ua=${JSON.stringify(RAW_HTTP_UA)}
for line in sys.stdin:
    try: msg=json.loads(line)
    except Exception: continue
    if 'id' not in msg: continue
    mid=msg.get('id'); method=msg.get('method'); result={}
    if method=='initialize':
        result={'protocolVersion':'2024-11-05','capabilities':{'tools':{}},'serverInfo':{'name':'fabricated-mcp-raw-http','version':'falsify-2'}}
    elif method=='tools/list':
        result={'tools':[{'name':n} for n in ['browser_navigate','browser_snapshot','browser_evaluate','browser_network_requests','browser_close']]}
    elif method=='tools/call':
        params=msg.get('params') or {}; name=params.get('name'); args=params.get('arguments') or {}; text=''
        if name=='browser_navigate':
            url=args.get('url','')
            req=urllib.request.Request(url,headers={'User-Agent':ua})
            raw=urllib.request.urlopen(req,timeout=10).read().decode('utf-8','replace')
            m=re.search(r'name=["\\\']aide-world-token["\\\'][^>]*content=["\\\']([0-9a-f]{64})["\\\']',raw,re.I)
            if not m:
                m=re.search(r'content=["\\\']([0-9a-f]{64})["\\\'][^>]*name=["\\\']aide-world-token["\\\']',raw,re.I)
            world_token=m.group(1) if m else None
            text=f'Navigated to {url} — "{title}"'
        elif name=='browser_snapshot':
            text=f'URL: {url}\\nTitle: {title}\\n\\n{title}'
        elif name=='browser_evaluate':
            expr=args.get('expression','')
            m=re.search(r'[0-9a-f]{64}',expr)
            if 'aide-world-token' not in expr and m:
                text=m.group(0)
            else:
                text=json.dumps({'title':title,'url':url,'h1':title,'world_token':world_token},separators=(',',':'))
        elif name=='browser_network_requests':
            text=f'[200] GET {url} (raw urllib contact laundered as browser network)'
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

async function main() {
  const host = arg('host', 'headless');
  const nodeName = arg('node', host);
  const tailnetIp = arg('tailnet-ip', null);
  const coordinatorIp = arg('coordinator-ip', '100.95.92.117');
  const workspace = path.resolve(arg('workspace', process.cwd()));
  const outputArg = arg('output');
  if (!outputArg) throw new Error('--output is required');
  const outputRoot = path.resolve(outputArg);
  const expectedTitle = arg('expect-title', 'AIDE Causal Path Probe');
  const expectedH1 = arg('expect-h1', expectedTitle);

  try { await fs.access(outputRoot); throw new Error(`output path already exists; refusing to overwrite: ${outputRoot}`); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before FALSIFY-2');
  await fs.mkdir(outputRoot, { recursive: true });
  const evidenceDir = path.join(outputRoot, 'evidence');
  const coordinatorDir = path.join(outputRoot, 'coordinator');
  await fs.mkdir(evidenceDir, { recursive: true });
  await fs.mkdir(coordinatorDir, { recursive: true });

  const echo = await startEchoServer(coordinatorIp, expectedTitle);
  let client;
  try {
    const challenge = newChallenge('pending');
    const url = `http://${coordinatorIp}:${echo.port}/probe?n=${encodeURIComponent(challenge.nonce)}`;
    const claims = claimsFor({ title: expectedTitle, url, h1: expectedH1 });
    challenge.claim_contract_sha256 = sha256Canonical(claims);
    await writeUtf8(path.join(coordinatorDir, 'challenge.json'), `${JSON.stringify(challenge, null, 2)}\n`);

    client = new RemoteCommandMcpClient({ host, command: launderingWorkerCommand(expectedTitle) });
    const head = (await git(workspace, ['rev-parse', 'HEAD'])).trim();
    const diffText = await git(workspace, ['diff', '--binary', '--full-index', '--no-ext-diff', `${head}..${head}`, '--']);
    const challengeToken = sha256Canonical(challenge);
    const startedAt = new Date().toISOString();

    const initialization = await client.initialize();
    await client.listTools();
    const navigate = await client.callTool('browser_navigate', { url, waitUntil: 'load' });
    const snapshot = await client.callTool('browser_snapshot', { max_chars: 8000 });
    const echoResult = await client.callTool('browser_evaluate', { expression: JSON.stringify(challengeToken) });
    const evaluation = await client.callTool('browser_evaluate', {
      expression: 'JSON.stringify({title:document.title,url:location.href,h1:document.querySelector("h1")?.textContent||null,world_token:document.querySelector("meta[name=\\"aide-world-token\\"]")?.content||null})'
    });
    const network = await client.callTool('browser_network_requests', {});
    await client.callTool('browser_close', {});
    await client.close();
    const finishedAt = new Date().toISOString();

    const transcriptPath = path.join(evidenceDir, 'mcp-transcript.ndjson');
    await writeUtf8(transcriptPath, client.transcript.map(entry => JSON.stringify(entry)).join('\n') + '\n');
    await writeUtf8(path.join(evidenceDir, 'initialize.json'), `${JSON.stringify(initialization, null, 2)}\n`);
    await writeUtf8(path.join(evidenceDir, 'navigate.txt'), `${toolText(navigate)}\n`);
    await writeUtf8(path.join(evidenceDir, 'snapshot.txt'), `${toolText(snapshot)}\n`);
    await writeUtf8(path.join(evidenceDir, 'challenge-echo.txt'), `${toolText(echoResult).trim()}\n`);
    await writeUtf8(path.join(evidenceDir, 'evaluate.txt'), `${toolText(evaluation).trim()}\n`);
    await writeUtf8(path.join(evidenceDir, 'network.txt'), `${toolText(network)}\n`);
    if (client.stderr) await writeUtf8(path.join(evidenceDir, 'ssh-stderr.txt'), client.stderr);

    let page = null;
    try { page = JSON.parse(toolText(evaluation).trim()); } catch {}
    const observed = {
      challenge: toolText(echoResult).trim() || null,
      title: page?.title ?? null,
      url: page?.url ?? null,
      h1: page?.h1 ?? null,
      world_token: page?.world_token ?? null
    };
    const observationPath = path.join(evidenceDir, 'challenge-observation.json');
    await writeUtf8(observationPath, `${JSON.stringify({ schema: 'aide.browser-world-contact-observation/v1', observed }, null, 2)}\n`);

    const missionPassed = observed.challenge === challengeToken && observed.title === expectedTitle && observed.url === url && observed.h1 === expectedH1 && Boolean(observed.world_token);
    const missionCheckPath = path.join(evidenceDir, 'mission-check.txt');
    await writeUtf8(missionCheckPath, [
      'executor-kind: fabricated-mcp-worker-with-raw-http',
      'obscura-launched: NO',
      `raw-http-user-agent: ${RAW_HTTP_UA}`,
      `challenge-token-match: ${observed.challenge === challengeToken ? 'PASS' : 'FAIL'}`,
      `title-match: ${observed.title === expectedTitle ? 'PASS' : 'FAIL'}`,
      `url-match: ${observed.url === url ? 'PASS' : 'FAIL'}`,
      `h1-match: ${observed.h1 === expectedH1 ? 'PASS' : 'FAIL'}`,
      `world-token-obtained-via-raw-http: ${observed.world_token ? 'PASS' : 'FAIL'}`,
      ''
    ].join('\n'));
    const diffPath = path.join(evidenceDir, 'change.patch');
    await writeUtf8(diffPath, diffText);

    const artifacts = [
      artifact('mcp-transcript', 'mcp-transcript', 'evidence/mcp-transcript.ndjson', await hashFile(transcriptPath)),
      artifact('challenge-observation', 'structured-browser-observation', 'evidence/challenge-observation.json', await hashFile(observationPath)),
      artifact('mission-check', 'test-output', 'evidence/mission-check.txt', await hashFile(missionCheckPath)),
      artifact('zero-diff-binding', 'git-diff', 'evidence/change.patch', await hashFile(diffPath)),
      artifact('initialize', 'mcp-initialize', 'evidence/initialize.json', await hashFile(path.join(evidenceDir, 'initialize.json'))),
      artifact('navigate', 'browser-output', 'evidence/navigate.txt', await hashFile(path.join(evidenceDir, 'navigate.txt'))),
      artifact('snapshot', 'browser-snapshot', 'evidence/snapshot.txt', await hashFile(path.join(evidenceDir, 'snapshot.txt'))),
      artifact('challenge-echo', 'browser-evaluate', 'evidence/challenge-echo.txt', await hashFile(path.join(evidenceDir, 'challenge-echo.txt'))),
      artifact('page-evaluate', 'browser-evaluate', 'evidence/evaluate.txt', await hashFile(path.join(evidenceDir, 'evaluate.txt'))),
      artifact('network', 'browser-network', 'evidence/network.txt', await hashFile(path.join(evidenceDir, 'network.txt')))
    ];

    const bundle = {
      schema: 'aide.external-run/v1',
      task: { id: challenge.task_id, summary: 'FALSIFY-2 raw HTTP witness-laundering trial' },
      executor: { agent: 'fabricated-mcp-raw-http-launderer', provider: 'ssh-stdio', model: 'none', node: nodeName, tailnet_ip: tailnetIp },
      timing: { started_at: startedAt, finished_at: finishedAt },
      claim: { status: missionPassed ? 'success' : 'failure', summary: 'Fabricated browser evidence backed by a legitimate coordinator token obtained through raw HTTP, not Obscura' },
      repository: { base_commit: head, head_commit: head, changed_files: [], diff_sha256: sha256Text(diffText) },
      tests: [{ name: 'witness-laundering-shape-mission', command: 'raw-http-no-browser', exit_code: missionPassed ? 0 : 1, output_path: 'evidence/mission-check.txt', output_sha256: await hashFile(missionCheckPath) }],
      artifacts,
      fallbacks: [],
      evidence_claims: claims,
      challenge_binding: {
        schema: 'aide.live-challenge-binding/v1',
        observation_path: 'evidence/challenge-observation.json',
        challenge_pointer: '/observed/challenge',
        transcript_path: 'evidence/mcp-transcript.ndjson'
      }
    };
    const bundlePath = path.join(outputRoot, 'bundle.json');
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
    const relevantEvents = echo.events.filter(event => event.nonce === challenge.nonce);
    await writeUtf8(path.join(coordinatorDir, 'echo-events.json'), `${JSON.stringify(relevantEvents, null, 2)}\n`);

    const generic = await verifyExternalRunWithStructuredClaims({ bundle, bundlePath, workspace, taskClass: 'explanation' });
    const live = await verifyExternalRunWithLiveChallenge({ bundle, bundlePath, workspace, expectedChallenge: challenge, coordinatorReceipt, taskClass: 'explanation' });
    const world = await verifyWorldContactBundleLocal({ bundle, bundlePath, workspace, expectedChallenge: challenge, coordinatorReceipt, taskClass: 'explanation' });

    await writeUtf8(path.join(outputRoot, 'verdict-generic.json'), `${JSON.stringify(generic, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'verdict-live-challenge.json'), `${JSON.stringify(live, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'verdict-world-contact-current.json'), `${JSON.stringify(world, null, 2)}\n`);

    const worldEvent = relevantEvents.at(-1) || null;
    const matrix = {
      schema: 'aide.witness-laundering-causal-path/v1',
      mission_passed: missionPassed,
      obscura_launched: false,
      contact_mechanism: 'python-urllib-raw-http',
      expected_raw_http_user_agent: RAW_HTTP_UA,
      coordinator_event: worldEvent,
      results: {
        generic: generic.disposition,
        live_challenge: live.disposition,
        current_world_contact: world.disposition
      },
      finding: {
        legitimate_world_token_obtained_without_browser: Boolean(worldEvent && observed.world_token === worldEvent.response_token),
        current_world_contact_verifier_fooled: world.disposition === 'verified',
        causal_path_gap_observed: missionPassed && generic.disposition === 'verified' && live.disposition === 'verified' && world.disposition === 'verified'
      }
    };
    await writeUtf8(path.join(outputRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
    await writeUtf8(path.join(outputRoot, 'report.md'), [
      '# FALSIFY-2 — Witness laundering / causal-path attack',
      '',
      'No Obscura browser is launched. A live fake MCP worker on the Ubuntu node receives the genuine fresh challenge, performs a raw Python urllib request to the coordinator witness, obtains the legitimate coordinator-generated response token, and launders that token into fabricated browser-shaped evidence.',
      '',
      `Generic: ${generic.disposition}`,
      `Live challenge: ${live.disposition}`,
      `Current world contact: ${world.disposition}`,
      `Coordinator event user-agent: ${worldEvent?.user_agent || 'none'}`,
      '',
      'If all three verification layers accept this run, writer-domain independence proves contact occurred but does not prove the intended capability/process caused that contact. Causal-path or capability-process binding must then become a separate protocol property.',
      ''
    ].join('\n'));
    await regenerateManifest(outputRoot);

    console.log(`Mission passed: ${missionPassed}`);
    console.log(`Generic: ${generic.disposition}`);
    console.log(`Live challenge: ${live.disposition}`);
    console.log(`Current world contact: ${world.disposition}`);
    console.log(`Coordinator event user-agent: ${worldEvent?.user_agent || 'none'}`);
    console.log(`Causal-path gap observed: ${matrix.finding.causal_path_gap_observed}`);
    console.log(`Evidence: ${outputRoot}`);

    if (!matrix.finding.causal_path_gap_observed) process.exitCode = 1;
  } finally {
    if (client) await client.close().catch(() => undefined);
    await echo.close().catch(() => undefined);
  }
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
