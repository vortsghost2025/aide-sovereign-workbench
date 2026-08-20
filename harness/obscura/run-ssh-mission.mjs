import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { SshMcpClient, toolText } from './ssh-mcp-client.mjs';
import { sha256Buffer, sha256Text, verifyExternalRun } from '../external-run/verify.mjs';
import { renderExternalRunReport } from '../external-run/report.mjs';

const execFileAsync = promisify(execFile);

function readArg(name, fallback = null) {
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
    timeout: 120_000
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

function evidenceArtifact(name, kind, relativePath, sha256) {
  return { name, kind, path: relativePath.replaceAll('\\', '/'), sha256 };
}

function checkLine(name, passed, detail = '') {
  return `${passed ? 'PASS' : 'FAIL'} ${name}${detail ? ` - ${detail}` : ''}`;
}

function parseObscuraCliVersion(text) {
  const match = String(text || '').trim().match(/^obscura\s+([^\s]+)$/m);
  return match?.[1] || null;
}

async function probeRemoteCliVersion(host, remoteBinary) {
  try {
    const { stdout, stderr } = await execFileAsync('ssh', [
      '-T',
      '-o', 'BatchMode=yes',
      '-o', 'ConnectTimeout=10',
      host,
      remoteBinary,
      '--version'
    ], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
      timeout: 30_000,
      windowsHide: true
    });
    const text = String(stdout || '').trim();
    return {
      ok: true,
      text,
      stderr: String(stderr || '').trim(),
      version: parseObscuraCliVersion(text)
    };
  } catch (error) {
    return {
      ok: false,
      text: String(error?.stdout || '').trim(),
      stderr: String(error?.stderr || '').trim(),
      version: null,
      error: error?.message || String(error)
    };
  }
}

async function main() {
  const host = readArg('host', 'headless');
  const nodeName = readArg('node', host);
  const tailnetIp = readArg('tailnet-ip', null);
  const remoteBinary = readArg('remote', '/home/we4free/opt/aide-obscura-v0.2.0/obscura');
  const url = readArg('url', 'https://example.com');
  const expectedTitle = readArg('expect-title', 'Example Domain');
  const expectedVersion = readArg('expect-version', '0.2.0');
  const workspace = path.resolve(readArg('workspace', process.cwd()));
  const outputRootArg = readArg('output');
  if (!outputRootArg) throw new Error('--output is required');
  const outputRoot = path.resolve(outputRootArg);

  try {
    await fs.access(outputRoot);
    throw new Error(`output path already exists; refusing to overwrite evidence: ${outputRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before the browser evidence run');

  const head = (await git(workspace, ['rev-parse', 'HEAD'])).trim();
  if (!/^[a-f0-9]{40}$/i.test(head)) throw new Error(`unexpected Git HEAD: ${head}`);

  const evidenceDir = path.join(outputRoot, 'evidence');
  await fs.mkdir(evidenceDir, { recursive: true });
  const startedAt = new Date().toISOString();

  const cliProbe = await probeRemoteCliVersion(host, remoteBinary);
  await writeUtf8(
    path.join(evidenceDir, 'cli-version.txt'),
    `${cliProbe.text || ''}${cliProbe.stderr ? `\nstderr: ${cliProbe.stderr}` : ''}${cliProbe.error ? `\nerror: ${cliProbe.error}` : ''}\n`
  );

  const client = new SshMcpClient({ host, remoteBinary, timeoutMs: 30_000 });
  let initialization;
  let tools;
  let navigate;
  let snapshot;
  let markdown;
  let links;
  let evaluation;
  let network;
  let missionError = null;

  try {
    initialization = await client.initialize();
    tools = await client.listTools();
    navigate = await client.callTool('browser_navigate', { url, waitUntil: 'load' });
    snapshot = await client.callTool('browser_snapshot', { max_chars: 8000 });
    markdown = await client.callTool('browser_markdown', { max_chars: 8000 });
    links = await client.callTool('browser_links', { limit: 50 });
    evaluation = await client.callTool('browser_evaluate', {
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
  await writeUtf8(
    transcriptPath,
    client.transcript.map(entry => JSON.stringify(entry)).join('\n') + (client.transcript.length ? '\n' : '')
  );
  if (client.stderr) await writeUtf8(path.join(evidenceDir, 'ssh-stderr.txt'), client.stderr);

  if (initialization) await writeUtf8(path.join(evidenceDir, 'initialize.json'), `${JSON.stringify(initialization, null, 2)}\n`);
  if (tools) await writeUtf8(path.join(evidenceDir, 'tools.json'), `${JSON.stringify(tools, null, 2)}\n`);
  if (navigate) await writeUtf8(path.join(evidenceDir, 'navigate.txt'), `${toolText(navigate)}\n`);
  if (snapshot) await writeUtf8(path.join(evidenceDir, 'snapshot.txt'), `${toolText(snapshot)}\n`);
  if (markdown) await writeUtf8(path.join(evidenceDir, 'markdown.txt'), `${toolText(markdown)}\n`);
  if (links) await writeUtf8(path.join(evidenceDir, 'links.txt'), `${toolText(links)}\n`);
  if (evaluation) await writeUtf8(path.join(evidenceDir, 'evaluate.txt'), `${toolText(evaluation)}\n`);
  if (network) await writeUtf8(path.join(evidenceDir, 'network.txt'), `${toolText(network)}\n`);
  if (missionError) await writeUtf8(path.join(evidenceDir, 'mission-error.txt'), `${missionError.stack || missionError.message}\n`);

  const toolNames = Array.isArray(tools?.tools) ? tools.tools.map(tool => tool?.name).filter(Boolean) : [];
  const requiredTools = [
    'browser_navigate',
    'browser_snapshot',
    'browser_markdown',
    'browser_links',
    'browser_evaluate',
    'browser_network_requests',
    'browser_close'
  ];
  const snapshotText = toolText(snapshot);
  const markdownText = toolText(markdown);
  const evaluationText = toolText(evaluation);
  const mcpServerVersion = initialization?.serverInfo?.version || null;
  const mcpProtocolVersion = initialization?.protocolVersion || null;

  const assertions = [
    ['cli-version-probe', cliProbe.ok, cliProbe.error || cliProbe.text || 'missing'],
    ['obscura-cli-version', cliProbe.version === expectedVersion, `${cliProbe.version || 'missing'} expected ${expectedVersion}`],
    ['mcp-initialized', initialization?.serverInfo?.name === 'obscura-mcp', initialization?.serverInfo?.name || 'missing'],
    ['mcp-protocol', mcpProtocolVersion === '2024-11-05', mcpProtocolVersion || 'missing'],
    ['required-tools', requiredTools.every(name => toolNames.includes(name)), requiredTools.filter(name => !toolNames.includes(name)).join(', ') || 'all present'],
    ['navigation-completed', Boolean(navigate) && !missionError, missionError?.message || toolText(navigate)],
    ['snapshot-title', snapshotText.includes(expectedTitle), expectedTitle],
    ['markdown-title', markdownText.includes(expectedTitle), expectedTitle],
    ['evaluated-title', evaluationText.includes(expectedTitle), expectedTitle],
    ['evaluated-url', evaluationText.includes('https://example.com'), 'https://example.com'],
    ['network-evidence', Boolean(network), network ? 'captured' : 'missing'],
    ['transcript-nonempty', client.transcript.length > 0, `${client.transcript.length} events`]
  ];

  const missionPassed = assertions.every(([, passed]) => passed);
  const missionCheckText = assertions.map(([name, passed, detail]) => checkLine(name, passed, detail)).join('\n') + '\n';
  const missionCheckPath = path.join(evidenceDir, 'mission-check.txt');
  await writeUtf8(missionCheckPath, missionCheckText);

  const diffText = await git(workspace, ['diff', '--binary', '--full-index', '--no-ext-diff', `${head}..${head}`, '--']);
  const diffPath = path.join(evidenceDir, 'change.patch');
  await writeUtf8(diffPath, diffText);

  const evidenceFiles = [
    ['cli-version', 'runtime-version', 'evidence/cli-version.txt'],
    ['mcp-transcript', 'mcp-transcript', 'evidence/mcp-transcript.ndjson'],
    ['initialize', 'mcp-initialize', 'evidence/initialize.json'],
    ['tool-catalog', 'mcp-tools', 'evidence/tools.json'],
    ['browser-navigation', 'browser-output', 'evidence/navigate.txt'],
    ['browser-snapshot', 'browser-snapshot', 'evidence/snapshot.txt'],
    ['browser-markdown', 'browser-markdown', 'evidence/markdown.txt'],
    ['browser-links', 'browser-links', 'evidence/links.txt'],
    ['browser-evaluation', 'browser-evaluate', 'evidence/evaluate.txt'],
    ['browser-network', 'browser-network', 'evidence/network.txt'],
    ['mission-check', 'test-output', 'evidence/mission-check.txt'],
    ['zero-diff-binding', 'git-diff', 'evidence/change.patch']
  ];

  const artifacts = [];
  for (const [name, kind, relative] of evidenceFiles) {
    const absolute = path.join(outputRoot, relative);
    try {
      artifacts.push(evidenceArtifact(name, kind, relative, await hashFile(absolute)));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  if (missionError) {
    artifacts.push(evidenceArtifact('mission-error', 'error', 'evidence/mission-error.txt', await hashFile(path.join(evidenceDir, 'mission-error.txt'))));
  }
  if (client.stderr) {
    artifacts.push(evidenceArtifact('ssh-stderr', 'transport-stderr', 'evidence/ssh-stderr.txt', await hashFile(path.join(evidenceDir, 'ssh-stderr.txt'))));
  }

  const bundle = {
    schema: 'aide.external-run/v1',
    task: {
      id: `obscura-ssh-browser-${Date.now()}`,
      summary: `Verify a remote Obscura MCP browser mission over SSH against ${url}`
    },
    executor: {
      agent: 'obscura-mcp-over-ssh',
      provider: 'ssh-stdio',
      model: 'none',
      transport_host: host,
      node: nodeName,
      tailnet_ip: tailnetIp,
      engine: 'obscura',
      engine_version: cliProbe.version || 'unknown',
      mcp_server: initialization?.serverInfo?.name || 'unknown',
      mcp_server_version: mcpServerVersion || 'unknown',
      mcp_protocol_version: mcpProtocolVersion || 'unknown'
    },
    timing: { started_at: startedAt, finished_at: finishedAt },
    claim: {
      status: missionPassed ? 'success' : 'failure',
      summary: missionPassed ? 'Remote browser mission completed and deterministic assertions passed' : 'Remote browser mission did not satisfy every deterministic assertion'
    },
    repository: {
      base_commit: head,
      head_commit: head,
      changed_files: [],
      diff_sha256: sha256Text(diffText)
    },
    tests: [{
      name: 'obscura-ssh-browser-mission',
      command: `ssh ${host} ${remoteBinary} mcp`,
      exit_code: missionPassed ? 0 : 1,
      output_path: 'evidence/mission-check.txt',
      output_sha256: await hashFile(missionCheckPath)
    }],
    artifacts,
    fallbacks: []
  };

  const bundlePath = path.join(outputRoot, 'bundle.json');
  await writeUtf8(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`);

  const verdict = await verifyExternalRun({ bundle, bundlePath, workspace, taskClass: 'explanation' });
  await writeUtf8(path.join(outputRoot, 'verdict.json'), `${JSON.stringify(verdict, null, 2)}\n`);

  const evidenceReport = renderExternalRunReport(verdict);
  const combinedReport = [
    '# AIDE Distributed Browser Run',
    '',
    `Execution outcome: ${missionPassed ? 'PASS' : 'FAIL'}`,
    `Evidence verification: ${String(verdict.disposition || 'unknown').toUpperCase()}`,
    `Obscura CLI: ${cliProbe.version || 'unknown'}`,
    `Obscura MCP server: ${mcpServerVersion || 'unknown'}`,
    `MCP protocol: ${mcpProtocolVersion || 'unknown'}`,
    `Transport: SSH stdio via ${host}`,
    `Node: ${nodeName}${tailnetIp ? ` (${tailnetIp})` : ''}`,
    '',
    'Execution success and evidence verification are independent axes. A failed execution may still have authentic, internally consistent evidence.',
    '',
    '---',
    '',
    evidenceReport,
    ''
  ].join('\n');
  await writeUtf8(path.join(outputRoot, 'report.md'), combinedReport);

  const manifestEntries = [];
  async function walk(directory) {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else manifestEntries.push({
        path: path.relative(outputRoot, absolute).replaceAll('\\', '/'),
        sha256: await hashFile(absolute)
      });
    }
  }
  await walk(outputRoot);
  manifestEntries.sort((a, b) => a.path.localeCompare(b.path));
  await writeUtf8(path.join(outputRoot, 'manifest.sha256.json'), `${JSON.stringify(manifestEntries, null, 2)}\n`);

  console.log(`Execution outcome: ${missionPassed ? 'PASS' : 'FAIL'}`);
  console.log(`Evidence verification: ${verdict.disposition}`);
  console.log(`Evidence score: ${Math.round(verdict.evidence_score * 100)}%`);
  console.log(`Obscura CLI: ${cliProbe.version || 'unknown'}`);
  console.log(`Obscura MCP server: ${mcpServerVersion || 'unknown'} (protocol ${mcpProtocolVersion || 'unknown'})`);
  console.log(`Node: ${nodeName}${tailnetIp ? ` ${tailnetIp}` : ''} via ssh ${host}`);
  console.log(`Evidence: ${outputRoot}`);

  if (!missionPassed || verdict.disposition !== 'verified') process.exitCode = 1;
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
