import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { SshMcpClient, toolText } from './ssh-mcp-client.mjs';
import { sha256Buffer, sha256Text } from '../external-run/verify.mjs';
import { verifyExternalRunWithStructuredClaims } from '../external-run/verify-structured-claims.mjs';
import { renderExternalRunReport } from '../external-run/report.mjs';

const execFileAsync = promisify(execFile);

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  if (index < 0) return fallback;
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`--${name} requires a value`);
  return value;
}

function assertSafeHost(value) {
  if (!/^[A-Za-z0-9._-]+$/.test(value)) throw new Error(`unsafe SSH host token: ${value}`);
  return value;
}

function assertSafeRemotePath(value) {
  if (!/^\/[A-Za-z0-9._/-]+$/.test(value)) throw new Error(`unsafe remote path: ${value}`);
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

async function ssh(host, command, timeout = 20_000) {
  try {
    const { stdout, stderr } = await execFileAsync('ssh', [
      '-T',
      '-o', 'BatchMode=yes',
      '-o', 'ConnectTimeout=10',
      host,
      command
    ], {
      encoding: 'utf8',
      maxBuffer: 2 * 1024 * 1024,
      timeout,
      windowsHide: true
    });
    return { ok: true, stdout: String(stdout || '').trim(), stderr: String(stderr || '').trim(), exit_code: 0 };
  } catch (error) {
    return {
      ok: false,
      stdout: String(error?.stdout || '').trim(),
      stderr: String(error?.stderr || '').trim(),
      exit_code: Number.isInteger(error?.code) ? error.code : null,
      error: error?.message || String(error)
    };
  }
}

async function installTrackedWrapper(host, remoteBinary, label) {
  const token = `${label}-${randomUUID()}`.replaceAll('-', '');
  const wrapper = assertSafeRemotePath(`/tmp/aide-obscura-${token}.sh`);
  const pidfile = assertSafeRemotePath(`/tmp/aide-obscura-${token}.pid`);
  const script = [
    '#!/bin/sh',
    'set -eu',
    `printf '%s\\n' "$$" > '${pidfile}'`,
    `exec '${remoteBinary}' "$@"`,
    ''
  ].join('\n');
  const payload = Buffer.from(script, 'utf8').toString('base64');
  const command = `umask 077; printf '%s' '${payload}' | base64 -d > '${wrapper}'; chmod 700 '${wrapper}'`;
  const result = await ssh(host, command);
  if (!result.ok) throw new Error(`unable to install tracked Obscura wrapper: ${result.stderr || result.error}`);
  return { wrapper, pidfile };
}

async function killTrackedRemote(host, pidfile, remoteBinary) {
  const command = [
    `pid=$(cat '${pidfile}' 2>/dev/null || true)`,
    'if [ -z "$pid" ]; then echo pid-missing; exit 0; fi',
    'if [ ! -r "/proc/$pid/cmdline" ]; then echo gone; exit 0; fi',
    'cmd=$(tr "\\000" " " < "/proc/$pid/cmdline")',
    `case "$cmd" in *"${remoteBinary} mcp"*) kill -TERM "$pid"; echo "killed:$pid"; exit 0 ;; *) echo "refused:$pid:$cmd" >&2; exit 42 ;; esac`
  ].join('; ');
  return ssh(host, command);
}

async function removeTrackedFiles(host, wrapper, pidfile) {
  return ssh(host, `rm -f '${wrapper}' '${pidfile}'`);
}

async function waitForExit(proc, timeoutMs = 5_000) {
  if (!proc) return { exited: false, reason: 'missing-process' };
  if (proc.exitCode !== null || proc.signalCode !== null) {
    return { exited: true, code: proc.exitCode, signal: proc.signalCode || null };
  }
  return Promise.race([
    once(proc, 'exit').then(([code, signal]) => ({ exited: true, code, signal: signal || null })),
    new Promise(resolve => setTimeout(() => resolve({ exited: false, reason: 'timeout' }), timeoutMs))
  ]);
}

function parseObservation(text) {
  const raw = String(text || '').trim();
  if (!raw) throw new Error('browser evaluation returned empty observation');
  let value = JSON.parse(raw);
  if (typeof value === 'string') value = JSON.parse(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('browser observation is not a JSON object');
  return value;
}

async function browseOnce({ host, remoteBinary, url, timeoutMs = 10_000 }) {
  const client = new SshMcpClient({ host, remoteBinary, timeoutMs });
  let observation = null;
  try {
    await client.initialize();
    await client.callTool('browser_navigate', { url, waitUntil: 'load' });
    const evaluation = await client.callTool('browser_evaluate', {
      expression: 'JSON.stringify({title:document.title,url:location.href,h1:document.querySelector("h1")?.textContent||null})'
    });
    observation = parseObservation(toolText(evaluation));
    await client.callTool('browser_close', {});
  } finally {
    await client.close();
  }
  return { observation, transcript: client.transcript, stderr: client.stderr };
}

async function crashCase({ host, remoteBinary, url, expectedTitle }) {
  const tracked = await installTrackedWrapper(host, remoteBinary, 'crash');
  const client = new SshMcpClient({ host, remoteBinary: tracked.wrapper, timeoutMs: 8_000 });
  let preCrashObservation = null;
  let killResult = null;
  let exit = { exited: false, reason: 'not-run' };
  let recovery = null;
  let error = null;

  try {
    await client.initialize();
    await client.callTool('browser_navigate', { url, waitUntil: 'load' });
    const before = await client.callTool('browser_evaluate', {
      expression: 'JSON.stringify({title:document.title,url:location.href})'
    });
    preCrashObservation = parseObservation(toolText(before));

    killResult = await killTrackedRemote(host, tracked.pidfile, remoteBinary);
    if (!killResult.ok) throw new Error(`safe remote kill failed: ${killResult.stderr || killResult.error}`);
    exit = await waitForExit(client.proc, 5_000);
    if (!exit.exited) throw new Error('SSH MCP process did not exit after exact remote Obscura termination');
  } catch (caseError) {
    error = caseError?.message || String(caseError);
  } finally {
    await client.close().catch(() => undefined);
  }

  try {
    recovery = await browseOnce({ host, remoteBinary, url });
  } catch (recoveryError) {
    error = [error, `recovery failed: ${recoveryError?.message || recoveryError}`].filter(Boolean).join(' | ');
  }

  const finalCleanup = await killTrackedRemote(host, tracked.pidfile, remoteBinary);
  await removeTrackedFiles(host, tracked.wrapper, tracked.pidfile);

  const recoveredTitle = recovery?.observation?.title || null;
  const passed = Boolean(killResult?.ok && exit.exited && recovery && recoveredTitle === expectedTitle && finalCleanup.ok);
  return {
    passed,
    remote_kill_safe: Boolean(killResult?.ok),
    remote_kill_message: killResult?.stdout || killResult?.stderr || null,
    remote_process_exit_detected: Boolean(exit.exited),
    remote_process_exit: exit,
    pre_crash_title: preCrashObservation?.title || null,
    recovered: Boolean(recovery),
    recovered_title: recoveredTitle,
    recovery_observation: recovery?.observation || null,
    cleanup_safe: Boolean(finalCleanup.ok),
    error,
    before_transcript: client.transcript,
    before_stderr: client.stderr,
    recovery_transcript: recovery?.transcript || [],
    recovery_stderr: recovery?.stderr || ''
  };
}

async function transportCase({ host, remoteBinary, url, expectedTitle }) {
  const tracked = await installTrackedWrapper(host, remoteBinary, 'transport');
  const client = new SshMcpClient({ host, remoteBinary: tracked.wrapper, timeoutMs: 8_000 });
  let preInterruptObservation = null;
  let interruptIssued = false;
  let exit = { exited: false, reason: 'not-run' };
  let cleanup = null;
  let recovery = null;
  let error = null;

  try {
    await client.initialize();
    await client.callTool('browser_navigate', { url, waitUntil: 'load' });
    const before = await client.callTool('browser_evaluate', {
      expression: 'JSON.stringify({title:document.title,url:location.href})'
    });
    preInterruptObservation = parseObservation(toolText(before));

    interruptIssued = Boolean(client.proc?.kill());
    exit = await waitForExit(client.proc, 5_000);
    if (!interruptIssued || !exit.exited) throw new Error('local SSH transport interruption was not observed');
  } catch (caseError) {
    error = caseError?.message || String(caseError);
  } finally {
    await client.close().catch(() => undefined);
  }

  cleanup = await killTrackedRemote(host, tracked.pidfile, remoteBinary);
  await removeTrackedFiles(host, tracked.wrapper, tracked.pidfile);

  try {
    recovery = await browseOnce({ host, remoteBinary, url });
  } catch (recoveryError) {
    error = [error, `recovery failed: ${recoveryError?.message || recoveryError}`].filter(Boolean).join(' | ');
  }

  const recoveredTitle = recovery?.observation?.title || null;
  const passed = Boolean(interruptIssued && exit.exited && cleanup.ok && recovery && recoveredTitle === expectedTitle);
  return {
    passed,
    local_ssh_interrupt_issued: interruptIssued,
    ssh_exit_detected: Boolean(exit.exited),
    ssh_exit: exit,
    pre_interrupt_title: preInterruptObservation?.title || null,
    remote_cleanup_safe: Boolean(cleanup?.ok),
    remote_cleanup_message: cleanup?.stdout || cleanup?.stderr || null,
    recovered: Boolean(recovery),
    recovered_title: recoveredTitle,
    recovery_observation: recovery?.observation || null,
    error,
    before_transcript: client.transcript,
    before_stderr: client.stderr,
    recovery_transcript: recovery?.transcript || [],
    recovery_stderr: recovery?.stderr || ''
  };
}

function caseText(name, result, expectedTitle) {
  return [
    `${name}: ${result.passed ? 'PASS' : 'FAIL'}`,
    `expected recovered title: ${expectedTitle}`,
    `observed recovered title: ${result.recovered_title || 'missing'}`,
    `recovered: ${result.recovered}`,
    `error: ${result.error || 'none'}`,
    ''
  ].join('\n');
}

function transcriptText(entries) {
  return entries.map(item => JSON.stringify(item)).join('\n') + (entries.length ? '\n' : '');
}

async function main() {
  const host = assertSafeHost(arg('host', 'headless'));
  const nodeName = arg('node', host);
  const tailnetIp = arg('tailnet-ip', null);
  const remoteBinary = assertSafeRemotePath(arg('remote', '/home/we4free/opt/aide-obscura-v0.2.0/obscura'));
  const url = arg('url', 'https://example.com');
  const expectedTitle = arg('expect-title', 'Example Domain');
  const workspace = path.resolve(arg('workspace', process.cwd()));
  const outputArg = arg('output');
  if (!outputArg) throw new Error('--output is required');
  const outputRoot = path.resolve(outputArg);

  try {
    await fs.access(outputRoot);
    throw new Error(`output already exists; refusing to overwrite: ${outputRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before resilience evidence run');
  const head = (await git(workspace, ['rev-parse', 'HEAD'])).trim();
  if (!/^[a-f0-9]{40}$/i.test(head)) throw new Error(`unexpected Git HEAD: ${head}`);

  const evidenceDir = path.join(outputRoot, 'evidence');
  await fs.mkdir(evidenceDir, { recursive: true });
  const startedAt = new Date().toISOString();

  console.log('01 remote-process crash/recovery...');
  const crash = await crashCase({ host, remoteBinary, url, expectedTitle });
  console.log(`   ${crash.passed ? 'PASS' : 'FAIL'} recovered=${crash.recovered_title || 'missing'}`);

  console.log('02 SSH transport interruption/recovery...');
  const transport = await transportCase({ host, remoteBinary, url, expectedTitle });
  console.log(`   ${transport.passed ? 'PASS' : 'FAIL'} recovered=${transport.recovered_title || 'missing'}`);

  const finishedAt = new Date().toISOString();
  const observation = {
    schema: 'aide.obscura-runtime-resilience/v1',
    node: nodeName,
    tailnet_ip: tailnetIp,
    transport_host: host,
    target_url: url,
    crash: {
      passed: crash.passed,
      remote_kill_safe: crash.remote_kill_safe,
      remote_process_exit_detected: crash.remote_process_exit_detected,
      recovered: crash.recovered,
      recovered_title: crash.recovered_title,
      cleanup_safe: crash.cleanup_safe
    },
    transport: {
      passed: transport.passed,
      local_ssh_interrupt_issued: transport.local_ssh_interrupt_issued,
      ssh_exit_detected: transport.ssh_exit_detected,
      remote_cleanup_safe: transport.remote_cleanup_safe,
      recovered: transport.recovered,
      recovered_title: transport.recovered_title
    }
  };

  const observationPath = path.join(evidenceDir, 'runtime-resilience.json');
  const crashPath = path.join(evidenceDir, 'crash-recovery.txt');
  const transportPath = path.join(evidenceDir, 'transport-recovery.txt');
  await writeUtf8(observationPath, `${JSON.stringify(observation, null, 2)}\n`);
  await writeUtf8(crashPath, caseText('remote-process-crash-recovery', crash, expectedTitle));
  await writeUtf8(transportPath, caseText('ssh-transport-interruption-recovery', transport, expectedTitle));
  await writeUtf8(path.join(evidenceDir, 'crash-before.ndjson'), transcriptText(crash.before_transcript));
  await writeUtf8(path.join(evidenceDir, 'crash-recovery.ndjson'), transcriptText(crash.recovery_transcript));
  await writeUtf8(path.join(evidenceDir, 'transport-before.ndjson'), transcriptText(transport.before_transcript));
  await writeUtf8(path.join(evidenceDir, 'transport-recovery.ndjson'), transcriptText(transport.recovery_transcript));
  if (crash.before_stderr) await writeUtf8(path.join(evidenceDir, 'crash-before-stderr.txt'), crash.before_stderr);
  if (crash.recovery_stderr) await writeUtf8(path.join(evidenceDir, 'crash-recovery-stderr.txt'), crash.recovery_stderr);
  if (transport.before_stderr) await writeUtf8(path.join(evidenceDir, 'transport-before-stderr.txt'), transport.before_stderr);
  if (transport.recovery_stderr) await writeUtf8(path.join(evidenceDir, 'transport-recovery-stderr.txt'), transport.recovery_stderr);

  const diffText = await git(workspace, ['diff', '--binary', '--full-index', '--no-ext-diff', `${head}..${head}`, '--']);
  const diffPath = path.join(evidenceDir, 'change.patch');
  await writeUtf8(diffPath, diffText);

  const artifacts = [];
  for (const entry of await fs.readdir(evidenceDir, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const absolute = path.join(evidenceDir, entry.name);
    artifacts.push({
      name: entry.name.replace(/\.[^.]+$/, ''),
      kind: entry.name === 'change.patch' ? 'git-diff' : entry.name === 'runtime-resilience.json' ? 'browser-resilience-observation' : 'runtime-evidence',
      path: `evidence/${entry.name}`,
      sha256: await hashFile(absolute)
    });
  }

  const allPassed = crash.passed && transport.passed;
  const bundle = {
    schema: 'aide.external-run/v1',
    task: {
      id: `obscura-runtime-resilience-${Date.now()}`,
      summary: 'Verify recovery after an exact remote Obscura MCP process termination and an independent SSH transport interruption'
    },
    executor: {
      agent: 'aide-obscura-runtime-resilience',
      provider: 'ssh-stdio',
      model: 'none',
      transport_host: host,
      node: nodeName,
      tailnet_ip: tailnetIp,
      engine: 'obscura'
    },
    timing: { started_at: startedAt, finished_at: finishedAt },
    claim: {
      status: allPassed ? 'success' : 'failure',
      summary: allPassed ? 'Both isolated runtime interruption cases recovered with verified browser observations' : 'At least one runtime interruption case failed to recover cleanly'
    },
    repository: {
      base_commit: head,
      head_commit: head,
      changed_files: [],
      diff_sha256: sha256Text(diffText)
    },
    tests: [
      {
        name: 'remote-obscura-process-crash-recovery',
        command: 'exact tracked Obscura MCP termination followed by fresh SSH/MCP recovery',
        exit_code: crash.passed ? 0 : 1,
        output_path: 'evidence/crash-recovery.txt',
        output_sha256: await hashFile(crashPath)
      },
      {
        name: 'ssh-transport-interruption-recovery',
        command: 'local SSH transport termination, exact remote cleanup, then fresh SSH/MCP recovery',
        exit_code: transport.passed ? 0 : 1,
        output_path: 'evidence/transport-recovery.txt',
        output_sha256: await hashFile(transportPath)
      }
    ],
    artifacts,
    evidence_claims: [
      { id: 'crash-exit-detected', operator: 'json-equals', evidence_path: 'evidence/runtime-resilience.json', pointer: '/crash/remote_process_exit_detected', expected: true },
      { id: 'crash-recovered', operator: 'json-equals', evidence_path: 'evidence/runtime-resilience.json', pointer: '/crash/recovered', expected: true },
      { id: 'crash-recovered-title', operator: 'json-equals', evidence_path: 'evidence/runtime-resilience.json', pointer: '/crash/recovered_title', expected: expectedTitle },
      { id: 'transport-exit-detected', operator: 'json-equals', evidence_path: 'evidence/runtime-resilience.json', pointer: '/transport/ssh_exit_detected', expected: true },
      { id: 'transport-cleanup-safe', operator: 'json-equals', evidence_path: 'evidence/runtime-resilience.json', pointer: '/transport/remote_cleanup_safe', expected: true },
      { id: 'transport-recovered', operator: 'json-equals', evidence_path: 'evidence/runtime-resilience.json', pointer: '/transport/recovered', expected: true },
      { id: 'transport-recovered-title', operator: 'json-equals', evidence_path: 'evidence/runtime-resilience.json', pointer: '/transport/recovered_title', expected: expectedTitle }
    ],
    fallbacks: []
  };

  const bundlePath = path.join(outputRoot, 'bundle.json');
  await writeUtf8(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`);
  const verdict = await verifyExternalRunWithStructuredClaims({ bundle, bundlePath, workspace, taskClass: 'explanation' });
  await writeUtf8(path.join(outputRoot, 'verdict.json'), `${JSON.stringify(verdict, null, 2)}\n`);

  const report = [
    '# AIDE × Obscura Runtime Resilience',
    '',
    `Remote Obscura process crash/recovery: ${crash.passed ? 'PASS' : 'FAIL'}`,
    `SSH transport interruption/recovery: ${transport.passed ? 'PASS' : 'FAIL'}`,
    `Evidence verification: ${String(verdict.disposition).toUpperCase()}`,
    `Evidence score: ${Math.round(verdict.evidence_score * 100)}%`,
    `Structured claim binding: ${verdict.structured_claims?.passed ? 'PASS' : 'BLOCK'}`,
    `Node: ${nodeName}${tailnetIp ? ` (${tailnetIp})` : ''}`,
    '',
    'The remote process kill uses a unique PID file plus /proc cmdline validation before sending SIGTERM; it does not use broad pkill/killall matching.',
    '',
    '---',
    '',
    renderExternalRunReport(verdict),
    ''
  ].join('\n');
  await writeUtf8(path.join(outputRoot, 'report.md'), report);

  const manifest = [];
  async function walk(directory) {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.name !== 'manifest.sha256.json') manifest.push({
        path: path.relative(outputRoot, absolute).replaceAll('\\', '/'),
        sha256: await hashFile(absolute)
      });
    }
  }
  await walk(outputRoot);
  manifest.sort((a, b) => a.path.localeCompare(b.path));
  await writeUtf8(path.join(outputRoot, 'manifest.sha256.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  console.log('');
  console.log(`Remote crash recovery: ${crash.passed ? 'PASS' : 'FAIL'}`);
  console.log(`SSH interruption recovery: ${transport.passed ? 'PASS' : 'FAIL'}`);
  console.log(`Evidence verification: ${verdict.disposition}`);
  console.log(`Evidence score: ${Math.round(verdict.evidence_score * 100)}%`);
  console.log(`Structured claim binding: ${verdict.structured_claims?.passed ? 'PASS' : 'BLOCK'}`);
  console.log(`Evidence: ${outputRoot}`);

  if (!allPassed || verdict.disposition !== 'verified' || !verdict.structured_claims?.passed) process.exitCode = 1;
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
