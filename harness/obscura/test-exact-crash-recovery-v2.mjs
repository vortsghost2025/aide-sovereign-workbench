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

function safeHost(value) {
  if (!/^[A-Za-z0-9._-]+$/.test(value)) throw new Error(`unsafe SSH host token: ${value}`);
  return value;
}

function safeRemotePath(value) {
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

function parseKeyValue(text) {
  const result = {};
  for (const line of String(text || '').split(/\r?\n/)) {
    const index = line.indexOf('=');
    if (index <= 0) continue;
    result[line.slice(0, index)] = line.slice(index + 1);
  }
  return result;
}

async function installTrackedWrapper(host, remoteBinary) {
  const token = randomUUID().replaceAll('-', '');
  const wrapper = safeRemotePath(`/tmp/aide-obscura-crash-v2-${token}.sh`);
  const pidfile = safeRemotePath(`/tmp/aide-obscura-crash-v2-${token}.pid`);
  const script = [
    '#!/bin/sh',
    'set -eu',
    `printf '%s\\n' "$$" > '${pidfile}'`,
    `exec '${remoteBinary}' "$@"`,
    ''
  ].join('\n');
  const payload = Buffer.from(script, 'utf8').toString('base64');
  const result = await ssh(host, `umask 077; printf '%s' '${payload}' | base64 -d > '${wrapper}'; chmod 700 '${wrapper}'`);
  if (!result.ok) throw new Error(`unable to install tracked wrapper: ${result.stderr || result.error}`);
  return { wrapper, pidfile };
}

async function inspectAndTerminateExact(host, pidfile, remoteBinary) {
  const command = [
    `pid=$(cat '${pidfile}' 2>/dev/null || true)`,
    'printf "pid=%s\\n" "$pid"',
    'if [ -z "$pid" ]; then echo state=pid-missing; exit 44; fi',
    'if [ ! -r "/proc/$pid/cmdline" ]; then echo state=process-gone; exit 45; fi',
    `expected=$(readlink -f '${remoteBinary}' 2>/dev/null || true)`,
    'exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)',
    'arg0=$(tr "\\000" "\\n" < "/proc/$pid/cmdline" | sed -n "1p")',
    'arg1=$(tr "\\000" "\\n" < "/proc/$pid/cmdline" | sed -n "2p")',
    'printf "expected_exe=%s\\nexe=%s\\narg0=%s\\narg1=%s\\n" "$expected" "$exe" "$arg0" "$arg1"',
    'if [ -z "$expected" ] || [ "$exe" != "$expected" ] || [ "$arg1" != "mcp" ]; then echo state=identity-refused; exit 42; fi',
    'kill -TERM "$pid"',
    'echo state=terminated',
    'echo signal=TERM'
  ].join('; ');
  const result = await ssh(host, command);
  return { ...result, identity: parseKeyValue(`${result.stdout}\n${result.stderr}`) };
}

async function safeCleanupTracked(host, pidfile, wrapper, remoteBinary) {
  const command = [
    `pid=$(cat '${pidfile}' 2>/dev/null || true)`,
    'if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ]; then',
    `  expected=$(readlink -f '${remoteBinary}' 2>/dev/null || true)`,
    '  exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)',
    '  arg1=$(tr "\\000" "\\n" < "/proc/$pid/cmdline" | sed -n "2p")',
    '  if [ -n "$expected" ] && [ "$exe" = "$expected" ] && [ "$arg1" = "mcp" ]; then kill -TERM "$pid" || true; fi',
    'fi',
    `rm -f '${wrapper}' '${pidfile}'`,
    'echo cleanup=complete'
  ].join('; ');
  return ssh(host, command);
}

async function waitForExit(proc, timeoutMs = 8_000) {
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
  if (!raw) throw new Error('empty browser observation');
  let value = JSON.parse(raw);
  if (typeof value === 'string') value = JSON.parse(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('browser observation is not an object');
  return value;
}

async function browseOnce({ host, remoteBinary, url }) {
  const client = new SshMcpClient({ host, remoteBinary, timeoutMs: 10_000 });
  let observation;
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

async function runCrash({ host, remoteBinary, url, expectedTitle }) {
  const tracked = await installTrackedWrapper(host, remoteBinary);
  const client = new SshMcpClient({ host, remoteBinary: tracked.wrapper, timeoutMs: 8_000 });
  let before = null;
  let termination = null;
  let exit = { exited: false, reason: 'not-run' };
  let recovery = null;
  let error = null;

  try {
    await client.initialize();
    await client.callTool('browser_navigate', { url, waitUntil: 'load' });
    const evaluation = await client.callTool('browser_evaluate', {
      expression: 'JSON.stringify({title:document.title,url:location.href})'
    });
    before = parseObservation(toolText(evaluation));

    termination = await inspectAndTerminateExact(host, tracked.pidfile, remoteBinary);
    if (!termination.ok || termination.identity?.state !== 'terminated') {
      throw new Error(`exact process identity/termination failed: ${termination.stderr || termination.stdout || termination.error}`);
    }

    exit = await waitForExit(client.proc, 8_000);
    if (!exit.exited) throw new Error('SSH/MCP process did not exit after exact remote SIGTERM');
  } catch (caught) {
    error = caught?.message || String(caught);
  } finally {
    await client.close().catch(() => undefined);
  }

  try {
    recovery = await browseOnce({ host, remoteBinary, url });
  } catch (caught) {
    error = [error, `recovery failed: ${caught?.message || caught}`].filter(Boolean).join(' | ');
  }

  const cleanup = await safeCleanupTracked(host, tracked.pidfile, tracked.wrapper, remoteBinary);
  const recoveredTitle = recovery?.observation?.title || null;
  const identityExact = Boolean(
    termination?.ok &&
    termination.identity?.state === 'terminated' &&
    termination.identity?.expected_exe &&
    termination.identity?.exe === termination.identity?.expected_exe &&
    termination.identity?.arg1 === 'mcp'
  );
  const passed = Boolean(identityExact && exit.exited && recovery && recoveredTitle === expectedTitle && cleanup.ok);

  return {
    passed,
    identity_exact: identityExact,
    identity: termination?.identity || {},
    termination_ok: Boolean(termination?.ok),
    termination_stdout: termination?.stdout || '',
    termination_stderr: termination?.stderr || '',
    process_exit_detected: Boolean(exit.exited),
    process_exit: exit,
    pre_crash_title: before?.title || null,
    recovered: Boolean(recovery),
    recovered_title: recoveredTitle,
    recovery_observation: recovery?.observation || null,
    cleanup_safe: Boolean(cleanup?.ok),
    error,
    before_transcript: client.transcript,
    before_stderr: client.stderr,
    recovery_transcript: recovery?.transcript || [],
    recovery_stderr: recovery?.stderr || ''
  };
}

function transcript(entries) {
  return entries.map(entry => JSON.stringify(entry)).join('\n') + (entries.length ? '\n' : '');
}

async function main() {
  const host = safeHost(arg('host', 'headless'));
  const nodeName = arg('node', host);
  const tailnetIp = arg('tailnet-ip', null);
  const remoteBinary = safeRemotePath(arg('remote', '/home/we4free/opt/aide-obscura-v0.2.0/obscura'));
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
  if (dirty.trim()) throw new Error('workspace must be clean before exact crash recovery run');
  const head = (await git(workspace, ['rev-parse', 'HEAD'])).trim();
  const startedAt = new Date().toISOString();
  const evidenceDir = path.join(outputRoot, 'evidence');
  await fs.mkdir(evidenceDir, { recursive: true });

  console.log('Exact remote Obscura crash injection...');
  const crash = await runCrash({ host, remoteBinary, url, expectedTitle });
  console.log(`identity exact: ${crash.identity_exact ? 'PASS' : 'FAIL'}`);
  console.log(`remote exit detected: ${crash.process_exit_detected ? 'PASS' : 'FAIL'}`);
  console.log(`recovery title: ${crash.recovered_title || 'missing'}`);

  const finishedAt = new Date().toISOString();
  const observation = {
    schema: 'aide.obscura-exact-crash-recovery/v2',
    node: nodeName,
    tailnet_ip: tailnetIp,
    transport_host: host,
    target_url: url,
    identity_exact: crash.identity_exact,
    exact_executable: crash.identity?.exe || null,
    expected_executable: crash.identity?.expected_exe || null,
    argv0: crash.identity?.arg0 || null,
    argv1: crash.identity?.arg1 || null,
    termination_state: crash.identity?.state || null,
    process_exit_detected: crash.process_exit_detected,
    recovered: crash.recovered,
    recovered_title: crash.recovered_title,
    cleanup_safe: crash.cleanup_safe
  };

  const observationPath = path.join(evidenceDir, 'exact-crash-recovery.json');
  const resultPath = path.join(evidenceDir, 'exact-crash-recovery.txt');
  await writeUtf8(observationPath, `${JSON.stringify(observation, null, 2)}\n`);
  await writeUtf8(resultPath, [
    `exact-process-identity: ${crash.identity_exact ? 'PASS' : 'FAIL'}`,
    `termination-state: ${crash.identity?.state || 'missing'}`,
    `expected-executable: ${crash.identity?.expected_exe || 'missing'}`,
    `observed-executable: ${crash.identity?.exe || 'missing'}`,
    `argv0: ${crash.identity?.arg0 || 'missing'}`,
    `argv1: ${crash.identity?.arg1 || 'missing'}`,
    `remote-process-exit-detected: ${crash.process_exit_detected ? 'PASS' : 'FAIL'}`,
    `recovery-title: ${crash.recovered_title || 'missing'}`,
    `expected-title: ${expectedTitle}`,
    `cleanup-safe: ${crash.cleanup_safe ? 'PASS' : 'FAIL'}`,
    `error: ${crash.error || 'none'}`,
    ''
  ].join('\n'));
  await writeUtf8(path.join(evidenceDir, 'before.ndjson'), transcript(crash.before_transcript));
  await writeUtf8(path.join(evidenceDir, 'recovery.ndjson'), transcript(crash.recovery_transcript));
  if (crash.before_stderr) await writeUtf8(path.join(evidenceDir, 'before-stderr.txt'), crash.before_stderr);
  if (crash.recovery_stderr) await writeUtf8(path.join(evidenceDir, 'recovery-stderr.txt'), crash.recovery_stderr);

  const diffText = await git(workspace, ['diff', '--binary', '--full-index', '--no-ext-diff', `${head}..${head}`, '--']);
  const diffPath = path.join(evidenceDir, 'change.patch');
  await writeUtf8(diffPath, diffText);

  const files = [
    ['exact-crash-observation', 'structured-observation', 'evidence/exact-crash-recovery.json'],
    ['exact-crash-result', 'test-output', 'evidence/exact-crash-recovery.txt'],
    ['before-transcript', 'mcp-transcript', 'evidence/before.ndjson'],
    ['recovery-transcript', 'mcp-transcript', 'evidence/recovery.ndjson'],
    ['zero-diff-binding', 'git-diff', 'evidence/change.patch']
  ];
  for (const optional of ['before-stderr.txt', 'recovery-stderr.txt']) {
    try {
      await fs.access(path.join(evidenceDir, optional));
      files.push([optional, 'transport-stderr', `evidence/${optional}`]);
    } catch {}
  }

  const artifacts = [];
  for (const [name, kind, relative] of files) {
    artifacts.push({ name, kind, path: relative, sha256: await hashFile(path.join(outputRoot, relative)) });
  }

  const bundle = {
    schema: 'aide.external-run/v1',
    task: {
      id: `obscura-exact-crash-recovery-v2-${Date.now()}`,
      summary: 'Prove exact remote Obscura MCP process termination and fresh-session browser recovery'
    },
    executor: {
      agent: 'aide-obscura-exact-crash-recovery-v2',
      provider: 'ssh-stdio',
      model: 'none',
      node: nodeName,
      tailnet_ip: tailnetIp,
      transport_host: host,
      engine: 'obscura'
    },
    timing: { started_at: startedAt, finished_at: finishedAt },
    claim: {
      status: crash.passed ? 'success' : 'failure',
      summary: crash.passed
        ? 'Exact tracked Obscura MCP process was safely terminated, exit was observed, and a fresh browser session recovered'
        : 'Exact crash/recovery proof did not satisfy every deterministic postcondition'
    },
    repository: {
      base_commit: head,
      head_commit: head,
      changed_files: [],
      diff_sha256: sha256Text(diffText)
    },
    tests: [{
      name: 'exact-obscura-crash-recovery-v2',
      command: 'tracked exact /proc executable+argv identity -> SIGTERM -> observe exit -> fresh MCP browser recovery',
      exit_code: crash.passed ? 0 : 1,
      output_path: 'evidence/exact-crash-recovery.txt',
      output_sha256: await hashFile(resultPath)
    }],
    artifacts,
    evidence_claims: [
      { id: 'exact-process-identity', operator: 'json-equals', evidence_path: 'evidence/exact-crash-recovery.json', pointer: '/identity_exact', expected: true },
      { id: 'termination-state', operator: 'json-equals', evidence_path: 'evidence/exact-crash-recovery.json', pointer: '/termination_state', expected: 'terminated' },
      { id: 'remote-exit-detected', operator: 'json-equals', evidence_path: 'evidence/exact-crash-recovery.json', pointer: '/process_exit_detected', expected: true },
      { id: 'browser-recovered', operator: 'json-equals', evidence_path: 'evidence/exact-crash-recovery.json', pointer: '/recovered', expected: true },
      { id: 'recovered-title', operator: 'json-equals', evidence_path: 'evidence/exact-crash-recovery.json', pointer: '/recovered_title', expected: expectedTitle },
      { id: 'cleanup-safe', operator: 'json-equals', evidence_path: 'evidence/exact-crash-recovery.json', pointer: '/cleanup_safe', expected: true }
    ],
    fallbacks: []
  };

  const bundlePath = path.join(outputRoot, 'bundle.json');
  await writeUtf8(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`);
  const verdict = await verifyExternalRunWithStructuredClaims({ bundle, bundlePath, workspace, taskClass: 'explanation' });
  await writeUtf8(path.join(outputRoot, 'verdict.json'), `${JSON.stringify(verdict, null, 2)}\n`);
  const report = [
    '# AIDE × Obscura Exact Crash Recovery V2',
    '',
    `Exact process identity: ${crash.identity_exact ? 'PASS' : 'FAIL'}`,
    `Remote process exit detected: ${crash.process_exit_detected ? 'PASS' : 'FAIL'}`,
    `Browser recovery: ${crash.recovered_title === expectedTitle ? 'PASS' : 'FAIL'}`,
    `Evidence verification: ${String(verdict.disposition).toUpperCase()}`,
    `Evidence score: ${Math.round(verdict.evidence_score * 100)}%`,
    `Node: ${nodeName}${tailnetIp ? ` (${tailnetIp})` : ''}`,
    '',
    'The kill is issued only after the tracked PID resolves to the exact expected executable and argv[1] is exactly `mcp`.',
    '',
    '---',
    '',
    renderExternalRunReport(verdict),
    ''
  ].join('\n');
  await writeUtf8(path.join(outputRoot, 'report.md'), report);

  const manifest = [];
  async function walk(dir) {
    for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else manifest.push({ path: path.relative(outputRoot, absolute).replaceAll('\\', '/'), sha256: await hashFile(absolute) });
    }
  }
  await walk(outputRoot);
  manifest.sort((a, b) => a.path.localeCompare(b.path));
  await writeUtf8(path.join(outputRoot, 'manifest.sha256.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  console.log(`Exact process identity: ${crash.identity_exact ? 'PASS' : 'FAIL'}`);
  console.log(`Remote process exit detected: ${crash.process_exit_detected ? 'PASS' : 'FAIL'}`);
  console.log(`Recovered title: ${crash.recovered_title || 'missing'}`);
  console.log(`Evidence verification: ${verdict.disposition}`);
  console.log(`Evidence score: ${Math.round(verdict.evidence_score * 100)}%`);
  console.log(`Evidence: ${outputRoot}`);

  process.exitCode = crash.passed && verdict.disposition === 'verified' ? 0 : 1;
}

main().catch(error => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 2;
});
