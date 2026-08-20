import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { renderExternalRunReport } from './external-run/report.mjs';
import { canonicalGitDiff, sha256Text, verifyExternalRun } from './external-run/verify.mjs';
import { parseExternalVeritasArgs, renderExternalHelp } from './run-external-veritas.mjs';

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function rawSha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function writeEvidence(root, relative, content) {
  const target = path.join(root, relative);
  await fs.mkdir(path.dirname(target), { recursive: true });
  const data = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
  await fs.writeFile(target, data);
  return rawSha256(data);
}

const root = await fs.mkdtemp(path.join(os.tmpdir(), 'aide-external-run-'));
const workspace = path.join(root, 'workspace');
const evidenceRoot = path.join(root, 'bundle');
await fs.mkdir(workspace, { recursive: true });
await fs.mkdir(evidenceRoot, { recursive: true });

git(workspace, 'init');
git(workspace, 'config', 'user.email', 'aide-test@example.invalid');
git(workspace, 'config', 'user.name', 'AIDE Test');
await fs.writeFile(path.join(workspace, 'fixture.txt'), 'base\n', 'utf8');
git(workspace, 'add', 'fixture.txt');
git(workspace, 'commit', '-m', 'base');
const base = git(workspace, 'rev-parse', 'HEAD');
await fs.writeFile(path.join(workspace, 'fixture.txt'), 'changed\n', 'utf8');
git(workspace, 'add', 'fixture.txt');
git(workspace, 'commit', '-m', 'change');
const head = git(workspace, 'rev-parse', 'HEAD');

const diff = await canonicalGitDiff(workspace, base, head);
const diffRawSha = await writeEvidence(evidenceRoot, 'evidence/change.patch', diff);
const testOutput = 'fixture tests passed\n';
const testSha = await writeEvidence(evidenceRoot, 'evidence/test.txt', testOutput);
const eventSha = await writeEvidence(evidenceRoot, 'evidence/events.ndjson', '{"type":"start"}\n{"type":"finish"}\n');
const bundlePath = path.join(evidenceRoot, 'run.json');

function freshBundle() {
  return {
    schema: 'aide.external-run/v1',
    task: { id: 'external-run-fixture', summary: 'Verify an externally executed Git change' },
    executor: { agent: 'fixture-worker', provider: 'test-provider', model: 'test-model' },
    timing: { started_at: '2026-08-20T20:00:00Z', finished_at: '2026-08-20T20:01:00Z' },
    claim: { status: 'success', summary: 'Changed fixture and tests passed' },
    repository: {
      base_commit: base,
      head_commit: head,
      changed_files: ['fixture.txt'],
      diff_sha256: sha256Text(diff)
    },
    tests: [{
      name: 'fixture-test',
      command: 'node fixture-test.mjs',
      exit_code: 0,
      output_path: 'evidence/test.txt',
      output_sha256: testSha
    }],
    artifacts: [
      { name: 'git-diff', kind: 'git-diff', path: 'evidence/change.patch', sha256: diffRawSha },
      { name: 'events', kind: 'event-log', path: 'evidence/events.ndjson', sha256: eventSha }
    ],
    fallbacks: []
  };
}

const valid = await verifyExternalRun({ bundle: freshBundle(), bundlePath, workspace });
assert.equal(valid.disposition, 'verified');
assert.equal(valid.veritas.status, 'verified');
assert.equal(valid.contradictions.length, 0);
assert.equal(valid.missing_evidence.length, 0);
assert.equal(valid.checks.every(item => item.passed), true);

const lyingBundle = freshBundle();
lyingBundle.tests[0].exit_code = 1;
const lying = await verifyExternalRun({ bundle: lyingBundle, bundlePath, workspace });
assert.equal(lying.disposition, 'rejected');
assert.match(lying.contradictions.join('\n'), /claim\.status=success contradicts/);

const incompleteBundle = freshBundle();
incompleteBundle.tests = [];
const incomplete = await verifyExternalRun({ bundle: incompleteBundle, bundlePath, workspace });
assert.equal(incomplete.disposition, 'abstain-needs-evidence');
assert.match(incomplete.missing_evidence.join('\n'), /at least one test evidence record/);

const originalDiff = await fs.readFile(path.join(evidenceRoot, 'evidence/change.patch'));
await fs.appendFile(path.join(evidenceRoot, 'evidence/change.patch'), '\nTAMPERED\n', 'utf8');
const tampered = await verifyExternalRun({ bundle: freshBundle(), bundlePath, workspace });
assert.equal(tampered.disposition, 'rejected');
assert.match(tampered.contradictions.join('\n'), /artifact hash mismatch/);
await fs.writeFile(path.join(evidenceRoot, 'evidence/change.patch'), originalDiff);

const scopeBundle = freshBundle();
scopeBundle.repository.changed_files = ['other.txt'];
const scope = await verifyExternalRun({ bundle: scopeBundle, bundlePath, workspace });
assert.equal(scope.disposition, 'rejected');
assert.match(scope.contradictions.join('\n'), /changed_files/);

const unsafeBundle = freshBundle();
unsafeBundle.artifacts[0].path = '../outside.patch';
const unsafe = await verifyExternalRun({ bundle: unsafeBundle, bundlePath, workspace });
assert.equal(unsafe.disposition, 'rejected');
assert.match(unsafe.contradictions.join('\n'), /safe relative path/);

const report = renderExternalRunReport(valid);
assert.match(report, /Disposition: VERIFIED/);
assert.match(report, /external-diff-binding: PASS/);
assert.match(report, /Evidence score: 100%/);

const parsed = parseExternalVeritasArgs(['--bundle', bundlePath, '--workspace', workspace, '--report']);
assert.equal(parsed.format, 'report');
assert.equal(parsed.taskClass, 'code-change');
assert.equal(parsed.bundle, path.resolve(bundlePath));
assert.match(renderExternalHelp(), /veritas:external/);
assert.throws(() => parseExternalVeritasArgs(['--bundle']), /requires a value/);
assert.throws(() => parseExternalVeritasArgs(['--bundle', bundlePath, '--task-class', 'unknown']), /unknown task class/);

await fs.rm(root, { recursive: true, force: true });
console.log('external run veritas test passed');
