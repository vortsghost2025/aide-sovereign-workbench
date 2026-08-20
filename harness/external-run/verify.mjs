import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { evaluateVeritas } from '../veritas.mjs';
import { validateExternalRunBundle } from './schema.mjs';

const execFileAsync = promisify(execFile);
const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;

function canonicalText(value) {
  return String(value).replaceAll('\r\n', '\n');
}

export function sha256Buffer(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function sha256Text(value) {
  return sha256Buffer(Buffer.from(canonicalText(value), 'utf8'));
}

async function sha256File(file) {
  const stat = await fs.stat(file);
  if (stat.size > MAX_EVIDENCE_BYTES) throw new Error(`evidence file exceeds ${MAX_EVIDENCE_BYTES} bytes: ${file}`);
  return sha256Buffer(await fs.readFile(file));
}

async function git(workspace, args) {
  const { stdout } = await execFileAsync('git', args, {
    cwd: workspace,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 120_000
  });
  return canonicalText(stdout);
}

async function commitExists(workspace, commit) {
  try {
    await git(workspace, ['cat-file', '-e', `${commit}^{commit}`]);
    return true;
  } catch {
    return false;
  }
}

export async function canonicalGitDiff(workspace, baseCommit, headCommit) {
  return git(workspace, ['diff', '--binary', '--full-index', '--no-ext-diff', `${baseCommit}..${headCommit}`, '--']);
}

async function gitChangedFiles(workspace, baseCommit, headCommit) {
  const output = await git(workspace, ['diff', '--name-only', `${baseCommit}..${headCommit}`, '--']);
  return output.split('\n').filter(Boolean).map(file => file.replaceAll('\\', '/')).sort();
}

function sameList(left, right) {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}

function check(name, passed, details = {}) {
  return { name, passed, ...details };
}

function evidenceScore(checks) {
  const scored = checks.filter(item => item.scored !== false);
  if (!scored.length) return 0;
  return scored.filter(item => item.passed).length / scored.length;
}

export async function verifyExternalRun({ bundle, bundlePath, workspace, taskClass = 'code-change' } = {}) {
  const checks = [];
  const contradictions = [];
  const missing = [];
  const schema = validateExternalRunBundle(bundle);
  for (const issue of schema.issues) {
    (issue.kind === 'reject' ? contradictions : missing).push(`${issue.field}: ${issue.message}`);
  }
  checks.push(check('external-schema', schema.issues.length === 0, { issues: schema.issues }));

  const bundleRoot = path.dirname(path.resolve(bundlePath || '.'));
  const resolvedWorkspace = path.resolve(workspace || '.');

  let repositoryReady = false;
  const base = bundle?.repository?.base_commit;
  const head = bundle?.repository?.head_commit;
  if (base && head) {
    const baseExists = await commitExists(resolvedWorkspace, base);
    const headExists = await commitExists(resolvedWorkspace, head);
    repositoryReady = baseExists && headExists;
    checks.push(check('external-commit-binding', repositoryReady, { base_exists: baseExists, head_exists: headExists }));
    if (!repositoryReady) missing.push('repository commits are not both available in the supplied workspace');
  } else {
    checks.push(check('external-commit-binding', false));
  }

  const artifacts = Array.isArray(bundle?.artifacts) ? bundle.artifacts : [];
  const artifactResults = [];
  for (const artifact of artifacts) {
    if (!artifact?.path || !artifact?.sha256) continue;
    const target = path.resolve(bundleRoot, artifact.path);
    try {
      const actual = await sha256File(target);
      const passed = actual.toLowerCase() === artifact.sha256.toLowerCase();
      artifactResults.push({ name: artifact.name, kind: artifact.kind, path: artifact.path, passed, expected: artifact.sha256, actual });
      if (!passed) contradictions.push(`artifact hash mismatch: ${artifact.path}`);
    } catch (error) {
      artifactResults.push({ name: artifact.name, kind: artifact.kind, path: artifact.path, passed: false, missing: true, error: error.message });
      missing.push(`artifact unavailable: ${artifact.path}`);
    }
  }
  const declaredArtifactsComplete = artifacts.length > 0 && artifactResults.length === artifacts.length;
  const artifactsPassed = declaredArtifactsComplete && artifactResults.every(item => item.passed);
  checks.push(check('external-artifact-integrity', artifactsPassed, { artifacts: artifactResults }));

  const diffArtifact = artifacts.find(item => item?.kind === 'git-diff');
  let diffBindingPassed = false;
  if (!diffArtifact) {
    missing.push('git-diff artifact is required');
  } else if (repositoryReady && bundle?.repository?.diff_sha256) {
    try {
      const actualGitDiff = await canonicalGitDiff(resolvedWorkspace, base, head);
      const actualGitDiffHash = sha256Text(actualGitDiff);
      const artifactText = canonicalText(await fs.readFile(path.resolve(bundleRoot, diffArtifact.path), 'utf8'));
      const artifactSemanticHash = sha256Text(artifactText);
      const expected = bundle.repository.diff_sha256.toLowerCase();
      diffBindingPassed = actualGitDiffHash === expected && artifactSemanticHash === expected;
      if (!diffBindingPassed) contradictions.push('git diff evidence does not bind to the declared repository transition');
      checks.push(check('external-diff-binding', diffBindingPassed, {
        expected,
        repository_diff_sha256: actualGitDiffHash,
        artifact_diff_sha256: artifactSemanticHash
      }));
    } catch (error) {
      missing.push(`unable to verify git diff evidence: ${error.message}`);
      checks.push(check('external-diff-binding', false, { error: error.message }));
    }
  } else {
    checks.push(check('external-diff-binding', false));
  }

  let changedFilesPassed = false;
  if (repositoryReady && Array.isArray(bundle?.repository?.changed_files)) {
    try {
      const actual = await gitChangedFiles(resolvedWorkspace, base, head);
      const declared = bundle.repository.changed_files.map(file => file.replaceAll('\\', '/')).sort();
      changedFilesPassed = sameList(actual, declared);
      if (!changedFilesPassed) contradictions.push('declared changed_files do not match the repository transition');
      checks.push(check('external-changed-files', changedFilesPassed, { declared, actual }));
    } catch (error) {
      missing.push(`unable to enumerate changed files: ${error.message}`);
      checks.push(check('external-changed-files', false, { error: error.message }));
    }
  } else {
    checks.push(check('external-changed-files', false));
  }

  const tests = Array.isArray(bundle?.tests) ? bundle.tests : [];
  const testResults = [];
  if (!tests.length) missing.push('at least one test evidence record is required for a code-change run');
  for (const test of tests) {
    if (!test?.output_path || !test?.output_sha256 || !Number.isInteger(test?.exit_code)) continue;
    const target = path.resolve(bundleRoot, test.output_path);
    try {
      const actual = await sha256File(target);
      const integrity = actual.toLowerCase() === test.output_sha256.toLowerCase();
      if (!integrity) contradictions.push(`test output hash mismatch: ${test.output_path}`);
      testResults.push({
        name: test.name,
        command: test.command,
        exit_code: test.exit_code,
        output_path: test.output_path,
        integrity,
        passed: integrity && test.exit_code === 0,
        expected: test.output_sha256,
        actual
      });
    } catch (error) {
      missing.push(`test evidence unavailable: ${test.output_path}`);
      testResults.push({ name: test.name, command: test.command, exit_code: test.exit_code, output_path: test.output_path, integrity: false, missing: true, passed: false, error: error.message });
    }
  }
  const testsIntegrityPassed = tests.length > 0 && testResults.length === tests.length && testResults.every(item => item.integrity);
  checks.push(check('external-test-integrity', testsIntegrityPassed, { tests: testResults }));

  let claimConsistencyPassed = false;
  if (bundle?.claim?.status) {
    const anyFailingTest = tests.some(test => Number.isInteger(test?.exit_code) && test.exit_code !== 0);
    claimConsistencyPassed = !(bundle.claim.status === 'success' && anyFailingTest);
    if (!claimConsistencyPassed) contradictions.push('claim.status=success contradicts recorded non-zero test exit code');
  }
  checks.push(check('external-claim-consistency', claimConsistencyPassed));

  const fallbacks = Array.isArray(bundle?.fallbacks) ? bundle.fallbacks : [];
  const fallbackDisclosurePassed = fallbacks.every(item => item?.from && item?.to && item?.reason && item?.at);
  checks.push(check('external-fallback-disclosure', fallbackDisclosurePassed, { count: fallbacks.length }));

  const score = evidenceScore(checks);
  const checkMap = Object.fromEntries(checks.map(item => [item.name, item.passed]));
  const veritas = evaluateVeritas({ taskClass, evidenceScore: score, checks: checkMap });
  const disposition = contradictions.length
    ? 'rejected'
    : missing.length || !veritas.passed
      ? 'abstain-needs-evidence'
      : 'verified';

  return {
    schema: 'aide.external-verdict/v1',
    disposition,
    task_id: bundle?.task?.id || null,
    executor: bundle?.executor || null,
    repository: bundle?.repository || null,
    evidence_score: score,
    checks,
    contradictions: [...new Set(contradictions)],
    missing_evidence: [...new Set(missing)],
    veritas
  };
}
