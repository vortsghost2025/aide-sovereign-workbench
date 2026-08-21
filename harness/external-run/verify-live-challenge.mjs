import { promises as fs } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { evaluateVeritas } from '../veritas.mjs';
import { isSafeEvidencePath } from './schema.mjs';
import { verifyExternalRunWithStructuredClaims } from './verify-structured-claims.mjs';

const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function sha256Canonical(value) {
  return crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex');
}

async function sha256File(file) {
  const bytes = await fs.readFile(file);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function check(name, passed, details = {}) {
  return { name, passed, ...details };
}

function evidenceScore(checks) {
  const scored = checks.filter(item => item.scored !== false);
  if (!scored.length) return 0;
  return scored.filter(item => item.passed).length / scored.length;
}

function unique(values) {
  return [...new Set(values)];
}

async function resolveEvidenceFile(bundleRoot, relative) {
  if (!isSafeEvidencePath(relative)) throw new Error(`unsafe evidence path: ${relative}`);
  const root = await fs.realpath(bundleRoot);
  const target = await fs.realpath(path.resolve(bundleRoot, relative));
  const boundary = `${root}${path.sep}`;
  if (target !== root && !target.startsWith(boundary)) {
    throw new Error(`evidence path escapes bundle root: ${relative}`);
  }
  const stat = await fs.stat(target);
  if (stat.size > MAX_EVIDENCE_BYTES) throw new Error(`evidence file exceeds ${MAX_EVIDENCE_BYTES} bytes: ${relative}`);
  return target;
}

function decodePointerToken(token) {
  return token.replaceAll('~1', '/').replaceAll('~0', '~');
}

function jsonPointerGet(document, pointer) {
  if (pointer === '') return { found: true, value: document };
  if (typeof pointer !== 'string' || !pointer.startsWith('/')) return { found: false };
  let current = document;
  for (const raw of pointer.slice(1).split('/')) {
    const token = decodePointerToken(raw);
    if (current === null || typeof current !== 'object' || !Object.prototype.hasOwnProperty.call(current, token)) {
      return { found: false };
    }
    current = current[token];
  }
  return { found: true, value: current };
}

function parseTimestamp(value) {
  const ms = Date.parse(value || '');
  return Number.isFinite(ms) ? ms : null;
}

function transcriptContainsChallenge(entries, token) {
  let outbound = false;
  let inbound = false;
  for (const entry of entries) {
    const serialized = JSON.stringify(entry?.message ?? entry ?? {});
    if (entry?.direction === 'out' && entry?.message?.method === 'tools/call' && entry?.message?.params?.name === 'browser_evaluate' && serialized.includes(token)) {
      outbound = true;
    }
    if (entry?.direction === 'in' && serialized.includes(token)) inbound = true;
  }
  return { outbound, inbound };
}

export async function verifyExternalRunWithLiveChallenge({
  bundle,
  bundlePath,
  workspace,
  expectedChallenge,
  coordinatorReceipt,
  taskClass = 'explanation'
} = {}) {
  const base = await verifyExternalRunWithStructuredClaims({ bundle, bundlePath, workspace, taskClass });
  const contradictions = [...(base.contradictions || [])];
  const missing = [...(base.missing_evidence || [])];

  const binding = bundle?.challenge_binding;
  const results = {
    enabled: true,
    passed: false,
    expected_token: expectedChallenge ? sha256Canonical(expectedChallenge) : null,
    observed_token: null,
    task_id_match: false,
    claim_contract_match: false,
    execution_within_challenge_window: false,
    transcript_outbound_match: false,
    transcript_inbound_match: false,
    coordinator_receipt_present: Boolean(coordinatorReceipt),
    coordinator_receipt_match: false
  };

  if (!expectedChallenge || typeof expectedChallenge !== 'object') {
    missing.push('live challenge: coordinator-supplied expected challenge unavailable');
  }
  if (!coordinatorReceipt || typeof coordinatorReceipt !== 'object') {
    missing.push('live challenge: independent coordinator receipt unavailable');
  }
  if (!binding || binding.schema !== 'aide.live-challenge-binding/v1') {
    missing.push('live challenge: bundle challenge_binding contract unavailable');
  }

  if (expectedChallenge && binding) {
    results.task_id_match = bundle?.task?.id === expectedChallenge.task_id;
    if (!results.task_id_match) contradictions.push(`live challenge task mismatch; expected ${expectedChallenge.task_id} observed ${bundle?.task?.id || 'missing'}`);

    const claimsHash = sha256Canonical(bundle?.evidence_claims || []);
    results.claim_contract_match = claimsHash === expectedChallenge.claim_contract_sha256;
    if (!results.claim_contract_match) contradictions.push('live challenge claim contract hash mismatch');

    const issued = parseTimestamp(expectedChallenge.issued_at);
    const expires = parseTimestamp(expectedChallenge.expires_at);
    const started = parseTimestamp(bundle?.timing?.started_at);
    const finished = parseTimestamp(bundle?.timing?.finished_at);
    results.execution_within_challenge_window = [issued, expires, started, finished].every(value => value !== null) && started >= issued && finished <= expires && finished >= started;
    if (!results.execution_within_challenge_window) contradictions.push('live challenge execution timing is outside the coordinator challenge window');

    try {
      const bundleRoot = path.dirname(path.resolve(bundlePath || '.'));
      const observationPath = await resolveEvidenceFile(bundleRoot, binding.observation_path);
      const transcriptPath = await resolveEvidenceFile(bundleRoot, binding.transcript_path);
      const observation = JSON.parse(await fs.readFile(observationPath, 'utf8'));
      const observed = jsonPointerGet(observation, binding.challenge_pointer || '/observed/challenge');
      results.observed_token = observed.found ? observed.value : null;
      if (!observed.found || observed.value !== results.expected_token) {
        contradictions.push(`live challenge observation mismatch; expected ${results.expected_token} observed ${observed.found ? JSON.stringify(observed.value) : 'missing'}`);
      }

      const transcript = (await fs.readFile(transcriptPath, 'utf8'))
        .split(/\r?\n/)
        .filter(Boolean)
        .map(line => JSON.parse(line));
      const seen = transcriptContainsChallenge(transcript, results.expected_token);
      results.transcript_outbound_match = seen.outbound;
      results.transcript_inbound_match = seen.inbound;
      if (!seen.outbound) contradictions.push('live challenge token not found in captured outbound browser_evaluate invocation');
      if (!seen.inbound) contradictions.push('live challenge token not found in captured inbound MCP result');

      if (coordinatorReceipt) {
        const transcriptSha256 = await sha256File(transcriptPath);
        const observationSha256 = await sha256File(observationPath);
        const expectedReceipt = {
          task_id: expectedChallenge.task_id,
          challenge_token: results.expected_token,
          claim_contract_sha256: expectedChallenge.claim_contract_sha256,
          transcript_sha256: transcriptSha256,
          observation_sha256: observationSha256
        };
        results.coordinator_receipt_match =
          coordinatorReceipt.task_id === expectedReceipt.task_id &&
          coordinatorReceipt.challenge_token === expectedReceipt.challenge_token &&
          coordinatorReceipt.claim_contract_sha256 === expectedReceipt.claim_contract_sha256 &&
          coordinatorReceipt.transcript_sha256 === expectedReceipt.transcript_sha256 &&
          coordinatorReceipt.observation_sha256 === expectedReceipt.observation_sha256;
        if (!results.coordinator_receipt_match) contradictions.push('live challenge evidence does not match independent coordinator receipt');
      }
    } catch (error) {
      if (error?.code === 'ENOENT') missing.push(`live challenge evidence unavailable: ${error.path || error.message}`);
      else contradictions.push(`live challenge evidence invalid: ${error.message || String(error)}`);
    }
  }

  results.passed = contradictions.length === (base.contradictions || []).length && missing.length === (base.missing_evidence || []).length &&
    results.task_id_match && results.claim_contract_match && results.execution_within_challenge_window &&
    results.transcript_outbound_match && results.transcript_inbound_match && results.coordinator_receipt_match &&
    results.observed_token === results.expected_token;

  const checks = [
    ...(base.checks || []),
    check('external-live-challenge-binding', results.passed, { enabled: true, challenge: results })
  ];
  const score = evidenceScore(checks);
  const checkMap = Object.fromEntries(checks.map(item => [item.name, item.passed]));
  const veritas = evaluateVeritas({ taskClass, evidenceScore: score, checks: checkMap });

  const disposition = contradictions.length
    ? 'rejected'
    : missing.length || !veritas.passed
      ? 'abstain-needs-evidence'
      : 'verified';

  return {
    ...base,
    disposition,
    evidence_score: score,
    checks,
    contradictions: unique(contradictions),
    missing_evidence: unique(missing),
    veritas,
    live_challenge: results
  };
}
