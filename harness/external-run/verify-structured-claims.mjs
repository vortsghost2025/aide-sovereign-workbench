import { promises as fs } from 'node:fs';
import path from 'node:path';
import { evaluateVeritas } from '../veritas.mjs';
import { isSafeEvidencePath } from './schema.mjs';
import { verifyExternalRun } from './verify.mjs';

const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;
const JSON_EQUALS = 'json-equals';

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

function boundaryViolation(error) {
  const message = String(error?.message || error);
  return message.startsWith('unsafe evidence path:') || message.startsWith('evidence path escapes bundle root:');
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
  if (stat.size > MAX_EVIDENCE_BYTES) {
    throw new Error(`evidence file exceeds ${MAX_EVIDENCE_BYTES} bytes: ${relative}`);
  }
  return target;
}

function decodePointerToken(token) {
  return token.replaceAll('~1', '/').replaceAll('~0', '~');
}

function jsonPointerGet(document, pointer) {
  if (pointer === '') return { found: true, value: document };
  if (typeof pointer !== 'string' || !pointer.startsWith('/')) {
    return { found: false, error: 'JSON pointer must be empty or begin with /' };
  }

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

function isJsonScalar(value) {
  return value === null || ['string', 'number', 'boolean'].includes(typeof value);
}

function sameJsonScalar(left, right) {
  return Object.is(left, right);
}

async function evaluateStructuredClaims({ bundle, bundlePath }) {
  const claims = bundle?.evidence_claims;
  if (claims === undefined) {
    return {
      enabled: false,
      passed: true,
      results: [],
      contradictions: [],
      missing: []
    };
  }

  const contradictions = [];
  const missing = [];
  const results = [];

  if (!Array.isArray(claims) || claims.length === 0) {
    contradictions.push('evidence_claims must be a non-empty array when present');
    return { enabled: true, passed: false, results, contradictions, missing };
  }

  const artifacts = Array.isArray(bundle?.artifacts) ? bundle.artifacts : [];
  const bundleRoot = path.dirname(path.resolve(bundlePath || '.'));

  for (const [index, claim] of claims.entries()) {
    const id = typeof claim?.id === 'string' && claim.id.trim() ? claim.id.trim() : `claim-${index}`;
    const result = {
      id,
      operator: claim?.operator || null,
      evidence_path: claim?.evidence_path || null,
      pointer: claim?.pointer ?? null,
      expected: claim?.expected
    };

    if (claim?.operator !== JSON_EQUALS) {
      result.passed = false;
      result.error = `unsupported structured claim operator: ${claim?.operator || 'missing'}`;
      contradictions.push(`${id}: ${result.error}`);
      results.push(result);
      continue;
    }

    if (!isSafeEvidencePath(claim?.evidence_path)) {
      result.passed = false;
      result.error = `unsafe structured claim evidence path: ${claim?.evidence_path || 'missing'}`;
      contradictions.push(`${id}: ${result.error}`);
      results.push(result);
      continue;
    }

    if (typeof claim?.pointer !== 'string' || (!claim.pointer.startsWith('/') && claim.pointer !== '')) {
      result.passed = false;
      result.error = 'structured claim pointer must be a JSON pointer';
      contradictions.push(`${id}: ${result.error}`);
      results.push(result);
      continue;
    }

    if (!isJsonScalar(claim?.expected)) {
      result.passed = false;
      result.error = 'structured claim expected value must be a JSON scalar';
      contradictions.push(`${id}: ${result.error}`);
      results.push(result);
      continue;
    }

    const declaredArtifact = artifacts.find(artifact => artifact?.path === claim.evidence_path && artifact?.sha256);
    if (!declaredArtifact) {
      result.passed = false;
      result.missing = true;
      result.error = `structured claim evidence is not declared as a hashed artifact: ${claim.evidence_path}`;
      missing.push(`${id}: ${result.error}`);
      results.push(result);
      continue;
    }

    try {
      const target = await resolveEvidenceFile(bundleRoot, claim.evidence_path);
      const document = JSON.parse(await fs.readFile(target, 'utf8'));
      const observed = jsonPointerGet(document, claim.pointer);

      if (!observed.found) {
        result.passed = false;
        result.observed = undefined;
        result.error = observed.error || `JSON pointer not present in evidence: ${claim.pointer}`;
        contradictions.push(`${id}: ${result.error}`);
      } else {
        result.observed = observed.value;
        result.passed = sameJsonScalar(observed.value, claim.expected);
        if (!result.passed) {
          contradictions.push(
            `${id}: structured claim mismatch; expected ${JSON.stringify(claim.expected)} observed ${JSON.stringify(observed.value)}`
          );
        }
      }
    } catch (error) {
      result.passed = false;
      if (boundaryViolation(error)) {
        result.rejected = true;
        contradictions.push(`${id}: ${error.message}`);
      } else if (error?.code === 'ENOENT') {
        result.missing = true;
        missing.push(`${id}: structured claim evidence unavailable: ${claim.evidence_path}`);
      } else if (error instanceof SyntaxError) {
        result.rejected = true;
        result.error = `structured claim evidence is not valid JSON: ${claim.evidence_path}`;
        contradictions.push(`${id}: ${result.error}`);
      } else {
        result.missing = true;
        result.error = error?.message || String(error);
        missing.push(`${id}: unable to evaluate structured claim: ${result.error}`);
      }
    }

    results.push(result);
  }

  const passed = contradictions.length === 0 && missing.length === 0 && results.length === claims.length && results.every(item => item.passed);
  return { enabled: true, passed, results, contradictions, missing };
}

export async function verifyExternalRunWithStructuredClaims({ bundle, bundlePath, workspace, taskClass = 'code-change' } = {}) {
  const base = await verifyExternalRun({ bundle, bundlePath, workspace, taskClass });
  const structured = await evaluateStructuredClaims({ bundle, bundlePath });

  const checks = [
    ...(base.checks || []),
    check('external-structured-claim-binding', structured.passed, {
      scored: structured.enabled,
      enabled: structured.enabled,
      claims: structured.results
    })
  ];

  const contradictions = unique([...(base.contradictions || []), ...structured.contradictions]);
  const missing = unique([...(base.missing_evidence || []), ...structured.missing]);
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
    contradictions,
    missing_evidence: missing,
    veritas,
    structured_claims: {
      enabled: structured.enabled,
      passed: structured.passed,
      results: structured.results
    }
  };
}
