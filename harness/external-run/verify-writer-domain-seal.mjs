import crypto from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { sha256Canonical, verifyExternalRunWithLiveChallenge } from './verify-live-challenge.mjs';

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256Buffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function safeResolve(root, relativePath) {
  if (typeof relativePath !== 'string' || !relativePath || path.isAbsolute(relativePath)) {
    throw new Error(`unsafe evidence path: ${relativePath}`);
  }
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(root, relativePath);
  const relative = path.relative(resolvedRoot, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) throw new Error(`evidence path escapes bundle root: ${relativePath}`);
  return resolved;
}

async function readJson(file) {
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

function eventArray(value) {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object') return [value];
  return [];
}

function localWorldResult({ live, expectedChallenge, events, observation }) {
  const result = {
    disposition: 'abstain-needs-evidence',
    passed: false,
    live_challenge_disposition: live.disposition,
    coordinator_event_present: false,
    nonce_match: false,
    response_token_match: false,
    within_challenge_window: false,
    remote_address: null,
    reason: null
  };

  if (live.disposition !== 'verified') {
    result.disposition = live.disposition;
    result.reason = 'base live challenge did not verify';
    return result;
  }

  const worldEvent = eventArray(events).filter(event => event?.nonce === expectedChallenge.nonce).at(-1) || null;
  result.coordinator_event_present = Boolean(worldEvent);
  result.nonce_match = Boolean(worldEvent && worldEvent.nonce === expectedChallenge.nonce);
  result.remote_address = worldEvent?.remote_address || null;

  if (!worldEvent) {
    result.reason = 'bundle-local coordinator event missing for challenge nonce';
    return result;
  }

  const observedToken = observation?.observed?.world_token ?? null;
  result.response_token_match = Boolean(observedToken && observedToken === worldEvent.response_token);

  const issued = Date.parse(expectedChallenge.issued_at);
  const expires = Date.parse(expectedChallenge.expires_at);
  const eventTime = Date.parse(worldEvent.at);
  result.within_challenge_window = Number.isFinite(eventTime) && eventTime >= issued && eventTime <= expires;

  if (!result.response_token_match || !result.within_challenge_window) {
    result.disposition = 'rejected';
    result.reason = 'bundle-local world event contradicts browser observation or challenge timing';
    return result;
  }

  result.disposition = 'verified';
  result.passed = true;
  result.reason = 'bundle-local coordinator event matches browser observation';
  return result;
}

export async function verifyWorldContactBundleLocal({
  bundle,
  bundlePath,
  workspace,
  expectedChallenge,
  coordinatorReceipt,
  coordinatorEventPath = 'coordinator/echo-events.json',
  observationPath = null,
  taskClass = 'explanation'
}) {
  const live = await verifyExternalRunWithLiveChallenge({
    bundle,
    bundlePath,
    workspace,
    expectedChallenge,
    coordinatorReceipt,
    taskClass
  });

  const root = path.dirname(path.resolve(bundlePath));
  const observationRelative = observationPath || bundle?.challenge_binding?.observation_path;
  if (!observationRelative) {
    return {
      disposition: 'abstain-needs-evidence',
      passed: false,
      live_challenge_disposition: live.disposition,
      reason: 'challenge observation path missing'
    };
  }

  let events;
  let observation;
  try {
    events = await readJson(safeResolve(root, coordinatorEventPath));
    observation = await readJson(safeResolve(root, observationRelative));
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return {
        disposition: 'abstain-needs-evidence',
        passed: false,
        live_challenge_disposition: live.disposition,
        reason: `required bundle-local world evidence missing: ${error.message}`
      };
    }
    throw error;
  }

  return localWorldResult({ live, expectedChallenge, events, observation });
}

export function createSignedWriterDomainSeal({
  privateKey,
  expectedChallenge,
  eventPath = 'coordinator/echo-events.json',
  eventBytes,
  issuedAt = new Date().toISOString()
}) {
  if (!privateKey) throw new Error('privateKey is required');
  if (!Buffer.isBuffer(eventBytes)) eventBytes = Buffer.from(eventBytes);
  const payload = {
    schema: 'aide.writer-domain-seal-payload/v1',
    writer_domain: 'coordinator',
    task_id: expectedChallenge.task_id,
    challenge_sha256: sha256Canonical(expectedChallenge),
    event_path: eventPath.replaceAll('\\', '/'),
    event_sha256: sha256Buffer(eventBytes),
    issued_at: issuedAt
  };
  const signature = crypto.sign(null, Buffer.from(canonical(payload), 'utf8'), privateKey).toString('base64');
  return {
    schema: 'aide.writer-domain-seal/v1',
    signature_alg: 'ed25519',
    payload,
    signature_base64: signature
  };
}

export async function verifyWorldContactWithWriterDomainSeal({
  bundle,
  bundlePath,
  workspace,
  expectedChallenge,
  coordinatorReceipt,
  trustedSeal = null,
  trustedPublicKeyPem = null,
  coordinatorEventPath = 'coordinator/echo-events.json',
  observationPath = null,
  taskClass = 'explanation'
}) {
  const local = await verifyWorldContactBundleLocal({
    bundle,
    bundlePath,
    workspace,
    expectedChallenge,
    coordinatorReceipt,
    coordinatorEventPath,
    observationPath,
    taskClass
  });

  const result = {
    disposition: local.disposition,
    passed: false,
    local_world_contact: local,
    writer_domain_seal: {
      passed: false,
      writer_domain: trustedSeal?.payload?.writer_domain ?? null,
      signature_valid: false,
      task_match: false,
      challenge_match: false,
      event_path_match: false,
      event_hash_match: false,
      reason: null
    }
  };

  if (local.disposition !== 'verified') {
    result.writer_domain_seal.reason = 'bundle-local world contact did not verify';
    return result;
  }

  if (!trustedSeal || !trustedPublicKeyPem) {
    result.disposition = 'abstain-needs-evidence';
    result.writer_domain_seal.reason = 'independent coordinator seal/public key not supplied';
    return result;
  }

  if (trustedSeal.schema !== 'aide.writer-domain-seal/v1' || trustedSeal.signature_alg !== 'ed25519' || !trustedSeal.payload || !trustedSeal.signature_base64) {
    result.disposition = 'rejected';
    result.writer_domain_seal.reason = 'malformed coordinator writer-domain seal';
    return result;
  }

  const payload = trustedSeal.payload;
  const signature = Buffer.from(trustedSeal.signature_base64, 'base64');
  try {
    result.writer_domain_seal.signature_valid = crypto.verify(
      null,
      Buffer.from(canonical(payload), 'utf8'),
      trustedPublicKeyPem,
      signature
    );
  } catch {
    result.writer_domain_seal.signature_valid = false;
  }

  result.writer_domain_seal.task_match = payload.task_id === expectedChallenge.task_id;
  result.writer_domain_seal.challenge_match = payload.challenge_sha256 === sha256Canonical(expectedChallenge);
  result.writer_domain_seal.event_path_match = payload.event_path === coordinatorEventPath.replaceAll('\\', '/');

  let eventBytes;
  try {
    eventBytes = await fs.readFile(safeResolve(path.dirname(path.resolve(bundlePath)), coordinatorEventPath));
    result.writer_domain_seal.event_hash_match = payload.event_sha256 === sha256Buffer(eventBytes);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  const sealPassed = result.writer_domain_seal.signature_valid &&
    payload.writer_domain === 'coordinator' &&
    result.writer_domain_seal.task_match &&
    result.writer_domain_seal.challenge_match &&
    result.writer_domain_seal.event_path_match &&
    result.writer_domain_seal.event_hash_match;

  result.writer_domain_seal.passed = sealPassed;
  if (!sealPassed) {
    result.disposition = 'rejected';
    result.writer_domain_seal.reason = 'independent coordinator seal does not authenticate the bundle-local world event';
    return result;
  }

  result.disposition = 'verified';
  result.passed = true;
  result.writer_domain_seal.reason = 'Ed25519 coordinator seal authenticates the exact world-event bytes used for verification';
  return result;
}
