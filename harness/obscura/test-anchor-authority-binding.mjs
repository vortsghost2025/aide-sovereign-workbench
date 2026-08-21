import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { toolText } from './ssh-mcp-client.mjs';

const execFileAsync = promisify(execFile);

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  if (index < 0) return fallback;
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`--${name} requires a value`);
  return value;
}

async function git(workspace, args, timeout = 120_000) {
  const { stdout } = await execFileAsync('git', args, {
    cwd: workspace,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout,
    windowsHide: true
  });
  return String(stdout).replaceAll('\r\n', '\n');
}

async function writeUtf8(file, text) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, text, 'utf8');
}

function sha256Bytes(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function sha256Text(text) {
  return sha256Bytes(Buffer.from(String(text), 'utf8'));
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = stableValue(value[key]);
    return out;
  }
  return value;
}

function stableStringify(value) {
  return JSON.stringify(stableValue(value));
}

function transcriptText(transcript) {
  return `${(transcript || []).map(entry => JSON.stringify(entry)).join('\n')}\n`;
}

function parseObjectText(text) {
  if (!text) return null;
  const trimmed = String(text).trim();
  try {
    const first = JSON.parse(trimmed);
    if (first && typeof first === 'object') return first;
    if (typeof first === 'string') {
      const second = JSON.parse(first);
      if (second && typeof second === 'object') return second;
    }
  } catch {}
  const match = trimmed.match(/\{[\s\S]*\}/);
  if (!match) return null;
  try {
    const value = JSON.parse(match[0]);
    return value && typeof value === 'object' ? value : null;
  } catch {
    return null;
  }
}

function evaluateRequestIds(transcript) {
  const ids = new Set();
  for (const entry of transcript || []) {
    const message = entry?.message;
    if (entry?.direction === 'out' && message?.method === 'tools/call' && message?.params?.name === 'browser_evaluate') {
      ids.add(String(message.id));
    }
  }
  return ids;
}

function findEvaluateObservation(transcript) {
  const requestIds = evaluateRequestIds(transcript);
  for (const entry of transcript || []) {
    const message = entry?.message;
    if (entry?.direction !== 'in' || message?.id === undefined || !requestIds.has(String(message.id))) continue;
    const text = toolText(message.result);
    const observation = parseObjectText(text);
    if (observation) return { rpc_id: message.id, observation, response_text: text };
  }
  return null;
}

function mutateEvaluateTranscript(transcript, fabricatedTitle) {
  const clone = JSON.parse(JSON.stringify(transcript || []));
  const requestIds = evaluateRequestIds(clone);
  for (const entry of clone) {
    const message = entry?.message;
    if (entry?.direction !== 'in' || message?.id === undefined || !requestIds.has(String(message.id))) continue;
    const currentText = toolText(message.result);
    const current = parseObjectText(currentText);
    if (!current) continue;
    const mutated = { ...current, title: fabricatedTitle, h1: fabricatedTitle };
    const content = message.result?.content;
    if (!Array.isArray(content)) continue;
    const textItem = content.find(item => item?.type === 'text');
    if (!textItem) continue;
    textItem.text = JSON.stringify(mutated);
    return { transcript: clone, rpc_id: message.id, mutated_observation: mutated };
  }
  return { transcript: clone, rpc_id: null, mutated_observation: null };
}

function verifyAnchorRequest(request) {
  if (!request || request.schema !== 'aide.external-transcript-anchor-request/v1') {
    return { disposition: 'rejected', reason: 'anchor request schema missing or unsupported' };
  }
  const { request_sha256: declared, ...body } = request;
  const observed = sha256Text(stableStringify(body));
  return {
    disposition: declared === observed ? 'verified' : 'rejected',
    declared_sha256: declared || null,
    observed_sha256: observed,
    match: declared === observed,
    reason: declared === observed ? 'anchor request bytes match their self-digest' : 'anchor request bytes diverge from their declared digest'
  };
}

function createSubstitutedRequest(originalRequest, mutatedTranscript, mutatedObservation) {
  const body = {
    schema: 'aide.external-transcript-anchor-request/v1',
    captured_at: new Date().toISOString(),
    source_commit: originalRequest.source_commit,
    transcript_sha256: sha256Text(transcriptText(mutatedTranscript)),
    process_identity: originalRequest.process_identity,
    process_identity_sha256: originalRequest.process_identity_sha256,
    challenge_nonce: originalRequest.challenge_nonce,
    response_token: originalRequest.response_token,
    world_event_sha256: originalRequest.world_event_sha256,
    semantic_observation_sha256: sha256Text(stableStringify(mutatedObservation))
  };
  return { ...body, request_sha256: sha256Text(stableStringify(body)) };
}

function verifyAnchorAgainstRequest(anchor, request, transcript) {
  if (!anchor || anchor.schema !== 'aide.external-transcript-anchor/v1') {
    return { disposition: 'rejected', reason: 'external anchor schema missing or unsupported' };
  }
  const checks = {
    request_sha256: anchor.anchor_request_sha256 === request.request_sha256,
    transcript_sha256: anchor.transcript_sha256 === sha256Text(transcriptText(transcript)),
    source_commit: anchor.source_commit === request.source_commit,
    challenge_nonce: anchor.challenge_nonce === request.challenge_nonce,
    response_token: anchor.response_token === request.response_token,
    process_identity_sha256: anchor.process_identity_sha256 === request.process_identity_sha256,
    world_event_sha256: anchor.world_event_sha256 === request.world_event_sha256,
    semantic_observation_sha256: anchor.semantic_observation_sha256 === request.semantic_observation_sha256
  };
  const passed = Object.values(checks).every(Boolean);
  return {
    disposition: passed ? 'verified' : 'rejected',
    checks,
    reason: passed ? 'candidate external anchor matches the supplied anchor request and transcript' : 'candidate external anchor does not match the supplied anchor request and transcript'
  };
}

function verifyAnchorAgainstTranscript(anchor, transcript) {
  if (!anchor?.transcript_sha256) {
    return { disposition: 'abstain-needs-evidence', reason: 'external anchor transcript hash unavailable' };
  }
  const observed = sha256Text(transcriptText(transcript));
  const match = observed === anchor.transcript_sha256;
  return {
    disposition: match ? 'verified' : 'rejected',
    expected_sha256: anchor.transcript_sha256,
    observed_sha256: observed,
    match,
    reason: match ? 'transcript bytes match the selected external anchor' : 'transcript bytes diverge from the selected external anchor'
  };
}

async function readTranscript(file) {
  return (await fs.readFile(file, 'utf8'))
    .split(/\r?\n/)
    .filter(Boolean)
    .map(line => JSON.parse(line));
}

async function regenerateManifest(root) {
  const files = [];
  async function walk(dir) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile()) files.push(absolute);
    }
  }
  await walk(root);
  const manifest = [];
  for (const absolute of files) {
    const relative = path.relative(root, absolute).replaceAll('\\', '/');
    if (relative === 'manifest.sha256.json') continue;
    manifest.push({ path: relative, sha256: sha256Bytes(await fs.readFile(absolute)) });
  }
  await writeUtf8(path.join(root, 'manifest.sha256.json'), `${JSON.stringify(manifest, null, 2)}\n`);
}

async function preparePhase({ workspace, causal6Root, outputRoot, fabricatedTitle }) {
  try {
    await fs.access(outputRoot);
    throw new Error(`output path already exists; refusing to overwrite: ${outputRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before anchor-substitution prepare phase');

  const originalRequestPath = path.join(causal6Root, 'prepare', 'anchor-request.json');
  const originalTranscriptPath = path.join(causal6Root, 'prepare', 'original-mcp-transcript.ndjson');
  const originalRequest = JSON.parse(await fs.readFile(originalRequestPath, 'utf8'));
  const originalTranscript = await readTranscript(originalTranscriptPath);
  const originalRequestVerdict = verifyAnchorRequest(originalRequest);

  console.log('01 mutate a copy of the preserved CAUSAL-6 transcript...');
  const mutation = mutateEvaluateTranscript(originalTranscript, fabricatedTitle);
  if (!mutation.mutated_observation) throw new Error('unable to mutate browser_evaluate response');
  const mutatedTranscript = mutation.transcript;
  const mutatedBound = findEvaluateObservation(mutatedTranscript);

  console.log('02 construct a self-consistent substitute anchor request for the mutated bytes...');
  const substitutedRequest = createSubstitutedRequest(originalRequest, mutatedTranscript, mutatedBound?.observation || null);
  const substitutedRequestVerdict = verifyAnchorRequest(substitutedRequest);

  const originalTranscriptHash = sha256Text(transcriptText(originalTranscript));
  const mutatedTranscriptHash = sha256Text(transcriptText(mutatedTranscript));
  const matrix = {
    schema: 'aide.anchor-authority-substitution-prepare/v1',
    causal6_root: causal6Root,
    original_request: originalRequest,
    original_request_verdict: originalRequestVerdict,
    mutation: {
      rpc_id: mutation.rpc_id,
      fabricated_title: fabricatedTitle,
      observation: mutatedBound?.observation || null,
      original_transcript_sha256: originalTranscriptHash,
      mutated_transcript_sha256: mutatedTranscriptHash
    },
    substituted_request: substitutedRequest,
    substituted_request_verdict: substitutedRequestVerdict,
    findings: {
      original_request_self_digest_verified: originalRequestVerdict.disposition === 'verified',
      mutated_transcript_differs_from_original: originalTranscriptHash !== mutatedTranscriptHash,
      substituted_request_self_digest_verified: substitutedRequestVerdict.disposition === 'verified',
      substituted_request_differs_from_original_request: substitutedRequest.request_sha256 !== originalRequest.request_sha256,
      original_anchor_selection_not_yet_consulted: true
    }
  };

  const prepareRoot = path.join(outputRoot, 'prepare');
  await writeUtf8(path.join(prepareRoot, 'mutated-mcp-transcript.ndjson'), transcriptText(mutatedTranscript));
  await writeUtf8(path.join(prepareRoot, 'substituted-anchor-request.json'), `${JSON.stringify(substitutedRequest, null, 2)}\n`);
  await writeUtf8(path.join(prepareRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
  await writeUtf8(path.join(prepareRoot, 'report.md'), [
    '# CAUSAL-7A — Anchor substitution prepare',
    '',
    `Original request self-digest: ${originalRequestVerdict.disposition}`,
    `Original transcript SHA256: ${originalTranscriptHash}`,
    `Mutated transcript SHA256: ${mutatedTranscriptHash}`,
    `Substituted request self-digest: ${substitutedRequestVerdict.disposition}`,
    `Substituted request SHA256: ${substitutedRequest.request_sha256}`,
    '',
    'Interpretation:',
    '- CAUSAL-6 proved that an exact pinned external commit rejects local transcript re-sealing.',
    '- This phase constructs a different, internally self-consistent anchor request around the already-mutated transcript without changing the preserved CAUSAL-6 evidence.',
    '- The next step is intentionally out-of-band: publish this substitute request into a different content-addressed commit controlled as an attacker-selected candidate.',
    '- Phase B will then compare naive candidate-anchor acceptance against an independently authorized anchor-commit identity.',
    ''
  ].join('\n'));
  await regenerateManifest(prepareRoot);

  console.log(`Original request: ${originalRequestVerdict.disposition}`);
  console.log(`Original transcript SHA256: ${originalTranscriptHash}`);
  console.log(`Mutated transcript SHA256: ${mutatedTranscriptHash}`);
  console.log(`Substituted request: ${substitutedRequestVerdict.disposition}`);
  console.log(`Substituted request SHA256: ${substitutedRequest.request_sha256}`);
  console.log(`Evidence: ${outputRoot}`);

  const expected = Object.values(matrix.findings).every(Boolean);
  if (!expected) process.exitCode = 1;
}

async function verifyPhase({ workspace, causal6Root, outputRoot, anchorRemote, authorizedRef, authorizedCommit, authorizedPath, candidateRef, candidateCommit, candidatePath }) {
  const prepareRoot = path.join(outputRoot, 'prepare');
  const verifyRoot = path.join(outputRoot, 'verify');
  await fs.access(path.join(prepareRoot, 'substituted-anchor-request.json'));
  await fs.access(path.join(prepareRoot, 'mutated-mcp-transcript.ndjson'));
  try {
    await fs.access(verifyRoot);
    throw new Error(`verify path already exists; refusing to overwrite: ${verifyRoot}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const dirty = await git(workspace, ['status', '--porcelain']);
  if (dirty.trim()) throw new Error('workspace must be clean before anchor-authority verify phase');
  if (!authorizedCommit || !authorizedPath || !candidateCommit || !candidatePath) {
    throw new Error('--authorized-commit/--authorized-path/--candidate-commit/--candidate-path are required');
  }

  console.log('01 fetch and pin authorized and candidate anchor commits...');
  if (authorizedRef) await git(workspace, ['fetch', '--no-tags', anchorRemote, authorizedRef]);
  if (candidateRef) await git(workspace, ['fetch', '--no-tags', anchorRemote, candidateRef]);
  await git(workspace, ['cat-file', '-e', `${authorizedCommit}^{commit}`]);
  await git(workspace, ['cat-file', '-e', `${candidateCommit}^{commit}`]);

  const authorizedAnchor = JSON.parse(await git(workspace, ['show', `${authorizedCommit}:${authorizedPath}`]));
  const candidateAnchor = JSON.parse(await git(workspace, ['show', `${candidateCommit}:${candidatePath}`]));

  const originalRequest = JSON.parse(await fs.readFile(path.join(causal6Root, 'prepare', 'anchor-request.json'), 'utf8'));
  const originalTranscript = await readTranscript(path.join(causal6Root, 'prepare', 'original-mcp-transcript.ndjson'));
  const substitutedRequest = JSON.parse(await fs.readFile(path.join(prepareRoot, 'substituted-anchor-request.json'), 'utf8'));
  const mutatedTranscript = await readTranscript(path.join(prepareRoot, 'mutated-mcp-transcript.ndjson'));

  console.log('02 prove the original authorized anchor still matches the preserved CAUSAL-6 run...');
  const authorizedBaselineVerdict = verifyAnchorAgainstRequest(authorizedAnchor, originalRequest, originalTranscript);
  const authorizedVsMutatedVerdict = verifyAnchorAgainstTranscript(authorizedAnchor, mutatedTranscript);

  console.log('03 evaluate the attacker-selected candidate anchor only by content consistency...');
  const candidateRequestVerdict = verifyAnchorAgainstRequest(candidateAnchor, substitutedRequest, mutatedTranscript);
  const candidateTranscriptVerdict = verifyAnchorAgainstTranscript(candidateAnchor, mutatedTranscript);
  const naiveCandidateComposite = {
    disposition:
      candidateRequestVerdict.disposition === 'verified' && candidateTranscriptVerdict.disposition === 'verified'
        ? 'verified'
        : 'rejected',
    reason: 'naive verifier accepts whichever content-addressed candidate commit is supplied if its contents match the supplied local evidence'
  };

  console.log('04 bind acceptance to the independently authorized anchor commit identity...');
  const authorityVerdict = {
    disposition: candidateCommit === authorizedCommit ? 'verified' : 'rejected',
    authorized_commit: authorizedCommit,
    candidate_commit: candidateCommit,
    match: candidateCommit === authorizedCommit,
    reason: candidateCommit === authorizedCommit
      ? 'candidate anchor is the independently authorized commit'
      : 'candidate anchor is content-valid for the substituted evidence but is not the independently authorized commit'
  };
  const authorityBoundComposite = {
    disposition:
      naiveCandidateComposite.disposition === 'verified' && authorityVerdict.disposition === 'verified'
        ? 'verified'
        : 'rejected',
    reason: authorityVerdict.disposition === 'verified'
      ? 'candidate content is valid and its exact commit identity is authorized'
      : 'candidate content is self-consistent but the selected anchor commit identity is unauthorized'
  };

  const matrix = {
    schema: 'aide.anchor-authority-substitution-verify/v1',
    authorized_anchor: { remote: anchorRemote, ref: authorizedRef || null, commit: authorizedCommit, path: authorizedPath, document: authorizedAnchor },
    candidate_anchor: { remote: anchorRemote, ref: candidateRef || null, commit: candidateCommit, path: candidatePath, document: candidateAnchor },
    authorized_baseline_verdict: authorizedBaselineVerdict,
    authorized_anchor_vs_mutated_transcript: authorizedVsMutatedVerdict,
    candidate_request_verdict: candidateRequestVerdict,
    candidate_transcript_verdict: candidateTranscriptVerdict,
    naive_candidate_composite_verdict: naiveCandidateComposite,
    anchor_authority_verdict: authorityVerdict,
    authority_bound_composite_verdict: authorityBoundComposite,
    findings: {
      authorized_anchor_still_matches_original_run: authorizedBaselineVerdict.disposition === 'verified',
      authorized_anchor_rejects_mutated_transcript: authorizedVsMutatedVerdict.disposition === 'rejected',
      substituted_candidate_matches_substituted_request: candidateRequestVerdict.disposition === 'verified',
      substituted_candidate_matches_mutated_transcript: candidateTranscriptVerdict.disposition === 'verified',
      naive_candidate_selection_accepts_substitution: naiveCandidateComposite.disposition === 'verified',
      substituted_candidate_is_not_authorized_commit: authorityVerdict.disposition === 'rejected',
      authority_bound_composite_rejects_substitution: authorityBoundComposite.disposition === 'rejected',
      anchor_commit_authority_binding_adds_discrimination:
        naiveCandidateComposite.disposition === 'verified' && authorityBoundComposite.disposition === 'rejected'
    }
  };

  await fs.mkdir(verifyRoot, { recursive: true });
  await writeUtf8(path.join(verifyRoot, 'authorized-anchor.json'), `${JSON.stringify(authorizedAnchor, null, 2)}\n`);
  await writeUtf8(path.join(verifyRoot, 'candidate-anchor.json'), `${JSON.stringify(candidateAnchor, null, 2)}\n`);
  await writeUtf8(path.join(verifyRoot, 'matrix.json'), `${JSON.stringify(matrix, null, 2)}\n`);
  await writeUtf8(path.join(verifyRoot, 'report.md'), [
    '# CAUSAL-7B — Anchor authority binding verification',
    '',
    `Authorized anchor vs original run: ${authorizedBaselineVerdict.disposition}`,
    `Authorized anchor vs mutated transcript: ${authorizedVsMutatedVerdict.disposition}`,
    `Candidate anchor vs substituted request: ${candidateRequestVerdict.disposition}`,
    `Candidate anchor vs mutated transcript: ${candidateTranscriptVerdict.disposition}`,
    `Naive candidate-anchor composite: ${naiveCandidateComposite.disposition}`,
    `Candidate exact-commit authority: ${authorityVerdict.disposition}`,
    `Authority-bound composite: ${authorityBoundComposite.disposition}`,
    '',
    'Interpretation:',
    '- Content addressing protects the bytes of a selected commit but does not decide which commit is authorized for a task.',
    '- If an executor may substitute a different self-consistent external commit, naive content-only verification can accept the substituted history.',
    '- Binding the exact anchor commit identity to an independently authorized coordinator/verifier decision adds a separate requirement: anchor-selection authority.',
    '- This lab comparison does not yet prove how production authorization is protected. The source of the authorized commit identity must itself be outside executor rewrite authority and freshness/task-bound.',
    ''
  ].join('\n'));
  await regenerateManifest(verifyRoot);

  console.log(`Authorized baseline: ${authorizedBaselineVerdict.disposition}`);
  console.log(`Authorized anchor vs mutation: ${authorizedVsMutatedVerdict.disposition}`);
  console.log(`Candidate request/content: ${candidateRequestVerdict.disposition}`);
  console.log(`Candidate transcript/content: ${candidateTranscriptVerdict.disposition}`);
  console.log(`Naive candidate composite: ${naiveCandidateComposite.disposition}`);
  console.log(`Anchor authority: ${authorityVerdict.disposition}`);
  console.log(`Authority-bound composite: ${authorityBoundComposite.disposition}`);
  console.log(`Authority discriminator: ${matrix.findings.anchor_commit_authority_binding_adds_discrimination}`);
  console.log(`Evidence: ${outputRoot}`);

  const expected = Object.values(matrix.findings).every(Boolean);
  if (!expected) process.exitCode = 1;
}

async function main() {
  const phase = arg('phase', 'prepare');
  const workspace = path.resolve(arg('workspace', process.cwd()));
  const causal6Arg = arg('causal6-root');
  const outputArg = arg('output');
  if (!causal6Arg) throw new Error('--causal6-root is required');
  if (!outputArg) throw new Error('--output is required');
  const causal6Root = path.resolve(causal6Arg);
  const outputRoot = path.resolve(outputArg);
  const fabricatedTitle = arg('fabricated-title', 'ANCHOR SUBSTITUTION FABRICATION');
  const anchorRemote = arg('anchor-remote', 'fork');
  const authorizedRef = arg('authorized-ref', null);
  const authorizedCommit = arg('authorized-commit', null);
  const authorizedPath = arg('authorized-path', null);
  const candidateRef = arg('candidate-ref', null);
  const candidateCommit = arg('candidate-commit', null);
  const candidatePath = arg('candidate-path', null);

  if (phase === 'prepare') {
    await preparePhase({ workspace, causal6Root, outputRoot, fabricatedTitle });
    return;
  }
  if (phase === 'verify') {
    await verifyPhase({ workspace, causal6Root, outputRoot, anchorRemote, authorizedRef, authorizedCommit, authorizedPath, candidateRef, candidateCommit, candidatePath });
    return;
  }
  throw new Error(`unsupported --phase ${phase}`);
}

main().catch(error => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
