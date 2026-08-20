import path from 'node:path';

export const EXTERNAL_RUN_SCHEMA = 'aide.external-run/v1';
export const CLAIM_STATUSES = new Set(['success', 'failure', 'partial']);

const SHA256 = /^[a-f0-9]{64}$/i;
const COMMIT = /^[a-f0-9]{7,64}$/i;

function string(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function safeRelativePath(value) {
  if (!string(value)) return false;
  if (path.isAbsolute(value) || path.win32.isAbsolute(value)) return false;
  const normalized = value.replaceAll('\\', '/');
  return !normalized.split('/').some(part => part === '..');
}

function missing(issues, field, message = 'is required') {
  issues.push({ kind: 'missing', field, message });
}

function invalid(issues, field, message) {
  issues.push({ kind: 'reject', field, message });
}

export function validateExternalRunBundle(bundle) {
  const issues = [];
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
    invalid(issues, '$', 'bundle must be a JSON object');
    return { valid: false, issues };
  }

  if (!string(bundle.schema)) missing(issues, 'schema');
  else if (bundle.schema !== EXTERNAL_RUN_SCHEMA) invalid(issues, 'schema', `unsupported schema: ${bundle.schema}`);

  if (!string(bundle.task?.id)) missing(issues, 'task.id');
  if (!string(bundle.task?.summary)) missing(issues, 'task.summary');
  if (!string(bundle.executor?.agent)) missing(issues, 'executor.agent');

  if (!string(bundle.timing?.started_at)) missing(issues, 'timing.started_at');
  if (!string(bundle.timing?.finished_at)) missing(issues, 'timing.finished_at');
  if (string(bundle.timing?.started_at) && Number.isNaN(Date.parse(bundle.timing.started_at))) {
    invalid(issues, 'timing.started_at', 'must be an ISO-8601 timestamp');
  }
  if (string(bundle.timing?.finished_at) && Number.isNaN(Date.parse(bundle.timing.finished_at))) {
    invalid(issues, 'timing.finished_at', 'must be an ISO-8601 timestamp');
  }
  if (string(bundle.timing?.started_at) && string(bundle.timing?.finished_at)) {
    const started = Date.parse(bundle.timing.started_at);
    const finished = Date.parse(bundle.timing.finished_at);
    if (!Number.isNaN(started) && !Number.isNaN(finished) && finished < started) {
      invalid(issues, 'timing.finished_at', 'must not be earlier than started_at');
    }
  }

  if (!string(bundle.claim?.status)) missing(issues, 'claim.status');
  else if (!CLAIM_STATUSES.has(bundle.claim.status)) invalid(issues, 'claim.status', 'must be success, failure, or partial');

  if (!string(bundle.repository?.base_commit)) missing(issues, 'repository.base_commit');
  else if (!COMMIT.test(bundle.repository.base_commit)) invalid(issues, 'repository.base_commit', 'must look like a Git commit id');
  if (!string(bundle.repository?.head_commit)) missing(issues, 'repository.head_commit');
  else if (!COMMIT.test(bundle.repository.head_commit)) invalid(issues, 'repository.head_commit', 'must look like a Git commit id');
  if (!Array.isArray(bundle.repository?.changed_files)) missing(issues, 'repository.changed_files');
  else {
    for (const [index, file] of bundle.repository.changed_files.entries()) {
      if (!safeRelativePath(file)) invalid(issues, `repository.changed_files[${index}]`, 'must be a safe relative path');
    }
  }
  if (!string(bundle.repository?.diff_sha256)) missing(issues, 'repository.diff_sha256');
  else if (!SHA256.test(bundle.repository.diff_sha256)) invalid(issues, 'repository.diff_sha256', 'must be a SHA-256 hex digest');

  if (!Array.isArray(bundle.tests)) missing(issues, 'tests');
  else {
    for (const [index, test] of bundle.tests.entries()) {
      if (!string(test?.name)) missing(issues, `tests[${index}].name`);
      if (!string(test?.command)) missing(issues, `tests[${index}].command`);
      if (!Number.isInteger(test?.exit_code)) missing(issues, `tests[${index}].exit_code`);
      if (!string(test?.output_path)) missing(issues, `tests[${index}].output_path`);
      else if (!safeRelativePath(test.output_path)) invalid(issues, `tests[${index}].output_path`, 'must be a safe relative path');
      if (!string(test?.output_sha256)) missing(issues, `tests[${index}].output_sha256`);
      else if (!SHA256.test(test.output_sha256)) invalid(issues, `tests[${index}].output_sha256`, 'must be a SHA-256 hex digest');
    }
  }

  if (!Array.isArray(bundle.artifacts)) missing(issues, 'artifacts');
  else {
    for (const [index, artifact] of bundle.artifacts.entries()) {
      if (!string(artifact?.name)) missing(issues, `artifacts[${index}].name`);
      if (!string(artifact?.kind)) missing(issues, `artifacts[${index}].kind`);
      if (!string(artifact?.path)) missing(issues, `artifacts[${index}].path`);
      else if (!safeRelativePath(artifact.path)) invalid(issues, `artifacts[${index}].path`, 'must be a safe relative path');
      if (!string(artifact?.sha256)) missing(issues, `artifacts[${index}].sha256`);
      else if (!SHA256.test(artifact.sha256)) invalid(issues, `artifacts[${index}].sha256`, 'must be a SHA-256 hex digest');
    }
  }

  if (bundle.fallbacks !== undefined && !Array.isArray(bundle.fallbacks)) {
    invalid(issues, 'fallbacks', 'must be an array when present');
  } else if (Array.isArray(bundle.fallbacks)) {
    for (const [index, fallback] of bundle.fallbacks.entries()) {
      for (const field of ['from', 'to', 'reason', 'at']) {
        if (!string(fallback?.[field])) missing(issues, `fallbacks[${index}].${field}`);
      }
      if (string(fallback?.at) && Number.isNaN(Date.parse(fallback.at))) {
        invalid(issues, `fallbacks[${index}].at`, 'must be an ISO-8601 timestamp');
      }
    }
  }

  return { valid: issues.length === 0, issues };
}

export function isSafeEvidencePath(value) {
  return safeRelativePath(value);
}
