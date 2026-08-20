function upper(value) {
  return String(value || 'unknown').toUpperCase();
}

export function renderExternalRunReport(result) {
  const lines = [
    '# AIDE External Run Verification',
    '',
    `Disposition: ${upper(result.disposition)}`,
    `Task: ${result.task_id || 'unknown'}`,
    `Executor: ${result.executor?.agent || 'unknown'}`,
    `Provider: ${result.executor?.provider || 'not-disclosed'}`,
    `Model: ${result.executor?.model || 'not-disclosed'}`,
    `Evidence score: ${Math.round((result.evidence_score || 0) * 100)}%`,
    `Veritas: ${result.veritas?.status || 'unknown'}`,
    ''
  ];

  lines.push('## Deterministic Checks', '');
  for (const item of result.checks || []) lines.push(`- ${item.name}: ${item.passed ? 'PASS' : 'BLOCK'}`);
  lines.push('');

  if (result.contradictions?.length) {
    lines.push('## Contradictions / Tamper Evidence', '');
    for (const item of result.contradictions) lines.push(`- ${item}`);
    lines.push('');
  }

  if (result.missing_evidence?.length) {
    lines.push('## Missing Evidence', '');
    for (const item of result.missing_evidence) lines.push(`- ${item}`);
    lines.push('');
  }

  lines.push('## Rule', '');
  lines.push(result.veritas?.rule || 'A claim is not proof. Deterministic evidence controls the disposition.');
  return lines.join('\n').trimEnd();
}
