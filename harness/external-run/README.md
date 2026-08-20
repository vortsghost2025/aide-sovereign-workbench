# External Run Verification

AIDE can verify evidence produced by an executor it does not control. The executor may be a coding agent, CI worker, supervisor, remote machine, or another orchestration system.

The external-run contract deliberately separates **execution** from **verification**:

```text
external executor -> evidence bundle -> AIDE deterministic checks -> Veritas -> disposition
```

AIDE does not trust the executor's success claim. It binds the claim to Git commits, the canonical diff, changed-file scope, test exit codes, and SHA-256 evidence artifacts.

## Dispositions

- `verified` — required evidence is complete and every deterministic binding agrees.
- `rejected` — supplied evidence contradicts the claim or an integrity binding fails.
- `abstain-needs-evidence` — AIDE cannot prove the claim because required evidence is missing.

## Bundle v1

```json
{
  "schema": "aide.external-run/v1",
  "task": { "id": "task-123", "summary": "Fix the provider test" },
  "executor": { "agent": "worker-1", "provider": "local", "model": "coder" },
  "timing": { "started_at": "2026-08-20T20:00:00Z", "finished_at": "2026-08-20T20:02:00Z" },
  "claim": { "status": "success" },
  "repository": {
    "base_commit": "<git commit>",
    "head_commit": "<git commit>",
    "changed_files": ["providers/test-manager.mjs"],
    "diff_sha256": "<sha256 of canonical git diff>"
  },
  "tests": [
    {
      "name": "provider-manager",
      "command": "node providers/test-manager.mjs",
      "exit_code": 0,
      "output_path": "evidence/provider-manager.txt",
      "output_sha256": "<sha256 of raw output file>"
    }
  ],
  "artifacts": [
    {
      "name": "git-diff",
      "kind": "git-diff",
      "path": "evidence/change.patch",
      "sha256": "<sha256 of raw artifact file>"
    }
  ],
  "fallbacks": []
}
```

Evidence paths are relative to the bundle directory. Absolute paths and `..` traversal are rejected.

## Verify

```bash
npm run veritas:external -- --bundle artifacts/external-run.json --workspace . --report
```

The verifier never replays arbitrary commands from the bundle. Test commands are evidence labels; their exit codes and output artifacts are verified, while repository bindings are recomputed independently from Git.
