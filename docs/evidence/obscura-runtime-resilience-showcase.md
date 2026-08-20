# AIDE × Obscura runtime-resilience showcase

Date: 2026-08-20

Status: **PROVEN in isolated lab branch**

This note records a distributed crash/recovery proof for the AIDE × Obscura lab. It is intentionally separate from the upstream provider-test PR and the generic external-run proposal.

## Topology

- AIDE / Veritas coordinator: Windows
- Browser executor: Obscura `0.2.0` on a separate Ubuntu node
- Transport: private SSH stdio
- Browser protocol: Obscura MCP
- Verification: AIDE external-run verifier plus structured-claim binding

## What was fault-injected

A tracked Obscura MCP process was started through a unique wrapper and PID file. Before termination, the harness independently checked the live Linux process identity:

- `/proc/<pid>/exe` resolved exactly to the expected Obscura binary
- `argv[0]` was the expected Obscura binary
- `argv[1]` was exactly `mcp`

Only after those checks passed did the harness send `SIGTERM` to that exact PID.

No broad `pkill`, `killall`, wildcard process matching, or unrelated process termination is used.

## Verified V3 state-machine result

The corrected stateful harness produced:

- exact process identity: **PASS**
- exact remote SIGTERM: **PASS**
- remote process exit observed: **PASS**
- fresh Obscura browser recovery: **PASS**
- recovered title: `Example Domain`
- cleanup safety: **PASS**
- cleanup state: `already-gone`
- structured claim binding: **PASS**
- final evidence disposition: **VERIFIED**
- evidence score: **100%**

`already-gone` is the desired cleanup state in this run: the exact process deliberately terminated earlier had disappeared, so cleanup did not need to kill any further process. The cleanup state machine never kills a reused PID whose current executable/argv identity does not still match the exact tracked Obscura MCP process.

## Deterministic Veritas gates

All gates passed:

- `external-schema`
- `external-commit-binding`
- `external-artifact-integrity`
- `external-diff-binding`
- `external-changed-files`
- `external-test-integrity`
- `external-claim-consistency`
- `external-fallback-disclosure`
- `external-structured-claim-binding`

## Why the failed attempts matter

Earlier preserved runs were deliberately not overwritten:

1. A first resilience run recovered the browser but could not safely certify the intended remote kill; Veritas rejected the crash claim.
2. A hardened exact-identity run proved executable identity, `argv[1]=mcp`, termination, process exit, and browser recovery, but a cleanup-helper bug left `cleanup_safe=false`; Veritas rejected the overall transition.
3. A later identity-inspection attempt failed before certified termination and was also rejected.
4. The stateful V3 harness fixed the cleanup/identity state machine and reached the fully verified result above.

That progression is part of the evidence: successful recovery alone is not enough. Required safety and finalization postconditions must also be independently satisfied before a durable VERIFIED state transition is accepted.

## Architectural consequence

The experiment now has independent proof of both major runtime fault classes:

- SSH transport interruption → detected → fresh session recovery
- exact remote Obscura MCP process termination → detected → fresh session recovery → safe finalization

This strengthens the emerging proof-carrying-action model: execution outcome, evidence integrity, semantic claims, and safety/finalization invariants are separable and independently gate durable state.