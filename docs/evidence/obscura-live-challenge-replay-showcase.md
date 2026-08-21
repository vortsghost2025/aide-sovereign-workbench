# AIDE × Obscura Live Challenge Replay Showcase

Date: 2026-08-20
Scope: isolated lab branch `lab/obscura-veritas-browser-run`

## Result

The V2 replay matrix cleanly separates generic integrity/semantic verification from freshness verification.

| Case | Generic verifier | Live challenge verifier | Meaning |
| --- | --- | --- | --- |
| Fresh challenge A | VERIFIED | VERIFIED | Genuine fresh execution accepted |
| Simple replay A under new challenge B | VERIFIED | REJECTED | Generic verifier is replay-blind; live binding blocks stale challenge |
| Post-hoc rewrap A as B with rewritten challenge bytes and recomputed bundle-local hashes | VERIFIED | ABSTAIN-NEEDS-EVIDENCE | Generic integrity is insufficient; no independent coordinator receipt for the rewritten execution |
| Fresh challenge B | VERIFIED | VERIFIED | Independent second fresh execution accepted |

All fresh baseline mission assertions passed: challenge echo, page observation parse, title, final URL, and H1. Fresh A and Fresh B both had matching outbound/inbound challenge tokens in the captured MCP transcript and matching independent coordinator receipts.

## Key finding

A nonce or challenge value carried only inside executor-controlled evidence is not a freshness proof. The experiment demonstrated that an attacker can rewrite the challenge token in the observation/transcript and recompute bundle-local artifact hashes while the generic verifier still returns VERIFIED.

Freshness requires an independent coordinator-side receipt over the captured transcript and observation, checked against the coordinator-issued challenge. With that split trust boundary:

- stale replay is REJECTED;
- aggressive post-hoc rewrap without the coordinator receipt is not VERIFIED;
- genuinely fresh executions remain VERIFIED.

## What this does not prove

The coordinator receipt proves challenge freshness and binding to the coordinator-captured execution evidence. It does **not** prove that the remote executor contacted an external web origin. A malicious worker could still fabricate a self-consistent browser transcript/observation if all world-contact evidence is executor-originated.

The next falsification experiment should therefore compare an honest Obscura fetch with a lying worker against a coordinator-owned HTTP echo/access log. That test determines whether `CERTIFIED` can be tied to non-executor world-contact rather than merely consistent evidence.

## Preserved evidence

Local evidence root:

`S:\AIDE-External-Evidence\2026-08-20\obscura-live-challenge-replay-v2`

The failed V1 replay experiment remains preserved separately and was not overwritten.
