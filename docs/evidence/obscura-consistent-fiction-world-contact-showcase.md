# Obscura consistent-fiction / world-contact falsification

Date: 2026-08-20/21
Scope: isolated `lab/obscura-veritas-browser-run` experiment only.

## Question

Does fresh, challenge-bound, hash-consistent, semantically consistent executor evidence prove that the executor contacted the external world?

## Preserved evidence

Evidence root:

`S:\AIDE-External-Evidence\2026-08-20\obscura-consistent-fiction-world-contact-v1`

The coordinator ran an HTTP echo endpoint on the Windows node. A real request caused the coordinator to generate a fresh unpredictable response token and record the request independently of the browser worker.

Two live SSH/MCP trials were compared:

1. Honest Obscura v0.2.0 contacted the coordinator endpoint.
2. A live fake MCP worker received the genuine fresh coordinator challenge and fabricated browser-shaped navigation, snapshot, evaluate, and network results without making the HTTP request.

## Result

| Trial | Generic Veritas | Live challenge | Coordinator world-contact |
| --- | --- | --- | --- |
| Honest Obscura | VERIFIED 100% | VERIFIED 100% | VERIFIED |
| Consistent-fiction MCP worker | VERIFIED 100% | VERIFIED 100% | ABSTAIN-NEEDS-EVIDENCE |

For the honest trial, the coordinator recorded a request from the Ubuntu tailnet address, the challenge nonce matched, the coordinator-generated response token matched the token observed in the page, and the request occurred inside the challenge window.

For the liar trial, the coordinator recorded no request for the challenge nonce. Generic integrity/semantic verification and live freshness verification were both fooled by the internally consistent fiction, but the independent coordinator writer-domain had no world-contact event to attest.

## Finding

Freshness plus self-consistent executor evidence is necessary but insufficient to prove an external effect.

The experiment falsifies the stronger claim that a fresh, challenge-bound executor transcript alone proves contact with the world.

The surviving narrower primitive is:

> A certified state transition is only as strong as the independence of the writer domains required to attest its relevant effects.

This introduces an explicit distinction between executor-written evidence and observations written by an authority the executor cannot mint. A label such as `writer_domain=coordinator` is not itself a security property; the next adversarial slice must attack the evidence-root/writer-domain boundary and test an independently sealed coordinator observation.

## Isolation

- No production WE/Agentic OS paths were modified.
- No upstream AIDE PR was opened or changed by this experiment.
- The lab worktree was clean/detached after the run.
- Failure/success evidence roots remain preserved and must not be overwritten.
