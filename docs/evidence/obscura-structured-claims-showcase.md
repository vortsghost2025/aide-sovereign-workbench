# AIDE × Obscura — Structured Browser Claim Verification

This lab checkpoint demonstrates deterministic semantic binding for browser observations produced remotely by Obscura over SSH.

## Topology

- Coordinator/verifier: Windows AIDE lab
- Transport: private SSH/Tailscale path
- Browser executor: `ubuntu-headless-we`
- Browser engine: Obscura CLI `0.2.0`
- MCP server: `0.1.0`
- MCP protocol: `2024-11-05`
- Test target: `https://example.com`

## Verified V4 run

The distributed V4 run completed successfully and produced hashed structured browser evidence.

Machine-checkable observations:

- page title = `Example Domain`
- page URL = `https://example.com/`
- H1 = `Example Domain`

Result:

- execution outcome: PASS
- evidence verification: VERIFIED
- evidence score: 100%
- structured claim binding: PASS
- `external-structured-claim-binding`: PASS

Free-form task/claim prose is treated only as descriptive metadata. Only declarations in `evidence_claims` are presented as machine-verified semantic observations.

## Adversarial comparison

The adversarial matrix establishes the distinction between evidence integrity and semantic claim binding:

| Case | Result |
| --- | --- |
| Baseline structured evidence | VERIFIED |
| Tampered `page-observation.json` | REJECTED |
| Missing `page-observation.json` | ABSTAIN-NEEDS-EVIDENCE |
| False structured title using old generic verifier | VERIFIED |
| Same false structured title using structured verifier | REJECTED |
| Free-form prose lie with unchanged structured claims | VERIFIED; structured claims remain PASS |

The structured verifier rejects the false title because the declared expected value does not match the independently read value in the hashed observation evidence.

## Architectural conclusion

The generic external-run verifier proves integrity, repository bindings, test evidence, and claim-status consistency. That is not sufficient to assert that arbitrary free-form English statements about browser observations are true.

The structured browser-claim layer closes that gap for explicitly declared machine claims by binding each claim to:

1. a declared evidence artifact,
2. a structured path within that artifact,
3. an expected value or deterministic predicate,
4. artifact-integrity verification,
5. an independently recomputed claim result.

This lab work intentionally remains separate from the current upstream proposal until the maintainer indicates whether external-run Veritas fits AIDE's direction.
