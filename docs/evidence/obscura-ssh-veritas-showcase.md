# Distributed Obscura Veritas Showcase

This note records a cross-machine browser execution verified independently by AIDE Veritas.

## Topology

- Coordinator/verifier: Windows AIDE worktree
- Browser executor: Ubuntu headless node over private Tailscale SSH
- Browser engine: Obscura CLI `0.2.0`
- MCP server: `obscura-mcp` `0.1.0`
- MCP protocol: `2024-11-05`
- Transport: newline-delimited JSON-RPC over SSH stdio

The MCP server is not exposed over LAN or the public internet. AIDE launches the remote browser process through SSH and records the MCP request/response transcript as evidence.

## Mission

The remote Obscura worker navigated to `https://example.com` and produced deterministic browser evidence including:

- MCP initialization metadata
- tool catalog
- navigation result
- page snapshot
- page Markdown
- link extraction
- JavaScript-derived page identity
- network-request evidence
- complete MCP transcript
- deterministic mission assertions

The evidence was hashed and wrapped in the existing `aide.external-run/v1` contract. The repository binding used a zero-diff transition at the lab commit so browser evidence could be judged without weakening the existing Git/diff guarantees of the external-run verifier.

## Important semantic correction

The first distributed run exposed a real bridge bug: the prototype assumed the MCP server version must equal the Obscura CLI release version. The installed CLI reported `0.2.0`, while the MCP crate correctly identified itself as `0.1.0`.

That run produced a useful distinction:

- browser execution: failed its incorrect version assertion
- evidence verification: verified

In other words, AIDE correctly authenticated the evidence describing a failed execution. The bridge was then corrected to treat execution outcome and evidence verification as independent axes and to record CLI release, MCP server version, and MCP protocol separately.

## Corrected run

The corrected run completed with:

- execution outcome: `PASS`
- evidence verification: `VERIFIED`
- evidence score: `100%`
- Obscura CLI: `0.2.0`
- MCP server: `0.1.0`
- MCP protocol: `2024-11-05`

Every deterministic external-run check passed:

- external schema
- commit binding
- artifact integrity
- diff binding
- changed-file binding
- test evidence integrity
- claim consistency
- fallback disclosure

The isolated AIDE worktree remained clean after the run.

## Why this matters

This is not an in-process browser mock. The browser work occurred on a separate Linux machine and operating system, while AIDE on Windows independently verified the resulting evidence.

The resulting architecture is:

```text
Windows AIDE / Veritas
        |
        | private SSH stdio
        v
Linux Obscura MCP
        |
        v
Web mission
        |
        v
hashed browser evidence + MCP transcript
        |
        v
AIDE external-run verifier
        |
        v
execution outcome + evidence disposition
```

The executor is treated as untrusted input. A successful browser claim is not sufficient; deterministic evidence controls the verification result.

## Next adversarial gates

The next lab phase should deliberately test:

1. tampered MCP transcript
2. tampered snapshot or extracted content
3. missing browser evidence
4. false page/title claim
5. remote browser crash
6. SSH interruption and recovery
7. parallel remote browser workers
8. evidence from a recovered run versus evidence lost during recovery

Expected outcomes remain distinct:

- contradictory/tampered evidence -> `REJECTED`
- incomplete evidence without contradiction -> `ABSTAIN-NEEDS-EVIDENCE`
- complete consistent evidence -> `VERIFIED`
