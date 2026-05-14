# CLAUDE.md — Filesystem

> **NON-NEGOTIABLE PRIME DIRECTIVE:**
> **"We had been in position that all tests do execute with success and
> all Challenges as well, but in reality the most of the features does
> not work and can't be used! This MUST NOT be the case and execution
> of tests and Challenges MUST guarantee the quality, the completion
> and full usability by end users of the product!"**
> This statement is the foundational requirement of this project. Any
> agent dispatch, any CI configuration, any code review that allows
> green tests on broken features is a violation and MUST be rejected.

> **Constitution v2.3.0**: [Read the Constitution](https://github.com/HelixDevelopment/HelixPlay/blob/main/docs/research/chapters/MVP/05_Response/01_Constitution.md)
> All rules in Constitution §1-§21 are MANDATORY. No exception.
>
> **Amendments (2026-05-02):**
> - Anti-bluff: forbidden patterns include `assert.True(t, true)`,
>   `assert.NotNil(t, nil)`, constructor-only tests, mock-only
>   integration/E2E tests, and permanently skipped tests without
>   containerization plans.
> - Usability evidence mandatory per §6.7 (HelixQA visual assertion,
>   manual recording, or Challenge scenario).
> - Automatic negative-leg fault injection per §1.3 / §6.3 / §11.5.7 —
>   CI breaks each feature and verifies non-Unit tests fail.
> - `ValidateAntiBluff` unconditional; all challenges call `RecordAction()`.
> - Container verifier `execCommand()` executes real commands.
> - `go vet ./...` MUST pass with zero warnings — no suppressions, no exceptions.
> - Anti-bluff scan MUST fail the CI lane: `scripts/anti-bluff-scan.sh` exits
>   non-zero on any violation. Process substitution (`< <(...)>`) required over
>   pipes for variable state propagation; subshell-based patterns that silently
>   drop failure state are forbidden.
> - Observable behaviour assertion ratio: at least 60% of assertions must verify
>   observable behaviour per §1.2.
> - Mutation score >= 85% enforced by `mutation_ratchet_challenge.sh` per §6.4.
> - The 18 Contract Clauses (R-01..R-18) codified in §17.
> - Eight Architectural Pillars codified in §18 — binding architectural decisions.
> - Performance SLAs codified in §19 — <=30ms LAN, <=50ms WAN at p999.
> - Technology Stack codified in §20 — mandatory technology choices.
> - Implementation Roadmap codified in §21 — 14 phases (P00–P13).

## Project Context
This submodule is part of the HelixPlay system.
See the [feature spec](https://github.com/HelixDevelopment/HelixPlay/blob/001-helixplay-system/specs/001-helixplay-system/spec.md).

## Submodule-Specific Notes
<!-- Add submodule-specific AI agent guidance here -->

---

## Article XI §11.9 — Anti-Bluff Forensic Anchor (cascaded from parent CONSTITUTION.md)

> Verbatim user mandate (2026-04-29, reasserted multiple times across 2026-05): *"We had been in position that all tests do execute with success and all Challenges as well, but in reality the most of the features does not work and can't be used! This MUST NOT be the case and execution of tests and Challenges MUST guarantee the quality, the completion and full usability by end users of the product!"*

Operative rule: **The bar for shipping is not "tests pass" but "users can use the feature."** Every PASS in this codebase MUST carry positive runtime evidence captured during execution. Metadata-only / configuration-only / absence-of-error / grep-based PASS without runtime evidence are critical defects regardless of how green the summary line looks. No false-success results are tolerable.

This anchor MUST remain in this submodule's CONSTITUTION.md, CLAUDE.md, and AGENTS.md alongside CONST-047 — see the parent repository's `CONSTITUTION.md` for the full text.
