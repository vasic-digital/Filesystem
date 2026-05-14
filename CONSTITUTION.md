# CONSTITUTION.md — Filesystem

> **Source of truth:** [https://github.com/HelixDevelopment/HelixPlay/blob/main/docs/research/chapters/MVP/05_Response/01_Constitution.md](https://github.com/HelixDevelopment/HelixPlay/blob/main/docs/research/chapters/MVP/05_Response/01_Constitution.md)
>
> This submodule adopts the HelixPlay Constitution v2.3.0 in full.
> All clauses §1-§21 are binding. No local weakening permitted.

---

## Article XI §11.9 — Anti-Bluff Forensic Anchor (cascaded from parent CONSTITUTION.md)

> Verbatim user mandate (2026-04-29, reasserted multiple times across 2026-05): *"We had been in position that all tests do execute with success and all Challenges as well, but in reality the most of the features does not work and can't be used! This MUST NOT be the case and execution of tests and Challenges MUST guarantee the quality, the completion and full usability by end users of the product!"*

Operative rule: **The bar for shipping is not "tests pass" but "users can use the feature."** Every PASS in this codebase MUST carry positive runtime evidence captured during execution. Metadata-only / configuration-only / absence-of-error / grep-based PASS without runtime evidence are critical defects regardless of how green the summary line looks. No false-success results are tolerable.

This anchor MUST remain in this submodule's CONSTITUTION.md, CLAUDE.md, and AGENTS.md alongside CONST-047 — see the parent repository's `CONSTITUTION.md` for the full text.
