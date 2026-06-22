# AGENTS.md — Filesystem

## INHERITED FROM the Helix Constitution

This module is governed by the Helix Constitution. All rules in the
constitution's `AGENTS.md` and the `Constitution.md` it references apply
unconditionally. Locate the constitution from any nested depth via its
`find_constitution.sh` helper — do NOT hardcode a path (this module stays
fully decoupled and project-agnostic per §11.4.28).

Canonical reference: https://github.com/HelixDevelopment/HelixConstitution

## Repo state
This is a `vasic-digital` / `HelixDevelopment` submodule for the parent project.

## Critical constraints
- **Anti-bluff:** No placeholders, dead code, vacuous tests. Details in Constitution §1.
- **Containers only:** Every service, DB, build, test runs inside a container.
- **Decoupling:** Reusable components live in public `vasic-digital` submodules.
- **Tests:** 100% coverage across all ten types. Only Unit may use mocks.
- **R-18 Operational Integrity:** No command may suspend/hibernate/lock/terminate/crash the host.

## Git topology
`origin` fetch=GitHub, push=GitFlic. Four remotes configured.
Force-push requires explicit authorization. `--no-verify` is forbidden.
