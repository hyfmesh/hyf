# AGENTS.md for hyf

## Scope

This repository is the public `hyf` Rust workspace. Keep it usable from this
repository root without private workspace paths, private planning files, or
machine-specific assumptions.

## Engineering Rules

- Work from the public source, tests, and docs in this repository.
- Keep changes small, reviewable, deterministic, and verified.
- Prefer explicit contracts, typed errors, bounded buffers, and caller-provided
  storage.
- Do not add compatibility aliases, legacy wrappers, hidden fallbacks, or
  deprecated shim modules.
- Do not add runtime Python dependencies.
- Do not add LXMF-rs or copy code from external reference implementations.
- Do not claim Reticulum/RNS compatibility beyond the profiles proven by tests
  and evidence.
- Do not add GitHub Actions or workflow files under `.github/workflows`.
- Do not add `.act` workflows to this public repository.

## Handoff 4 Boundary

Allowed Handoff 4 work includes:

- generic synchronous link-driver contracts;
- loopback driver integration;
- opaque RNS packet wrapping as `PayloadKind::ForeignRnsPacket`;
- fake-serial-first RNode/KISS serial gateway link behavior;
- feature-gated serialport open-gate support;
- gateway core/executor separation;
- fake RNode serial smoke tests;
- public docs, ADRs, and local verification scripts.

Handoff 4 must not implement FIPS runtime code, Nostr, LXMF, BitChat, bridge
rooms, full Reticulum path tables, Reticulum link sessions, resources, channels,
firmware, mobile apps, production persistence, or RF transmission by default.

## Verification

Before claiming a source change is complete, run the narrowest relevant checks.
For full Handoff 4 validation, run:

```bash
scripts/verify_handoff4.sh
```

For focused Rust work, prefer:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Optional `HYF_RETICULUM_PATH` and `HYF_HIL_RNODE_PORT` lanes may skip when the
environment is not configured. Report skips explicitly and do not overclaim
hardware validation.
