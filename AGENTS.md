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

## Handoff 3 Boundary

Allowed Handoff 3 work includes the owned frame store, pure router state
machine, deterministic loopback link, typed gateway config, gateway runtime
shell, public docs, local verification script, and local evidence.

Handoff 3 must not implement FIPS runtime code, Nostr, LXMF, BitChat, bridge
rooms, live RNS/RNode I/O, Reticulum path tables, Reticulum link sessions,
firmware, mobile apps, or production persistence.

## Verification

Before claiming a source change is complete, run the narrowest relevant checks.
For full Handoff 3 validation, run:

```bash
scripts/verify_handoff3.sh
```

For focused Rust work, prefer:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
