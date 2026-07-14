# AGENTS.md for hyf

## Scope

This repository is the public HYF Rust workspace. Keep it usable from its own
root with ordinary Cargo commands and without machine-local paths or operator
context.

## Engineering Rules

- Work from the source, tests, fixtures, and public docs in this repository.
- Keep changes small, deterministic, reviewable, and verified.
- Prefer explicit contracts, typed errors, bounded buffers, caller-provided
  storage, and borrowed decoding on hot paths.
- Preserve `no_std` posture for firmware-capable crates.
- Do not add `unsafe`.
- Do not add compatibility aliases, legacy wrappers, hidden fallbacks, or
  deprecated shim modules.
- Do not add runtime Python dependencies.
- Do not copy code from external reference implementations.
- Do not claim Reticulum/RNS compatibility beyond profiles proven by tests and
  evidence.
- Do not add `scripts/**`, `.act/**`, or `.github/workflows/**`.
- Do not add live relay defaults, production secrets, real identities, or
  hardware requirements to default tests.

## Validation

Before claiming a source change is complete, run the narrowest relevant checks.
For broad Rust validation, use:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For crate-specific work, prefer the smallest package or integration test that
covers the change, then widen as risk increases.

For Nostr uplink verification, follow `docs/verification/nostr_uplink.md`.

For FIPS sidecar carrier verification, follow
`docs/verification/fips_sidecar.md`.

Optional Reticulum oracle checks may use `HYF_RETICULUM_PATH`. Optional RNode
serial checks may use `HYF_HIL_RNODE_PORT` only when a real device is explicitly
connected. When hardware is not configured, report the skip plainly and do not
describe it as hardware validation.
