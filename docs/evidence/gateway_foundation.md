# Gateway Foundation Evidence

## Scope

This evidence covers the gateway foundation: typed config, pure router
commands, bounded owned frame storage, deterministic loopback links, gateway
ingestion, loopback polling, time-aware expiry, retry-safe duplicate commit
behavior, and local smoke tests.

It does not claim production readiness or live network interoperability.

## Source State

- Evidence source baseline: `ebc8c43`
- Verification date: 2026-07-11

## Commands

The following checks passed from the repository root:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- no-default checks for `hyf_core`, `hyf_crypto`, `hyf_wire`, `hyf_link`,
  `hyf_store`, `hyf_router`, `hyf_link_loopback`, `hyf_config`,
  `hyf_rns_core`, `hyf_rns_crypto`, and `hyf_rns_wire`
- `cargo test -p hyf_gateway`
- `cargo test -p hyf_gateway --test gateway_smoke`
- `cargo test -p hyf_rns_conformance`
- `cargo bench -p hyf_rns_conformance --bench profile0 --no-run`
- `cargo build --manifest-path fuzz/Cargo.toml --bins`

`HYF_RETICULUM_PATH` was unset for this evidence capture, so optional Python
Reticulum oracle checks were skipped.

## Known Limitations

- No FIPS runtime code or dependency was added.
- No Nostr, LXMF, or BitChat integration was added.
- No live RNS/RNode gateway I/O was added.
- No Reticulum path table or Reticulum link-session runtime was added.
- No firmware, mobile application, bridge room, async daemon, or production
  persistence was added.
