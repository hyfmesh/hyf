# HYF

HYF is a Rust workspace for deterministic, reviewable mesh-networking
foundations.

The project is pre-release. The current code is intended for source review,
conformance testing, and continued protocol development. It is not a production
router, daemon, firmware image, or mobile application.

## What Is Implemented

- `no_std`-capable core crates for identifiers, timestamps, typed wire data,
  bounded link frames, store policy, and pure routing state.
- Native HYF envelope encoding and decoding with caller-owned buffers.
- Synchronous link-driver contracts, deterministic loopback drivers, and a
  gateway runtime shell for local tests.
- Reticulum-compatible RNS profile components for packet headers, packet
  hashes, destination hashes, announces, IFAC, identity material, token
  encryption, KISS frames, and RNode command primitives.
- Conformance fixtures, schema checks, fuzz targets, and optional Python oracle
  tests for Reticulum/RNS profile evidence.
- A fake-serial-first RNode/KISS serial link path, with real serial opening
  behind an explicit feature and environment gate.
- Nostr uplink primitives for NIP-01 event canonicalization, signing,
  messages, filters, bounded fake relay behavior, and gateway executor tests.

## Crates

- `hyf_core`: shared identifiers, node roles, timestamps, and foreign endpoint
  IDs.
- `hyf_wire`: native HYF envelope and payload encoding.
- `hyf_link`: link IDs, link classes, frames, commands, MTU checks, and driver
  traits.
- `hyf_store`: bounded in-memory frame storage for retry and expiry behavior.
- `hyf_router`: pure routing state machine and command emission.
- `hyf_link_loopback`: deterministic in-memory loopback link and driver.
- `hyf_config`: typed gateway configuration and runtime policy checks.
- `hyf_gateway`: gateway core, runtime shell, metrics, and link executors.
- `hyf_link_kiss`: KISS frame encoding and streaming decoding.
- `hyf_link_rnode`: RNode constants, command frames, state, and optional HIL
  readiness helpers.
- `hyf_link_rnode_serial`: fake serial and optional serialport-backed RNode
  gateway link.
- `hyf_link_rns`: opaque RNS packet validation and HYF foreign-packet wrapping.
- `hyf_link_nostr`: Nostr event, key, message, filter, fake relay, and HYF
  envelope carriage primitives.
- `hyf_rns_core`: Reticulum/RNS hashes, destination names, and profile
  constants.
- `hyf_rns_crypto`: Reticulum/RNS identity, signing, HKDF, token, and
  single-packet crypto helpers behind explicit features.
- `hyf_rns_wire`: Reticulum/RNS packet, announce, IFAC, and packet-hash wire
  helpers.
- `hyf_rns_conformance`: fixtures, reports, oracle integration, and profile
  validation tools.

## Validation

Run focused checks from this repository root:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Useful focused checks include:

```bash
cargo test -p hyf_rns_conformance
cargo test -p hyf_gateway --test gateway_smoke
cargo test -p hyf_gateway --test rnode_serial_smoke
cargo test -p hyf_gateway --test nostr_uplink_smoke
cargo build --manifest-path fuzz/Cargo.toml --bins
```

Optional Reticulum oracle tests require `HYF_RETICULUM_PATH` to point at a
compatible Reticulum source checkout. Optional RNode serial tests require
`HYF_HIL_RNODE_PORT` and an explicitly connected device. No default check
requires Python, a live Nostr relay, live Reticulum network state, or real
RNode hardware.

## Boundaries

HYF does not currently implement a full Reticulum router, Reticulum path table,
Reticulum link sessions, LXMF, BitChat, FIPS runtime support, NIP-17, NIP-44,
NIP-65, live Nostr relay runtime, production persistence, firmware, mobile
apps, or RF transmission by default.

Runtime crates do not depend on Python. Compatibility claims should be tied to
tested profiles and recorded evidence, not broad protocol assertions.
