# FIPS Sidecar Carrier Verification

This is the dedicated verification guide for the fake-sidecar-first FIPS
carrier surface. Run commands from the repository root.

No live FIPS daemon, TUN interface, route manager, root privilege, network
namespace, FMP/FSP stack, Noise session, or hardware is required for these
checks.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

cargo check -p hyf_link_fips --no-default-features
cargo test -p hyf_link_fips
cargo test -p hyf_link_fips --features control_json control
cargo test -p hyf_gateway --test fips_sidecar_smoke

cargo test -p hyf_gateway --test nostr_uplink_smoke
cargo test -p hyf_gateway --test rnode_serial_smoke
cargo test -p hyf_gateway --test gateway_smoke
cargo test -p hyf_rns_conformance
cargo build --manifest-path fuzz/Cargo.toml --bins

cargo tree --duplicates
cargo tree -p hyf_link_fips -e features
cargo tree -p hyf_link_fips --features control_json -e features
cargo tree -p hyf_gateway -e features
```

These checks validate:

- raw public-key to node-address derivation;
- IPv6-like address derivation;
- endpoint validation;
- bounded datagram storage;
- peer registration and unknown-peer rejection;
- link-down, MTU, and queue-full errors;
- short-output retry behavior;
- fixture-only control status parsing;
- gateway send and inbound poll behavior;
- store-forward flush and retention behavior;
- public metadata guards for docs, validation paths, and dependency boundaries.

## Pass Criteria

FIPS sidecar carrier verification passes when all required commands complete
successfully and no default check requires:

- a live FIPS daemon;
- a live TUN interface;
- root privileges;
- network namespace setup;
- route table changes;
- FMP, FSP, or Noise session support;
- production persistence;
- firmware;
- mobile apps;
- real hardware;
- a runtime Python dependency.

## Fail Criteria

Verification fails if:

- any required command fails;
- `hyf_link_fips --no-default-features` stops building;
- JSON parsing becomes part of the default feature set;
- a live FIPS, TUN, async runtime, or route-management dependency is added;
- queue-full or link-down send failures stop being recoverable;
- unknown peer or malformed control data stops failing closed;
- short-output polling consumes the pending datagram;
- public validation scripts or workflow definitions are added;
- broad live interoperability claims are added without evidence.

## Evidence

A final report should include:

- commit SHA;
- files changed;
- commands run;
- command results;
- any optional lanes skipped and why;
- any commands not run and why.
