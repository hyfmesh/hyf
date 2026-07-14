# Nostr Uplink Verification

This is the dedicated verification guide for the fake-relay-first Nostr uplink
surface. Run commands from the repository root.

No live relay, public relay account, network service, async daemon, or payload
privacy claim is required for these checks.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

cargo check -p hyf_link_nostr --no-default-features
cargo test -p hyf_link_nostr
cargo test -p hyf_gateway --test nostr_uplink_smoke

cargo test -p hyf_rns_conformance
cargo test -p hyf_gateway --test gateway_smoke
cargo test -p hyf_gateway --test rnode_serial_smoke
cargo build --manifest-path fuzz/Cargo.toml --bins

cargo tree --duplicates
cargo tree -p hyf_link_nostr -e features
cargo tree -p hyf_gateway -e features
```

These checks validate the fake-relay-first Nostr path:

- bounded event signing and verification;
- relay-owned event storage and deterministic replay;
- typed relay outputs for EVENT, OK, EOSE, CLOSED, NOTICE, and AUTH;
- short-buffer EVENT retry behavior;
- invalid EVENT consume-and-fail-closed behavior;
- public metadata guards for docs, validation paths, and boundary language.

## Optional Lanes

Optional Reticulum oracle checks may use `HYF_RETICULUM_PATH` when a compatible
Reticulum source checkout is explicitly configured.

Optional RNode serial checks may use `HYF_HIL_RNODE_PORT` when a real device is
explicitly connected.

When optional environment is absent, report that lane as skipped. A skipped
optional lane is not Reticulum live-network validation or hardware validation.

## Pass Criteria

Nostr uplink verification passes when all required commands complete
successfully and no default check requires:

- a live Nostr relay;
- a public relay URL or account;
- a WebSocket runtime;
- NIP-17, NIP-44, or NIP-65;
- LXMF, BitChat, bridge rooms, or mobile apps;
- FIPS runtime support;
- production persistence;
- firmware;
- a runtime Python dependency;
- real RNode hardware.

## Fail Criteria

Nostr uplink verification fails if:

- any required command fails;
- production code reintroduces leaked static Nostr event buffers;
- relay outputs are silently discarded instead of surfaced;
- short-buffer EVENT retry behavior consumes the event;
- invalid EVENT output is not consumed and failed closed;
- live relay defaults are added;
- public validation scripts or workflow definitions are added;
- broad compatibility claims are added without evidence.

## Evidence

A final report should include:

- commit SHA;
- files changed;
- commands run;
- command results;
- optional lanes skipped and why;
- any commands not run and why.
