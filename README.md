# hyf

`hyf` is an experimental Rust workspace for deterministic, reviewable mesh
networking foundations. The current codebase focuses on small `no_std`-capable
core crates, Reticulum/RNS profile conformance crates, and a local in-memory
gateway foundation used to exercise store-and-forward behavior without live
radio or network I/O.

## Current Status

The project is pre-release. The implemented surfaces are intended for source
review, conformance testing, and continued protocol development.

- Handoff 1 established native HYF core, wire, crypto, link, store, and routing
  foundations.
- Handoff 2 added Reticulum/RNS profile conformance crates and deterministic
  vector tests.
- Handoff 3 adds a gateway library foundation with typed config,
  deterministic loopback links, owned frame storage, router-owned forwarding
  decisions, inbound frame ingestion, loopback polling, and local smoke tests.

The Handoff 3 gateway is not a live RNS/RNode runtime and does not implement a
production transport service.

## Workspace

- `crates/hyf_core`: shared identifiers and time types.
- `crates/hyf_wire`: native HYF envelope encoding and decoding.
- `crates/hyf_link`: link identifiers, frames, commands, and MTU checks.
- `crates/hyf_store`: bounded owned encoded-frame store.
- `crates/hyf_router`: pure routing state machine and command emission.
- `crates/hyf_link_loopback`: deterministic in-memory loopback link.
- `crates/hyf_config`: typed gateway configuration.
- `crates/hyf_gateway`: gateway runtime shell for local loopback testing.
- `crates/hyf_rns_*` and `crates/hyf_rns_conformance`: Reticulum/RNS profile
  compatibility and evidence tooling.

## Non-Goals For Handoff 3

Handoff 3 does not add FIPS, Nostr, LXMF, BitChat, bridge rooms, live
Reticulum path tables, Reticulum link sessions, live RNode serial runtime,
firmware, mobile applications, production databases, or public workflow files.

FIPS is documented only as a future gateway-side sidecar or TUN accommodation.
It is not compiled into the runtime and is not a Cargo dependency.

## Verification

Run the Handoff 3 verification script from the repository root:

```bash
scripts/verify_handoff3.sh
```

The script runs formatting, workspace clippy, workspace tests, no-default
checks for the firmware-capable crates, gateway smoke tests, Reticulum/RNS
conformance regression tests, benchmark build checks, and fuzz target builds.
Optional Python oracle checks run only when `HYF_RETICULUM_PATH` is configured.
