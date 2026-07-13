# hyf

`hyf` is an experimental Rust workspace for deterministic, reviewable mesh
networking foundations. The current codebase focuses on small `no_std`-capable
core crates, Reticulum/RNS profile conformance crates, a local gateway
foundation, and a fake-serial-first RNode/KISS gateway path.

## Current Status

The project is pre-release. The implemented surfaces are intended for source
review, conformance testing, and continued protocol development.

- Handoff 1 established the initial HYF/RNS packet and announce foundation.
- Handoff 2 added Reticulum/RNS crypto, IFAC, KISS, RNode primitives, and
  conformance/evidence tooling.
- Handoff 3 added the native HYF gateway foundation: typed config,
  deterministic loopback links, owned frame storage, router-owned forwarding
  decisions, inbound frame ingestion, loopback polling, and local smoke tests.
- Handoff 4 adds the first hardware-facing gateway path: a generic link-driver
  boundary, opaque RNS packet wrapping, a fake-serial-first RNode/KISS serial
  adapter, gateway core/executor separation, and fake RNode serial smoke tests.

Handoff 4 is not a full Reticulum router and does not implement a
production transport service.

## Workspace

- `crates/hyf_core`: shared identifiers, time types, and foreign endpoint IDs.
- `crates/hyf_wire`: native HYF envelope encoding and decoding.
- `crates/hyf_link`: link identifiers, frames, commands, MTU checks, and
  synchronous link-driver contracts.
- `crates/hyf_store`: bounded owned encoded-frame store.
- `crates/hyf_router`: pure routing state machine and command emission.
- `crates/hyf_link_loopback`: deterministic in-memory loopback link and driver.
- `crates/hyf_config`: typed gateway configuration.
- `crates/hyf_gateway`: gateway core/runtime shell for local and fake-driver
  testing.
- `crates/hyf_link_rns`: opaque RNS packet validation and `ForeignRnsPacket`
  wrapping.
- `crates/hyf_link_rnode_serial`: fake-serial-first RNode/KISS gateway link.
- `crates/hyf_link_kiss` and `crates/hyf_link_rnode`: KISS and RNode protocol
  primitives.
- `crates/hyf_rns_*` and `crates/hyf_rns_conformance`: Reticulum/RNS profile
  compatibility and evidence tooling.

## Non-Goals For Handoff 4

Handoff 4 does not add FIPS, Nostr, LXMF, BitChat, bridge rooms, full Reticulum
path tables, Reticulum link sessions, resources, channels, firmware, mobile
applications, production databases, async gateway daemons, or public workflow
files.

FIPS is documented only as a future gateway-side sidecar or TUN accommodation.
It is not compiled into the runtime and is not a Cargo dependency.

Raw RNS packet support is opaque packet carriage only. It does not imply full
Reticulum routing compatibility.

## Verification

Run the Handoff 4 verification script from the repository root:

```bash
scripts/verify_handoff4.sh
```

The script runs formatting, workspace clippy, workspace tests, no-default checks
for the firmware-capable crates, gateway smoke tests, fake RNode serial smoke
tests, Reticulum/RNS conformance regression tests, benchmark build checks, fuzz
target builds, and feature checks for optional serial runtime support.

Optional Python oracle checks run only when `HYF_RETICULUM_PATH` is configured.
Optional RNode serial open-gate checks run only when `HYF_HIL_RNODE_PORT` is
configured. The HIL gate is non-transmitting and should not be interpreted as
full hardware validation.
