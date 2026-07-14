# FIPS Sidecar Carrier

HYF includes a small, fake-sidecar-first FIPS carrier surface for gateway
envelope tests.

The implemented surface is deliberately narrow:

- `hyf_link_fips` derives FIPS-style node and IPv6-like addresses from raw
  32-byte public keys.
- `FakeFipsSidecar` stores peers and datagrams in bounded memory.
- `hyf_gateway::FipsGatewayExecutor` sends and polls encoded HYF envelope bytes
  through the fake sidecar.
- optional `control_json` parsing accepts bounded status fixtures only.

This is not a live FIPS runtime. It does not open a TUN interface, talk to a
daemon, configure routes, join a mesh, implement FMP/FSP, provide Noise
sessions, or claim live interoperability.

## Current Guarantees

- The FIPS carrier is first-party Rust code.
- Normal validation uses deterministic fake-sidecar tests.
- No external FIPS crate, daemon, TUN crate, Tokio runtime, rtnetlink,
  nftables, or rustables dependency is required.
- Gateway core remains protocol-agnostic.
- Default checks do not require root privileges, network services, or hardware.

## Integration Shape

Future live work should stay behind the gateway executor boundary. A live
sidecar client can implement the same send and poll responsibilities without
making FIPS a dependency of `hyf_wire`, `hyf_router`, `hyf_store`, or the
Reticulum/RNS conformance crates.

Until live evidence exists, public claims should stay at the fake-sidecar
carrier level.
