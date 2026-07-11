# FIPS Accommodation

FIPS is a future integration target, not a Handoff 3 implementation.

The current model can represent foreign endpoints, including 16-byte FIPS
`node_addr` values and 32-byte identities such as Nostr public-key-derived
identifiers. That representation is only an address model. It does not add a
FIPS transport, protocol adapter, dependency, sidecar process, or runtime path.

## Intended Future Shape

If FIPS support is added later, the expected shape is a gateway-side
accommodation such as a sidecar or TUN-style boundary. That boundary should
translate between a future FIPS-facing adapter and the existing HYF gateway
runtime without making FIPS a dependency of the core wire, router, store, or
RNS conformance crates.

## Current Guarantees

- No FIPS crate or dependency is compiled into Handoff 3.
- No FIPS adapter is implemented.
- No FIPS behavior is claimed by the gateway smoke tests.
- FIPS does not replace Reticulum/RNS compatibility work.
- FIPS does not alter RNode or Reticulum non-goals.
