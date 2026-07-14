# ADR 0004: FIPS Gateway-Side Accommodation

## Status

Accepted. Refined by ADR 0011, ADR 0012, ADR 0013, and ADR 0014.

## Context

HYF can carry foreign endpoint identifiers without making every foreign
network a core dependency. FIPS-style addressing is useful to model at the
gateway edge, but it should not change the HYF wire format, router, store, or
Reticulum/RNS conformance boundaries.

## Decision

Treat FIPS as a gateway-side carrier surface. Keep the core crates independent
from live FIPS runtime dependencies. Model and test the boundary through
first-party Rust types and deterministic fake-sidecar behavior.

## Consequences

HYF can validate gateway envelope carriage through a FIPS-shaped sidecar model
without claiming live FIPS routing. Live sidecar clients, TUN setup, route
management, FMP, FSP, and Noise sessions require separate design and evidence.
