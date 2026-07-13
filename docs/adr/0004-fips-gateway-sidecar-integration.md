# ADR 0004: FIPS Gateway-Side Accommodation

## Status

Accepted as future-facing documentation only. No FIPS runtime implementation is
included.

## Context

The HYF data model includes foreign endpoint identifiers that can represent
FIPS-style addresses. That does not mean the gateway should directly depend on
or implement FIPS during the gateway foundation phase.

## Decision

Treat FIPS as a possible future gateway-side accommodation, likely through a
sidecar or TUN-style boundary. Keep FIPS out of the core crates, router, store,
wire format implementation, Reticulum/RNS conformance crates, and current
gateway runtime.

## Consequences

The current code can discuss how FIPS might fit later without carrying a FIPS
dependency or making FIPS behavior claims. Any future FIPS work needs its own
specification, tests, security review, and compatibility evidence.
