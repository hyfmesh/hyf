# ADR 0013: No FIPS Runtime Dependency

## Status

Accepted.

## Context

Live FIPS integration may eventually require daemon, TUN, route-management, or
transport-specific crates. Those dependencies would change the build surface
and operational assumptions for a pre-release Rust workspace.

## Decision

Keep the current FIPS carrier first-party and fake-sidecar-first. Do not add a
live FIPS daemon dependency, TUN crate, route-management crate, async runtime,
FMP/FSP stack, or Noise session implementation to the default workspace.

Do not add a live FIPS daemon dependency to default validation.

All normal validation must run without root privileges, network services, or
hardware.

## Consequences

The public crate graph remains small and reviewable. Future live work can add
an explicit sidecar client behind a separate feature and verification story
without changing current default behavior.
