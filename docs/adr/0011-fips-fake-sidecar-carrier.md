# ADR 0011: FIPS Fake-Sidecar Carrier

## Status

Accepted.

## Context

HYF needs a deterministic FIPS-shaped carrier path for gateway envelopes while
the live FIPS runtime surface remains outside the default build and test
environment.

## Decision

Add `hyf_link_fips` and `hyf_gateway::FipsGatewayExecutor`. The normal test
path uses `FakeFipsSidecar`, bounded peer tables, bounded inbound and outbound
queues, explicit link state, MTU checks, and borrowed frame polling.

Gateway core stays protocol-agnostic and interacts only through
`GatewayLinkExecutor`.

## Consequences

HYF can model and test gateway carriage over a FIPS-shaped sidecar without
running a daemon, opening a TUN interface, changing routes, or depending on a
live mesh.
