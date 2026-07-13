# ADR 0005: RNode Serial Gateway Path

## Status

Accepted.

## Context

The deterministic gateway foundation uses loopback links only. HYF needs a
first hardware-facing gateway path without turning `hyf_gateway` into an
RNode-specific runtime.

The project already has KISS/RNode primitives and gateway routing/store-forward
primitives.

## Decision

Add a generic synchronous link-driver boundary and implement an RNode/KISS
serial path as a driver-style integration.

The first implementation must be fake-serial-first:

- normal CI uses bounded fake serial I/O;
- real `serialport` support is feature-gated;
- HIL is optional and explicitly gated;
- no RF transmission is performed by default.

The gateway core remains protocol-agnostic. RNode serial behavior lives in
`hyf_link_rnode_serial`.

## Consequences

This gives HYF its first hardware-facing gateway path while preserving clean
boundaries. It does not implement full Reticulum routing, Reticulum link
sessions, LXMF, Nostr, FIPS, BitChat, bridge rooms, firmware, mobile apps, or
production persistence.
