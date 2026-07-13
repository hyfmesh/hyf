# ADR 0005: RNode Serial Gateway Path

## Status

Accepted for Handoff 4.

## Context

Handoff 3 created a deterministic gateway foundation using loopback links only.
Handoff 4 must add the first hardware-facing gateway path without turning
`hyf_gateway` into an RNode-specific runtime.

The project already has KISS/RNode primitives from Handoff 2 and gateway
routing/store-forward primitives from Handoff 3.

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
