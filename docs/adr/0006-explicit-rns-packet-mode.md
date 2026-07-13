# ADR 0006: Explicit RNS Packet Mode

## Status

Accepted for Handoff 4.

## Context

RNode KISS `CMD_DATA` frames can carry different application-level payloads. In
Handoff 4, they may carry native HYF envelope bytes or raw opaque RNS packet
bytes.

Autodetection is unsafe because a raw RNS packet could be misclassified as
malformed HYF or vice versa, leading to ambiguous behavior and future security
bugs.

## Decision

Use explicit data modes:

```rust
RNodeDataMode::HyfEnvelope
RNodeDataMode::RawRnsPacket
```

HYF envelope mode treats KISS `CMD_DATA` payloads as encoded HYF envelopes.

Raw RNS packet mode treats KISS `CMD_DATA` payloads as raw RNS packets,
validates them using `hyf_link_rns`, and wraps them into
`PayloadKind::ForeignRnsPacket` using explicit `RnsWrapParams`.

There is no autodetection and no hidden default wrapping parameters.

## Consequences

Callers must choose the mode up front. RawRNS gateway polling requires explicit
wrap params. This keeps the API honest and prevents accidental protocol
confusion.
