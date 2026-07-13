# ADR 0007: Nostr Uplink

## Status

Accepted.

## Context

HYF needs an internet-relay uplink path after the deterministic gateway and
fake-serial-first RNode/KISS paths. Nostr provides a simple signed event and
relay protocol that can carry opaque HYF envelope bytes while remaining
separate from Reticulum/RNS and hardware-facing code.

## Decision

Add `hyf_link_nostr` as a dedicated link crate. Implement a minimal NIP-01
event subset, signed HYF envelope events, bounded fake relay behavior, and a
gateway executor that integrates through `GatewayLinkExecutor`.

The normal implementation and tests are fake-relay-first. No live relay is a
default dependency.

## Consequences

HYF gains a deterministic Nostr uplink test path without making gateway core
Nostr-specific. Full Nostr client behavior, public relay defaults, direct
messages, encryption, relay discovery, async daemon runtime, and production
persistence remain out of scope.
