# ADR 0009: Fake Relay And No Public Defaults

## Status

Accepted for Handoff 5.

## Context

Handoff 5 needs deterministic gateway proof without depending on live relay
availability, external network state, account policy, rate limits, or public
relay operator behavior.

## Decision

Make `FakeNostrRelay` the mandatory normal test path. Keep storage and queues
bounded. Provide deterministic replay order, typed rejection outcomes,
duplicate detection, and control-message surfacing.

Do not configure a public relay by default. Live WebSocket support is deferred
unless a later approved feature provides a real compile-checked runtime with
operator-supplied configuration.

## Consequences

Handoff 5 remains repeatable and source-reviewable. Interoperability with live
relays can be explored later without making normal validation depend on the
network.
