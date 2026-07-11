# ADR 0003: Gateway Foundation

## Status

Accepted for the Handoff 3 gateway foundation.

## Context

The workspace needs a testable gateway foundation before adding live network
or hardware I/O. The foundation must exercise routing, store-and-forward,
inbound frame ingestion, expiry, duplicate suppression, and metrics without
introducing async runtime machinery or transport-specific dependencies.

## Decision

Implement the gateway as a synchronous library runtime over existing small
crates:

- `hyf_router` remains pure and emits commands.
- `hyf_store` owns bounded encoded frames.
- `hyf_link_loopback` provides deterministic local link behavior.
- `hyf_gateway` executes router commands and owns metrics.

The gateway accepts local submissions and borrowed inbound link frames for the
duration of each call. It stores only owned encoded frame bytes and delivery
metadata.

## Consequences

This keeps the gateway easy to unit test and source review. It also means
Handoff 3 does not provide a daemon, live transport, RNode serial runtime,
Reticulum path table, or production persistence.
