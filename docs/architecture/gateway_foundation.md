# Gateway Foundation

The Handoff 3 gateway foundation is a deterministic library runtime for local
testing of HYF envelope routing and store-and-forward behavior. It is designed
to be small enough to review, explicit about ownership, and free of live
transport side effects.

## Components

- `hyf_config` validates gateway, router, store, policy, and link settings.
- `hyf_router` owns routing state and emits commands; it performs no I/O.
- `hyf_store` stores bounded owned encoded frames and returns borrowed views
  into store-owned storage.
- `hyf_link_loopback` provides two deterministic in-memory endpoints for smoke
  tests.
- `hyf_gateway` wires config, router, store, metrics, and loopback links into a
  synchronous runtime shell.

## Frame Ownership

Inbound frames are decoded from caller-owned receive buffers. The store never
keeps references to those buffers. When a frame must be stored, the gateway
encodes or copies the frame into `hyf_store`, which owns bounded bytes until
the record is removed or expired.

During recovery flush, the gateway copies a stored frame into a local fixed
buffer, decodes it, asks the router for a forwarding decision, and removes the
store record only after the command is successfully handled or deliberately
dropped.

## Routing Semantics

Local submissions keep their original hop limit when sent or stored. Inbound
non-local frames consume one hop before forwarding or storage. Inbound
non-local frames with `hop_limit <= 1` are dropped as exhausted. Inbound local
delivery does not decrement the hop limit.

The router owns duplicate suppression and link-state decisions. The gateway
commits a message as seen only after successful send, store, or local delivery
execution.

## Runtime API

The gateway exposes synchronous methods for local tests:

- `submit(envelope)` for local submissions.
- `ingest_link_frame(frame)` for inbound link frames.
- `poll_loopback(link_id, output)` for deterministic loopback receive and
  ingest.
- `tick(now)` for deterministic time advancement and expiry.
- `set_link_up(link_id, up)` for link-state tests.

The runtime records delivery metadata rather than retaining borrowed payload
references.

## Non-Goals

This foundation does not implement live RNS/RNode I/O, async transports,
Reticulum path tables, Reticulum link sessions, firmware, mobile bindings, or
production persistence.
