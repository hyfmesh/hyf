# FIPS Sidecar Carrier Architecture

The FIPS sidecar carrier gives HYF a deterministic way to move encoded gateway
envelopes through a bounded FIPS-shaped link model.

```text
GatewayCore
  -> GatewayLinkExecutor
     -> FipsGatewayExecutor
        -> FakeFipsSidecar
```

`GatewayCore` remains protocol-agnostic. It sends encoded HYF envelope bytes to
the executor and ingests borrowed `LinkFrameRef` values after the executor
polls the sidecar.

## Components

- `hyf_link_fips::FipsPublicKey` stores raw 32-byte public key material.
- `FipsNodeAddr` is the first 16 bytes of SHA-256 over the public key bytes.
- `FipsIpv6Addr` is `0xfd` plus the first 15 node-address bytes.
- `FipsEndpoint` stores the public key, node address, and IPv6-like address
  after derivation or validation.
- `FipsDatagramRecord` owns bounded payload bytes.
- `FipsDatagramRef` borrows caller-provided output bytes.
- `FakeFipsSidecar` owns bounded peer, inbound, and outbound queues.
- `FipsGatewayExecutor` maps gateway sends and inbound polls to the sidecar.

## Behavior

Peer registration is explicit. Duplicate peer identities, duplicate node
addresses, duplicate IPv6-like addresses, and unknown peers fail closed.

Frames are not fragmented. Payloads must fit the configured MTU and the
compile-time frame limit. Inbound and outbound queues are fixed-size arrays.

Polling copies a pending datagram into caller-owned output. If the output is
too small, the datagram remains pending and can be retried.

Gateway send failures map to typed driver failures. Link-down and queue-full
send failures are recoverable. Unknown peer, invalid endpoint, oversize frame,
and malformed control data are protocol failures.

## Control Fixtures

`control_json` enables bounded parsing of `show_status` response fixtures with
top-level `status` and `data` fields. It does not add live socket I/O.

The default crate build remains usable without JSON parsing.

## Non-Goals

The carrier does not implement a live FIPS daemon, live TUN setup, route
management, FMP, FSP, Noise sessions, bridge rooms, mobile behavior, firmware,
production persistence, or live interoperability claims.
