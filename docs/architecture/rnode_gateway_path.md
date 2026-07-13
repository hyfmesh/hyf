# RNode Gateway Path

Handoff 4 adds the first hardware-facing HYF gateway path. It builds on the
Handoff 3 gateway foundation and the Handoff 2 KISS/RNode primitives.

## Components

- `hyf_link::LinkDriver`: generic synchronous link-driver boundary.
- `hyf_link_loopback::LoopbackDriver`: in-memory driver used for deterministic
  tests.
- `hyf_link_rns`: validates opaque RNS packets and wraps/unwraps
  `PayloadKind::ForeignRnsPacket` envelopes.
- `hyf_link_rnode_serial`: fake-serial-first RNode/KISS gateway driver.
- `hyf_gateway::GatewayCore`: protocol-agnostic router/store/metrics core.
- `hyf_gateway::GatewayLinkExecutor`: executor boundary for link sends.

## Data Modes

`RNodeDataMode::HyfEnvelope` treats KISS `CMD_DATA` payloads as encoded HYF
envelopes.

`RNodeDataMode::RawRnsPacket` treats KISS `CMD_DATA` payloads as raw opaque RNS
packets. The caller must provide `RnsWrapParams` to wrap those bytes into a HYF
envelope. The implementation must not autodetect HYF versus RNS.

## Fake Serial First

Normal tests use `FakeSerial`, not a host serial device. The fake serial path
keeps Handoff 4 repeatable in CI and local review.

Real serial support is feature-gated behind `serialport_runtime`.

## Optional HIL

The current HIL lane is a non-transmitting serial open gate. It may prove that a
port can be opened, but it is not RF validation and not a full RNode hardware
acceptance test.

## Non-Goals

Handoff 4 does not implement full Reticulum pathing, Reticulum link sessions,
resources, channels, LXMF, Nostr, FIPS, BitChat, bridge rooms, firmware, mobile
apps, or production persistence.
