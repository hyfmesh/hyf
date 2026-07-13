# Nostr Uplink

The Nostr uplink path is fake-relay-first for HYF gateway tests. It uses a
minimal NIP-01 event subset to carry encoded HYF envelopes over signed Nostr
events without adding a social client, direct-message system, relay discovery,
or live public relay default.

## Components

- `hyf_link_nostr`: Nostr event, key, signature, filter, message, fake relay,
  content-codec, and gateway-executor crate.
- `hyf_gateway::GatewayLinkExecutor`: outbound gateway send boundary used by
  the Nostr executor.
- `hyf_link::LinkFrameRef`: inbound verified relay events are decoded back into
  gateway frames.
- `FakeNostrRelay`: bounded deterministic relay used by normal tests.

`GatewayCore` remains Nostr-agnostic. It sends encoded HYF envelope bytes
through `GatewayLinkExecutor` and ingests decoded `LinkFrameRef` values. Nostr
event and relay details stay in `hyf_link_nostr`.

## Event Shape

HYF envelope events use:

```text
HYF_NOSTR_ENVELOPE_KIND = 9775
```

The event content is lowercase canonical hex of encoded HYF envelope bytes.
Runtime decoders reject uppercase hex, whitespace, odd length input, invalid
characters, and oversized content.

The event ID is the NIP-01 SHA-256 hash of canonical serialized event data.
Events are signed and verified with Schnorr signatures over secp256k1.

## Fake Relay First

Normal tests use `FakeNostrRelay`. It must provide bounded storage,
deterministic replay order, duplicate detection, typed publish outcomes,
subscription filters, EOSE, and surfaced NOTICE, CLOSED, and AUTH messages.

No default test may require a live relay or network service.

## Gateway Behavior

Outbound gateway sends produce signed Nostr events and publish them to the fake
relay. Inbound relay EVENT messages are verified, decoded into HYF envelope
bytes, and returned as `LinkFrameRef` for normal gateway ingestion.

Relay rejections must be typed. Temporary failures such as rate limiting can be
recoverable send failures; invalid events must fail closed. Duplicate OK
responses are accepted duplicate outcomes, not fresh publishes.

## Non-Goals

The Nostr uplink path does not implement NIP-17, NIP-44, NIP-65, Nostr
chat/social client behavior, public relay defaults, async daemon runtime,
production persistence, FIPS, LXMF, BitChat, bridge rooms, mobile apps, or
firmware.
