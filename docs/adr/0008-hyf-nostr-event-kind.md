# ADR 0008: HYF Nostr Event Kind

## Status

Accepted.

## Context

HYF envelope carriage over Nostr needs a distinct event kind so relays and
clients can filter HYF gateway traffic without overloading social note kinds or
other application protocols.

## Decision

Use:

```rust
pub const HYF_NOSTR_ENVELOPE_KIND: u16 = 9775;
```

The event content is lowercase canonical hex of encoded HYF envelope bytes.

## Consequences

The kind is experimental to HYF and is expected to be stored like a regular
NIP-01 event. It does not imply Nostr chat behavior, direct messaging,
encryption, relay discovery, or public relay defaults.
