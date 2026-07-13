# ADR 0010: NIP-01 Canonicalization

## Status

Accepted.

## Context

Nostr event IDs are SHA-256 hashes of canonical serialized event data. Any
serialization mismatch changes the event ID and invalidates signatures.

## Decision

Implement explicit NIP-01 canonical serialization for event ID input:

```text
[0,"<pubkey>",<created_at>,<kind>,<tags>,"<content>"]
```

The serializer preserves tag order, emits no unnecessary whitespace, uses
UTF-8, and escapes quote, backslash, and required control characters according
to the NIP-01 event ID rules.

## Consequences

Event ID and signature verification do not depend on pretty JSON output or
unchecked generic serialization behavior. The implementation must pass known
canonicalization and signature vectors before claiming NIP-01 compatibility.
