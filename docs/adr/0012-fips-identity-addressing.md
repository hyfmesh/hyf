# ADR 0012: FIPS Identity Addressing

## Status

Accepted.

## Context

The FIPS carrier needs stable endpoint identifiers that are distinct from HYF
node IDs, Reticulum/RNS destination hashes, and Nostr user identities.

## Decision

Use raw 32-byte public key material as `FipsPublicKey`.

Derive:

```text
FipsNodeAddr = sha256(public_key_bytes)[0..16]
FipsIpv6Addr = [0xfd] + FipsNodeAddr[0..15]
```

`FipsEndpoint` stores all three values after canonical derivation or explicit
validation. NIP-19 and `npub` parsing are not part of this carrier surface.

## Consequences

The address model is deterministic and testable without live networking. HYF
does not collapse FIPS identities into native HYF node IDs or Reticulum/RNS
destination identifiers.
