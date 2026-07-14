# Nostr Uplink Verification

Run these checks from the repository root:

```bash
cargo test -p hyf_link_nostr
cargo test -p hyf_gateway --test nostr_uplink_smoke
cargo test -p hyf_rns_conformance --test workspace_metadata
```

These tests validate the fake-relay-first Nostr path:

- bounded event signing and verification;
- relay-owned event storage and deterministic replay;
- typed relay outputs for EVENT, OK, EOSE, CLOSED, NOTICE, and AUTH;
- short-buffer EVENT retry behavior;
- invalid EVENT consume-and-fail-closed behavior;
- public metadata guards for docs, validation paths, and boundary language.

No live relay, public relay account, network service, async daemon, or payload
privacy claim is required for these checks.
