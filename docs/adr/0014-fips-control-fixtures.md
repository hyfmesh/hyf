# ADR 0014: FIPS Control Fixtures

## Status

Accepted.

## Context

Status parsing is useful for testing sidecar readiness and address consistency,
but live control socket I/O would expand scope beyond deterministic local
validation.

## Decision

Provide a bounded `show_status` response parser behind the `control_json`
feature in `hyf_link_fips`.

The parser accepts fixture envelopes with top-level `status` and `data` fields,
requires `status == "ok"`, validates node and IPv6-like addresses, and ignores
unknown fields. It does not open sockets or perform live requests.

For `tun_state`, the parser recognizes `disabled`, `configured`, `active`, and
`failed`. Other strings are preserved as the typed `Unknown` state.

## Consequences

HYF can test control status shape and failure handling without adding live
control transport behavior to the default build.
