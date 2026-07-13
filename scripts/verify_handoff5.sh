#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cd "$repo_root"

run() {
    printf '+'
    for arg in "$@"; do
        printf ' %s' "$arg"
    done
    printf '\n'
    "$@"
}

require_clean_workflow_boundary() {
    if [ -e .act ]; then
        echo "public workflow-like files are not allowed under .act" >&2
        exit 1
    fi

    if [ -e .github/workflows ]; then
        echo "public workflow files are not allowed under .github/workflows" >&2
        exit 1
    fi

    tracked_workflows=$(git ls-files .act .github/workflows)
    if [ -n "$tracked_workflows" ]; then
        echo "public workflow-like files are not allowed under hyf:" >&2
        printf '%s\n' "$tracked_workflows" >&2
        exit 1
    fi
}

require_websocket_deferral() {
    deferred_manifest_matches=$(
        grep -n -E 'websocket_runtime|nostr-sdk|tokio-tungstenite' \
            Cargo.toml \
            crates/hyf_link_nostr/Cargo.toml \
            crates/hyf_gateway/Cargo.toml || true
    )
    if [ -n "$deferred_manifest_matches" ]; then
        echo "Handoff 5 WebSocket runtime remains deferred; remove placeholder features/deps:" >&2
        printf '%s\n' "$deferred_manifest_matches" >&2
        exit 1
    fi

    public_relay_defaults=$(
        git grep -n 'wss://' -- \
            Cargo.toml \
            crates/hyf_link_nostr/Cargo.toml \
            crates/hyf_gateway/Cargo.toml \
            crates/hyf_link_nostr/src \
            crates/hyf_gateway/src |
            grep -v 'wss://relay.example' || true
    )
    if [ -n "$public_relay_defaults" ]; then
        echo "public Nostr relay defaults are not allowed:" >&2
        printf '%s\n' "$public_relay_defaults" >&2
        exit 1
    fi
}

require_clean_workflow_boundary
require_websocket_deferral

run scripts/verify_handoff4.sh

run cargo fmt --check
run cargo clippy -p hyf_link_nostr -p hyf_gateway --all-targets -- -D warnings
run cargo test --workspace

run cargo check -p hyf_link_nostr --no-default-features
run cargo check -p hyf_gateway --no-default-features

run cargo test -p hyf_link_nostr
run cargo test -p hyf_gateway
run cargo test -p hyf_gateway --test nostr_uplink_smoke

run cargo tree --duplicates
run cargo tree -p hyf_link_nostr -e features
run cargo tree -p hyf_gateway -e features
