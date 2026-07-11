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

require_clean_workflow_boundary

run cargo fmt --check
run cargo clippy --workspace --all-targets -- -D warnings
run cargo test --workspace

for crate in \
    hyf_core \
    hyf_crypto \
    hyf_wire \
    hyf_link \
    hyf_store \
    hyf_router \
    hyf_link_loopback \
    hyf_config \
    hyf_link_kiss \
    hyf_link_rnode \
    hyf_link_rns \
    hyf_link_rnode_serial \
    hyf_rns_core \
    hyf_rns_crypto \
    hyf_rns_wire
do
    run cargo check -p "$crate" --no-default-features
done

run cargo test -p hyf_gateway
run cargo test -p hyf_gateway --test gateway_smoke
run cargo test -p hyf_gateway --test rnode_serial_smoke
run cargo test -p hyf_link_rns
run cargo test -p hyf_link_rnode_serial
run cargo test -p hyf_rns_conformance

run cargo bench -p hyf_rns_conformance --bench profile0 --no-run
run cargo build --manifest-path fuzz/Cargo.toml --bins

run cargo check -p hyf_link_rnode_serial --features serialport_runtime
run cargo test -p hyf_link_rnode_serial --features serialport_runtime
run env -u HYF_HIL_RNODE_PORT cargo test -p hyf_link_rnode_serial --features serialport_runtime -- --ignored --nocapture

if [ -n "${HYF_HIL_RNODE_PORT:-}" ]; then
    run cargo test -p hyf_link_rnode_serial --features serialport_runtime -- --ignored --nocapture
else
    echo "HYF_HIL_RNODE_PORT is unset; status=skipped_no_port" >&2
fi

if [ -n "${HYF_RETICULUM_PATH:-}" ]; then
    run cargo test -p hyf_rns_conformance --features python_oracle
else
    echo "HYF_RETICULUM_PATH is unset; status=skipped_python_oracle_no_path" >&2
fi

run cargo tree --duplicates
run cargo tree -p hyf_link_rnode_serial -e features
run cargo tree -p hyf_link_rns -e features
