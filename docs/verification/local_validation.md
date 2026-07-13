# Local Validation

Run from the repository root:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Expected Required Checks

Broad local validation should include:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- no-default checks for firmware-capable crates
- gateway tests
- `gateway_smoke`
- `rnode_serial_smoke`
- `hyf_link_rns` tests
- `hyf_link_rnode_serial` tests
- Reticulum/RNS conformance regression
- benchmark build checks
- fuzz target build
- serialport runtime check/test
- cargo tree duplicate/feature audits

## Optional Checks

If `HYF_RETICULUM_PATH` is unset, Python oracle checks may be skipped.

If `HYF_HIL_RNODE_PORT` is unset, HIL may report `skipped_no_port`.

A skipped optional lane is acceptable when reported.

## HIL Wording

The HIL lane is a non-transmitting serial open gate. Do not describe it as RF
validation or full hardware validation unless future tests and evidence prove
that behavior.
