#![cfg(feature = "hil_std")]

use hyf_link_rnode::RNODE_HIL_MANIFEST_SCHEMA;

#[test]
#[ignore]
fn hil_rnode_environment_gate_is_non_transmitting_by_default() {
    let Ok(port) = std::env::var("HYF_HIL_RNODE_PORT") else {
        return;
    };
    assert!(!port.is_empty());

    let allow_rf_tx = std::env::var("HYF_HIL_ALLOW_RF_TX").unwrap_or_else(|_| "0".to_owned());
    assert!(allow_rf_tx == "0" || allow_rf_tx == "1");
    assert_eq!(RNODE_HIL_MANIFEST_SCHEMA, "hyf.rnode.hil.v1");
}
