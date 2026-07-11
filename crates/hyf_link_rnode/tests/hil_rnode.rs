#![cfg(feature = "hil_std")]

use hyf_link_rnode::{
    RNODE_HIL_ARTIFACT_ROOT, RNODE_HIL_DEFAULT_BAUD, RNODE_HIL_MANIFEST_SCHEMA, RNodeHilCheck,
    RNodeHilCheckStatus, RNodeHilManifest, RNodeHilReadinessError, hil_manifest_artifact_path,
    probe_rnode_readiness_serial, write_hil_manifest_json,
};

#[test]
#[ignore]
fn hil_rnode_environment_gate_is_non_transmitting_by_default()
-> Result<(), Box<dyn std::error::Error>> {
    let Ok(port) = std::env::var("HYF_HIL_RNODE_PORT") else {
        return Ok(());
    };
    assert!(!port.is_empty());

    let allow_rf_tx = parse_optional_bool("HYF_HIL_ALLOW_RF_TX")?;
    if allow_rf_tx {
        return Err(RNodeHilReadinessError::RfTransmissionRequested.into());
    }
    let baud = parse_optional_baud("HYF_HIL_RNODE_BAUD")?;
    let readiness = probe_rnode_readiness_serial(&port, baud)?;
    let run_id = std::env::var("HYF_HIL_RUN_ID").unwrap_or_else(|_| "manual-rnode-hil".to_owned());
    let generated_at =
        std::env::var("HYF_HIL_GENERATED_AT").unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    let hardware_model = std::env::var("HYF_HIL_RNODE_MODEL").ok();
    let firmware_version = readiness
        .firmware_version
        .map(|version| format!("{}.{}", version.major, version.minor))
        .or_else(|| std::env::var("HYF_HIL_RNODE_FIRMWARE").ok());
    let check = [RNodeHilCheck::ready(RNodeHilCheckStatus::Passed)
        .with_detail("non-transmitting readiness probe passed")];
    let manifest = RNodeHilManifest {
        run_id: &run_id,
        generated_at: &generated_at,
        port: &port,
        baud,
        hardware_model: hardware_model.as_deref(),
        firmware_version: firmware_version.as_deref(),
        allow_rf_tx,
        transmission_performed: false,
        checks: &check,
    };
    let mut manifest_json = Vec::new();

    write_hil_manifest_json(&manifest, &mut manifest_json)?;

    assert_eq!(RNODE_HIL_MANIFEST_SCHEMA, "hyf.rnode.hil.v1");
    assert!(!manifest_json.is_empty());

    let artifact_path = match std::env::var("HYF_HIL_ARTIFACT_DIR") {
        Ok(output_dir) => hil_manifest_artifact_path(output_dir, &generated_at)?,
        Err(std::env::VarError::NotPresent) => {
            let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            hil_manifest_artifact_path(workspace_root.join(RNODE_HIL_ARTIFACT_ROOT), &generated_at)?
        }
        Err(error) => return Err(error.into()),
    };
    if let Some(parent) = artifact_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(artifact_path, manifest_json)?;

    Ok(())
}

fn parse_optional_bool(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => match value.as_str() {
            "0" | "false" | "False" | "FALSE" => Ok(false),
            "1" | "true" | "True" | "TRUE" => Ok(true),
            _ => Err(format!("{name} must be 0, 1, false, or true").into()),
        },
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn parse_optional_baud(name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(RNODE_HIL_DEFAULT_BAUD),
        Err(error) => Err(error.into()),
    }
}
