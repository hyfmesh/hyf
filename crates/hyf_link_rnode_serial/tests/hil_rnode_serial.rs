#![cfg(feature = "serialport_runtime")]

use hyf_link_rnode::RNODE_HIL_DEFAULT_BAUD;
use hyf_link_rnode_serial::{RNodeSerialError, SerialPortIo};

#[test]
#[ignore = "requires HYF_HIL_RNODE_PORT and an explicitly connected RNode"]
fn hil_rnode_serial_open_gate_is_explicit_and_non_transmitting() -> Result<(), RNodeSerialError> {
    let Ok(port) = std::env::var("HYF_HIL_RNODE_PORT") else {
        eprintln!("status=skipped_no_port");
        return Ok(());
    };

    if port.trim().is_empty() {
        eprintln!("status=skipped_no_port");
        return Ok(());
    }

    let _io = SerialPortIo::open(&port, RNODE_HIL_DEFAULT_BAUD, 250)?;
    eprintln!("status=opened_non_transmitting");
    Ok(())
}
