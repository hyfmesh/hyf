use crate::{FipsIpv6Addr, FipsNodeAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FipsTunState {
    Unknown,
    Disabled,
    Configured,
    Active,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FipsStatus {
    pub node_addr: FipsNodeAddr,
    pub ipv6_addr: FipsIpv6Addr,
    pub tun_state: FipsTunState,
    pub effective_ipv6_mtu: Option<u16>,
    pub peer_count: Option<u16>,
}

impl FipsTunState {
    pub const fn from_control_str(value: &str) -> Self {
        match value.as_bytes() {
            b"disabled" => Self::Disabled,
            b"configured" => Self::Configured,
            b"active" => Self::Active,
            b"failed" => Self::Failed,
            _ => Self::Unknown,
        }
    }
}

#[cfg(feature = "control_json")]
mod json {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use serde_json::{Map, Value};

    use super::{FipsStatus, FipsTunState};
    use crate::{
        FipsError, FipsIpv6Addr, FipsNodeAddr, HYF_FIPS_CONTROL_MAX_RESPONSE_BYTES,
        derive_fips_ipv6_addr,
    };

    pub fn parse_show_status_response(input: &[u8]) -> Result<FipsStatus, FipsError> {
        if input.len() > HYF_FIPS_CONTROL_MAX_RESPONSE_BYTES {
            return Err(FipsError::ControlResponseTooLarge {
                len: input.len(),
                maximum: HYF_FIPS_CONTROL_MAX_RESPONSE_BYTES,
            });
        }

        let text = core::str::from_utf8(input).map_err(|_| FipsError::Utf8)?;
        let value =
            serde_json::from_str::<Value>(text).map_err(|_| FipsError::MalformedControlStatus)?;
        let envelope = value.as_object().ok_or(FipsError::MalformedControlStatus)?;
        let status = required_str(envelope, "status")?;
        if status != "ok" {
            return Err(FipsError::MalformedControlStatus);
        }

        let data = envelope
            .get("data")
            .and_then(Value::as_object)
            .ok_or(FipsError::MalformedControlStatus)?;
        let node_addr = parse_node_addr(required_str(data, "node_addr")?)?;
        let ipv6_addr = parse_ipv6_addr(required_str(data, "ipv6_addr")?)?;
        if ipv6_addr != derive_fips_ipv6_addr(node_addr) {
            return Err(FipsError::MalformedControlStatus);
        }

        Ok(FipsStatus {
            node_addr,
            ipv6_addr,
            tun_state: FipsTunState::from_control_str(required_str(data, "tun_state")?),
            effective_ipv6_mtu: optional_u16(data, "effective_ipv6_mtu")?,
            peer_count: optional_u16(data, "peer_count")?,
        })
    }

    fn required_str<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, FipsError> {
        object
            .get(field)
            .and_then(Value::as_str)
            .ok_or(FipsError::MalformedControlStatus)
    }

    fn optional_u16(object: &Map<String, Value>, field: &str) -> Result<Option<u16>, FipsError> {
        let Some(value) = object.get(field) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }
        let Some(number) = value.as_u64() else {
            return Err(FipsError::MalformedControlStatus);
        };
        u16::try_from(number)
            .map(Some)
            .map_err(|_| FipsError::MalformedControlStatus)
    }

    fn parse_node_addr(input: &str) -> Result<FipsNodeAddr, FipsError> {
        if input.len() != 32 {
            return Err(FipsError::MalformedControlStatus);
        }

        let mut out = [0; 16];
        let bytes = input.as_bytes();
        for index in 0..16 {
            let high = decode_lower_nibble(bytes[index * 2])?;
            let low = decode_lower_nibble(bytes[(index * 2) + 1])?;
            out[index] = (high << 4) | low;
        }
        Ok(FipsNodeAddr::from_bytes(out))
    }

    fn decode_lower_nibble(byte: u8) -> Result<u8, FipsError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(FipsError::MalformedControlStatus),
        }
    }

    fn parse_ipv6_addr(input: &str) -> Result<FipsIpv6Addr, FipsError> {
        let parsed = Ipv6Addr::from_str(input).map_err(|_| FipsError::MalformedControlStatus)?;
        Ok(FipsIpv6Addr::from_bytes(parsed.octets()))
    }

    #[cfg(test)]
    mod tests {
        use super::parse_show_status_response;
        use crate::{
            FipsError, FipsIpv6Addr, FipsNodeAddr, FipsTunState,
            HYF_FIPS_CONTROL_MAX_RESPONSE_BYTES,
        };

        const VALID_STATUS: &[u8] = br#"{
  "status": "ok",
  "data": {
    "node_addr": "1b4788b7ab7a436a611fc59fb1e34c6e",
    "ipv6_addr": "fd1b:4788:b7ab:7a43:6a61:1fc5:9fb1:e34c",
    "tun_state": "disabled",
    "effective_ipv6_mtu": 1203,
    "peer_count": 0,
    "ignored": "value"
  },
  "message": "ignored"
}"#;

        #[test]
        fn control_status_accepts_minimal_valid_fixture_envelope() -> Result<(), FipsError> {
            let status = parse_show_status_response(VALID_STATUS)?;

            assert_eq!(
                status.node_addr,
                FipsNodeAddr::from_bytes([
                    0x1b, 0x47, 0x88, 0xb7, 0xab, 0x7a, 0x43, 0x6a, 0x61, 0x1f, 0xc5, 0x9f, 0xb1,
                    0xe3, 0x4c, 0x6e,
                ])
            );
            assert_eq!(
                status.ipv6_addr,
                FipsIpv6Addr::from_bytes([
                    0xfd, 0x1b, 0x47, 0x88, 0xb7, 0xab, 0x7a, 0x43, 0x6a, 0x61, 0x1f, 0xc5, 0x9f,
                    0xb1, 0xe3, 0x4c,
                ])
            );
            assert_eq!(status.tun_state, FipsTunState::Disabled);
            assert_eq!(status.effective_ipv6_mtu, Some(1203));
            assert_eq!(status.peer_count, Some(0));
            Ok(())
        }

        #[test]
        fn control_status_accepts_unknown_tun_state_and_missing_optional_fields()
        -> Result<(), FipsError> {
            let input = br#"{
  "status": "ok",
  "data": {
    "node_addr": "1b4788b7ab7a436a611fc59fb1e34c6e",
    "ipv6_addr": "fd1b:4788:b7ab:7a43:6a61:1fc5:9fb1:e34c",
    "tun_state": "warming"
  }
}"#;
            let status = parse_show_status_response(input)?;

            assert_eq!(status.tun_state, FipsTunState::Unknown);
            assert_eq!(status.effective_ipv6_mtu, None);
            assert_eq!(status.peer_count, None);
            Ok(())
        }

        #[test]
        fn control_status_parses_reference_tun_states() -> Result<(), FipsError> {
            for (tun_state, expected) in [
                ("disabled", FipsTunState::Disabled),
                ("configured", FipsTunState::Configured),
                ("active", FipsTunState::Active),
                ("failed", FipsTunState::Failed),
            ] {
                let input = format!(
                    r#"{{
  "status": "ok",
  "data": {{
    "node_addr": "1b4788b7ab7a436a611fc59fb1e34c6e",
    "ipv6_addr": "fd1b:4788:b7ab:7a43:6a61:1fc5:9fb1:e34c",
    "tun_state": "{tun_state}"
  }}
}}"#
                );

                let status = parse_show_status_response(input.as_bytes())?;
                assert_eq!(status.tun_state, expected);
                assert_eq!(status.effective_ipv6_mtu, None);
                assert_eq!(status.peer_count, None);
            }
            Ok(())
        }

        #[test]
        fn control_status_rejects_oversized_response() {
            let oversized = [b' '; HYF_FIPS_CONTROL_MAX_RESPONSE_BYTES + 1];

            assert_eq!(
                parse_show_status_response(&oversized),
                Err(FipsError::ControlResponseTooLarge {
                    len: HYF_FIPS_CONTROL_MAX_RESPONSE_BYTES + 1,
                    maximum: HYF_FIPS_CONTROL_MAX_RESPONSE_BYTES
                })
            );
        }

        #[test]
        fn control_status_rejects_error_envelope() {
            assert_eq!(
                parse_show_status_response(br#"{"status":"error","message":"no"}"#),
                Err(FipsError::MalformedControlStatus)
            );
        }

        #[test]
        fn control_status_rejects_missing_required_fields() {
            assert_eq!(
                parse_show_status_response(br#"{"status":"ok","data":{"tun_state":"active"}}"#),
                Err(FipsError::MalformedControlStatus)
            );
        }

        #[test]
        fn control_status_rejects_bad_node_address() {
            assert_eq!(
                parse_show_status_response(br#"{"status":"ok","data":{"node_addr":"ZZ4788b7ab7a436a611fc59fb1e34c6e","ipv6_addr":"fd1b:4788:b7ab:7a43:6a61:1fc5:9fb1:e34c","tun_state":"active"}}"#),
                Err(FipsError::MalformedControlStatus)
            );
        }

        #[test]
        fn control_status_rejects_bad_ipv6_address() {
            assert_eq!(
                parse_show_status_response(br#"{"status":"ok","data":{"node_addr":"1b4788b7ab7a436a611fc59fb1e34c6e","ipv6_addr":"fd1b:4788:b7ab:7a43:6a61:1fc5:9fb1:e34d","tun_state":"active"}}"#),
                Err(FipsError::MalformedControlStatus)
            );
        }

        #[test]
        fn control_status_rejects_bad_optional_numeric_field() {
            assert_eq!(
                parse_show_status_response(br#"{"status":"ok","data":{"node_addr":"1b4788b7ab7a436a611fc59fb1e34c6e","ipv6_addr":"fd1b:4788:b7ab:7a43:6a61:1fc5:9fb1:e34c","tun_state":"active","peer_count":70000}}"#),
                Err(FipsError::MalformedControlStatus)
            );
        }

        #[test]
        fn control_status_rejects_invalid_utf8() {
            assert_eq!(parse_show_status_response(&[0xff]), Err(FipsError::Utf8));
        }
    }
}

#[cfg(feature = "control_json")]
pub use json::parse_show_status_response;
