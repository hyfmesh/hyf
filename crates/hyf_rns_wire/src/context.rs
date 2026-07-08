pub const RNS_CONTEXT_NONE: u8 = 0x00;
pub const RNS_CONTEXT_RESOURCE: u8 = 0x01;
pub const RNS_CONTEXT_RESOURCE_ADV: u8 = 0x02;
pub const RNS_CONTEXT_RESOURCE_REQ: u8 = 0x03;
pub const RNS_CONTEXT_RESOURCE_HMU: u8 = 0x04;
pub const RNS_CONTEXT_RESOURCE_PRF: u8 = 0x05;
pub const RNS_CONTEXT_RESOURCE_ICL: u8 = 0x06;
pub const RNS_CONTEXT_RESOURCE_RCL: u8 = 0x07;
pub const RNS_CONTEXT_CACHE_REQUEST: u8 = 0x08;
pub const RNS_CONTEXT_REQUEST: u8 = 0x09;
pub const RNS_CONTEXT_RESPONSE: u8 = 0x0a;
pub const RNS_CONTEXT_PATH_RESPONSE: u8 = 0x0b;
pub const RNS_CONTEXT_COMMAND: u8 = 0x0c;
pub const RNS_CONTEXT_COMMAND_STATUS: u8 = 0x0d;
pub const RNS_CONTEXT_CHANNEL: u8 = 0x0e;
pub const RNS_CONTEXT_KEEPALIVE: u8 = 0xfa;
pub const RNS_CONTEXT_LINKIDENTIFY: u8 = 0xfb;
pub const RNS_CONTEXT_LINKCLOSE: u8 = 0xfc;
pub const RNS_CONTEXT_LINKPROOF: u8 = 0xfd;
pub const RNS_CONTEXT_LRRTT: u8 = 0xfe;
pub const RNS_CONTEXT_LRPROOF: u8 = 0xff;

#[cfg(test)]
mod tests {
    use super::{
        RNS_CONTEXT_CACHE_REQUEST, RNS_CONTEXT_CHANNEL, RNS_CONTEXT_COMMAND,
        RNS_CONTEXT_COMMAND_STATUS, RNS_CONTEXT_KEEPALIVE, RNS_CONTEXT_LINKCLOSE,
        RNS_CONTEXT_LINKIDENTIFY, RNS_CONTEXT_LINKPROOF, RNS_CONTEXT_LRPROOF, RNS_CONTEXT_LRRTT,
        RNS_CONTEXT_NONE, RNS_CONTEXT_PATH_RESPONSE, RNS_CONTEXT_REQUEST, RNS_CONTEXT_RESOURCE,
        RNS_CONTEXT_RESOURCE_ADV, RNS_CONTEXT_RESOURCE_HMU, RNS_CONTEXT_RESOURCE_ICL,
        RNS_CONTEXT_RESOURCE_PRF, RNS_CONTEXT_RESOURCE_RCL, RNS_CONTEXT_RESOURCE_REQ,
        RNS_CONTEXT_RESPONSE,
    };

    #[test]
    fn context_constants_match_reticulum_values() {
        assert_eq!(RNS_CONTEXT_NONE, 0x00);
        assert_eq!(RNS_CONTEXT_RESOURCE, 0x01);
        assert_eq!(RNS_CONTEXT_RESOURCE_ADV, 0x02);
        assert_eq!(RNS_CONTEXT_RESOURCE_REQ, 0x03);
        assert_eq!(RNS_CONTEXT_RESOURCE_HMU, 0x04);
        assert_eq!(RNS_CONTEXT_RESOURCE_PRF, 0x05);
        assert_eq!(RNS_CONTEXT_RESOURCE_ICL, 0x06);
        assert_eq!(RNS_CONTEXT_RESOURCE_RCL, 0x07);
        assert_eq!(RNS_CONTEXT_CACHE_REQUEST, 0x08);
        assert_eq!(RNS_CONTEXT_REQUEST, 0x09);
        assert_eq!(RNS_CONTEXT_RESPONSE, 0x0a);
        assert_eq!(RNS_CONTEXT_PATH_RESPONSE, 0x0b);
        assert_eq!(RNS_CONTEXT_COMMAND, 0x0c);
        assert_eq!(RNS_CONTEXT_COMMAND_STATUS, 0x0d);
        assert_eq!(RNS_CONTEXT_CHANNEL, 0x0e);
        assert_eq!(RNS_CONTEXT_KEEPALIVE, 0xfa);
        assert_eq!(RNS_CONTEXT_LINKIDENTIFY, 0xfb);
        assert_eq!(RNS_CONTEXT_LINKCLOSE, 0xfc);
        assert_eq!(RNS_CONTEXT_LINKPROOF, 0xfd);
        assert_eq!(RNS_CONTEXT_LRRTT, 0xfe);
        assert_eq!(RNS_CONTEXT_LRPROOF, 0xff);
    }
}
