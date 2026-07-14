use crate::HyfWireError;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PayloadKind {
    HyfNativeV0 = 0,
    ForeignRnsPacket = 16,
    ForeignLxmfMessage = 17,
}

impl PayloadKind {
    pub const fn wire_tag(self) -> u8 {
        self as u8
    }

    pub const fn from_wire_tag(tag: u8) -> Result<Self, HyfWireError> {
        match tag {
            0 => Ok(Self::HyfNativeV0),
            16 => Ok(Self::ForeignRnsPacket),
            17 => Ok(Self::ForeignLxmfMessage),
            _ => Err(HyfWireError::InvalidPayloadKind { tag }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PayloadKind;
    use crate::HyfWireError;

    #[test]
    fn payload_kind_discriminants_are_stable() {
        assert_eq!(PayloadKind::HyfNativeV0.wire_tag(), 0);
        assert_eq!(PayloadKind::ForeignRnsPacket.wire_tag(), 16);
        assert_eq!(PayloadKind::ForeignLxmfMessage.wire_tag(), 17);
        assert_eq!(
            PayloadKind::from_wire_tag(17),
            Ok(PayloadKind::ForeignLxmfMessage)
        );
        assert_eq!(
            PayloadKind::from_wire_tag(18),
            Err(HyfWireError::InvalidPayloadKind { tag: 18 })
        );
    }
}
