use crate::BitchatError;

const FLAG_HAS_RECIPIENT: u8 = 0x01;
const FLAG_HAS_SIGNATURE: u8 = 0x02;
const FLAG_IS_COMPRESSED: u8 = 0x04;
const FLAG_HAS_ROUTE: u8 = 0x08;
const FLAG_IS_RSR: u8 = 0x10;
const FLAG_RESERVED_MASK: u8 = 0xe0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitchatVersion {
    V1,
    V2,
}

impl BitchatVersion {
    pub(crate) fn from_wire_value(version: u8) -> Result<Self, BitchatError> {
        match version {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            _ => Err(BitchatError::UnknownVersion { version }),
        }
    }

    pub const fn wire_value(self) -> u8 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitchatFlags {
    pub has_recipient: bool,
    pub has_signature: bool,
    pub is_compressed: bool,
    pub has_route: bool,
    pub is_rsr: bool,
}

impl BitchatFlags {
    pub const fn empty() -> Self {
        Self {
            has_recipient: false,
            has_signature: false,
            is_compressed: false,
            has_route: false,
            is_rsr: false,
        }
    }

    pub fn from_wire_byte(flags: u8) -> Result<Self, BitchatError> {
        if flags & FLAG_RESERVED_MASK != 0 {
            return Err(BitchatError::ReservedFlags { flags });
        }

        Ok(Self {
            has_recipient: flags & FLAG_HAS_RECIPIENT != 0,
            has_signature: flags & FLAG_HAS_SIGNATURE != 0,
            is_compressed: flags & FLAG_IS_COMPRESSED != 0,
            has_route: flags & FLAG_HAS_ROUTE != 0,
            is_rsr: flags & FLAG_IS_RSR != 0,
        })
    }

    pub(crate) const fn to_wire_byte(self) -> u8 {
        bool_flag(self.has_recipient, FLAG_HAS_RECIPIENT)
            | bool_flag(self.has_signature, FLAG_HAS_SIGNATURE)
            | bool_flag(self.is_compressed, FLAG_IS_COMPRESSED)
            | bool_flag(self.has_route, FLAG_HAS_ROUTE)
            | bool_flag(self.is_rsr, FLAG_IS_RSR)
    }
}

const fn bool_flag(value: bool, flag: u8) -> u8 {
    if value { flag } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::{BitchatFlags, BitchatVersion};
    use crate::BitchatError;

    #[test]
    fn versions_preserve_wire_values() -> Result<(), BitchatError> {
        assert_eq!(BitchatVersion::V1.wire_value(), 1);
        assert_eq!(BitchatVersion::V2.wire_value(), 2);
        assert_eq!(BitchatVersion::from_wire_value(1)?, BitchatVersion::V1);
        assert_eq!(BitchatVersion::from_wire_value(2)?, BitchatVersion::V2);
        assert_eq!(
            BitchatVersion::from_wire_value(3),
            Err(BitchatError::UnknownVersion { version: 3 })
        );

        Ok(())
    }

    #[test]
    fn flags_parse_known_bits() -> Result<(), BitchatError> {
        let flags = BitchatFlags::from_wire_byte(0x1f)?;

        assert!(flags.has_recipient);
        assert!(flags.has_signature);
        assert!(flags.is_compressed);
        assert!(flags.has_route);
        assert!(flags.is_rsr);
        assert_eq!(flags.to_wire_byte(), 0x1f);

        Ok(())
    }

    #[test]
    fn flags_reject_reserved_bits() {
        assert_eq!(
            BitchatFlags::from_wire_byte(0xe0),
            Err(BitchatError::ReservedFlags { flags: 0xe0 })
        );
    }

    #[test]
    fn empty_flags_roundtrip_to_zero() -> Result<(), BitchatError> {
        assert_eq!(BitchatFlags::empty().to_wire_byte(), 0);
        assert_eq!(BitchatFlags::from_wire_byte(0)?, BitchatFlags::empty());

        Ok(())
    }
}
