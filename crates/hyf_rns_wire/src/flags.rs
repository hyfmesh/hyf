use crate::RnsWireError;

pub(crate) const IFAC_FLAG: u8 = 0b1000_0000;
const HEADER_TYPE_MASK: u8 = 0b0100_0000;
const CONTEXT_FLAG_MASK: u8 = 0b0010_0000;
const TRANSPORT_TYPE_MASK: u8 = 0b0001_0000;
const DESTINATION_TYPE_MASK: u8 = 0b0000_1100;
const PACKET_TYPE_MASK: u8 = 0b0000_0011;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RnsPacketFlags {
    pub header_type: RnsHeaderType,
    pub context_flag: bool,
    pub transport_type: RnsTransportType,
    pub destination_type: RnsDestinationType,
    pub packet_type: RnsPacketType,
}

pub const fn encode_flags(flags: RnsPacketFlags) -> u8 {
    (flags.header_type.to_bits() << 6)
        | ((flags.context_flag as u8) << 5)
        | (flags.transport_type.to_bits() << 4)
        | (flags.destination_type.to_bits() << 2)
        | flags.packet_type.to_bits()
}

pub fn decode_flags(byte: u8) -> Result<RnsPacketFlags, RnsWireError> {
    if byte & IFAC_FLAG != 0 {
        return Err(RnsWireError::UnsupportedPacketAccessCode);
    }

    Ok(RnsPacketFlags {
        header_type: RnsHeaderType::from_bits((byte & HEADER_TYPE_MASK) >> 6)?,
        context_flag: byte & CONTEXT_FLAG_MASK != 0,
        transport_type: RnsTransportType::from_bits((byte & TRANSPORT_TYPE_MASK) >> 4)?,
        destination_type: RnsDestinationType::from_bits((byte & DESTINATION_TYPE_MASK) >> 2)?,
        packet_type: RnsPacketType::from_bits(byte & PACKET_TYPE_MASK)?,
    })
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RnsHeaderType {
    Header1 = 0x00,
    Header2 = 0x01,
}

impl RnsHeaderType {
    pub const fn to_bits(self) -> u8 {
        self as u8
    }

    pub const fn from_bits(bits: u8) -> Result<Self, RnsWireError> {
        match bits {
            0x00 => Ok(Self::Header1),
            0x01 => Ok(Self::Header2),
            _ => Err(RnsWireError::InvalidHeaderType),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RnsTransportType {
    Broadcast = 0x00,
    Transport = 0x01,
}

impl RnsTransportType {
    pub const fn to_bits(self) -> u8 {
        self as u8
    }

    pub const fn from_bits(bits: u8) -> Result<Self, RnsWireError> {
        match bits {
            0x00 => Ok(Self::Broadcast),
            0x01 => Ok(Self::Transport),
            _ => Err(RnsWireError::InvalidTransportType),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RnsDestinationType {
    Single = 0x00,
    Group = 0x01,
    Plain = 0x02,
    Link = 0x03,
}

impl RnsDestinationType {
    pub const fn to_bits(self) -> u8 {
        self as u8
    }

    pub const fn from_bits(bits: u8) -> Result<Self, RnsWireError> {
        match bits {
            0x00 => Ok(Self::Single),
            0x01 => Ok(Self::Group),
            0x02 => Ok(Self::Plain),
            0x03 => Ok(Self::Link),
            _ => Err(RnsWireError::InvalidDestinationType),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RnsPacketType {
    Data = 0x00,
    Announce = 0x01,
    LinkRequest = 0x02,
    Proof = 0x03,
}

impl RnsPacketType {
    pub const fn to_bits(self) -> u8 {
        self as u8
    }

    pub const fn from_bits(bits: u8) -> Result<Self, RnsWireError> {
        match bits {
            0x00 => Ok(Self::Data),
            0x01 => Ok(Self::Announce),
            0x02 => Ok(Self::LinkRequest),
            0x03 => Ok(Self::Proof),
            _ => Err(RnsWireError::InvalidPacketType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RnsDestinationType, RnsHeaderType, RnsPacketFlags, RnsPacketType, RnsTransportType,
        decode_flags, encode_flags,
    };
    use crate::RnsWireError;

    #[test]
    fn header_type_conversions_match_reticulum_values() {
        assert_eq!(RnsHeaderType::Header1.to_bits(), 0x00);
        assert_eq!(RnsHeaderType::Header2.to_bits(), 0x01);
        assert_eq!(RnsHeaderType::from_bits(0x00), Ok(RnsHeaderType::Header1));
        assert_eq!(RnsHeaderType::from_bits(0x01), Ok(RnsHeaderType::Header2));
        assert_eq!(
            RnsHeaderType::from_bits(0x02),
            Err(RnsWireError::InvalidHeaderType)
        );
    }

    #[test]
    fn transport_type_conversions_match_profile_values() {
        assert_eq!(RnsTransportType::Broadcast.to_bits(), 0x00);
        assert_eq!(RnsTransportType::Transport.to_bits(), 0x01);
        assert_eq!(
            RnsTransportType::from_bits(0x00),
            Ok(RnsTransportType::Broadcast)
        );
        assert_eq!(
            RnsTransportType::from_bits(0x01),
            Ok(RnsTransportType::Transport)
        );
        assert_eq!(
            RnsTransportType::from_bits(0x02),
            Err(RnsWireError::InvalidTransportType)
        );
    }

    #[test]
    fn destination_type_conversions_match_reticulum_values() {
        assert_eq!(RnsDestinationType::Single.to_bits(), 0x00);
        assert_eq!(RnsDestinationType::Group.to_bits(), 0x01);
        assert_eq!(RnsDestinationType::Plain.to_bits(), 0x02);
        assert_eq!(RnsDestinationType::Link.to_bits(), 0x03);
        assert_eq!(
            RnsDestinationType::from_bits(0x00),
            Ok(RnsDestinationType::Single)
        );
        assert_eq!(
            RnsDestinationType::from_bits(0x01),
            Ok(RnsDestinationType::Group)
        );
        assert_eq!(
            RnsDestinationType::from_bits(0x02),
            Ok(RnsDestinationType::Plain)
        );
        assert_eq!(
            RnsDestinationType::from_bits(0x03),
            Ok(RnsDestinationType::Link)
        );
        assert_eq!(
            RnsDestinationType::from_bits(0x04),
            Err(RnsWireError::InvalidDestinationType)
        );
    }

    #[test]
    fn packet_type_conversions_match_reticulum_values() {
        assert_eq!(RnsPacketType::Data.to_bits(), 0x00);
        assert_eq!(RnsPacketType::Announce.to_bits(), 0x01);
        assert_eq!(RnsPacketType::LinkRequest.to_bits(), 0x02);
        assert_eq!(RnsPacketType::Proof.to_bits(), 0x03);
        assert_eq!(RnsPacketType::from_bits(0x00), Ok(RnsPacketType::Data));
        assert_eq!(RnsPacketType::from_bits(0x01), Ok(RnsPacketType::Announce));
        assert_eq!(
            RnsPacketType::from_bits(0x02),
            Ok(RnsPacketType::LinkRequest)
        );
        assert_eq!(RnsPacketType::from_bits(0x03), Ok(RnsPacketType::Proof));
        assert_eq!(
            RnsPacketType::from_bits(0x04),
            Err(RnsWireError::InvalidPacketType)
        );
    }

    #[test]
    fn flag_encoding_matches_reticulum_bit_layout() {
        let flags = RnsPacketFlags {
            header_type: RnsHeaderType::Header2,
            context_flag: true,
            transport_type: RnsTransportType::Transport,
            destination_type: RnsDestinationType::Link,
            packet_type: RnsPacketType::Proof,
        };

        assert_eq!(encode_flags(flags), 0b0111_1111);
    }

    #[test]
    fn flag_decoding_matches_reticulum_bit_layout() {
        assert_eq!(
            decode_flags(0b0111_1111),
            Ok(RnsPacketFlags {
                header_type: RnsHeaderType::Header2,
                context_flag: true,
                transport_type: RnsTransportType::Transport,
                destination_type: RnsDestinationType::Link,
                packet_type: RnsPacketType::Proof,
            })
        );
        assert_eq!(
            decode_flags(0b0000_0001),
            Ok(RnsPacketFlags {
                header_type: RnsHeaderType::Header1,
                context_flag: false,
                transport_type: RnsTransportType::Broadcast,
                destination_type: RnsDestinationType::Single,
                packet_type: RnsPacketType::Announce,
            })
        );
    }

    #[test]
    fn flag_roundtrips_all_profile_values() -> Result<(), RnsWireError> {
        let header_types = [RnsHeaderType::Header1, RnsHeaderType::Header2];
        let context_flags = [false, true];
        let transport_types = [RnsTransportType::Broadcast, RnsTransportType::Transport];
        let destination_types = [
            RnsDestinationType::Single,
            RnsDestinationType::Group,
            RnsDestinationType::Plain,
            RnsDestinationType::Link,
        ];
        let packet_types = [
            RnsPacketType::Data,
            RnsPacketType::Announce,
            RnsPacketType::LinkRequest,
            RnsPacketType::Proof,
        ];

        for header_type in header_types {
            for context_flag in context_flags {
                for transport_type in transport_types {
                    for destination_type in destination_types {
                        for packet_type in packet_types {
                            let flags = RnsPacketFlags {
                                header_type,
                                context_flag,
                                transport_type,
                                destination_type,
                                packet_type,
                            };

                            assert_eq!(decode_flags(encode_flags(flags))?, flags);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[test]
    fn flag_decoding_rejects_unsupported_ifac_high_bit() {
        assert_eq!(
            decode_flags(0b1000_0000),
            Err(RnsWireError::UnsupportedPacketAccessCode)
        );
        assert_eq!(
            decode_flags(0b1111_1111),
            Err(RnsWireError::UnsupportedPacketAccessCode)
        );
    }
}
