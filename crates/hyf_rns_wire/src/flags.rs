use crate::RnsWireError;

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
    use super::{RnsDestinationType, RnsHeaderType, RnsPacketType, RnsTransportType};
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
}
