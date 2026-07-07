#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LinkId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LinkClass {
    RawLora,
    RNodeKiss,
    Serial,
    Wifi,
    Ble,
    Nostr,
}

pub trait Link {
    fn link_id(&self) -> LinkId;
    fn link_class(&self) -> LinkClass;
    fn mtu(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::{Link, LinkClass, LinkId};

    struct FixedLink;

    impl Link for FixedLink {
        fn link_id(&self) -> LinkId {
            LinkId([7; 16])
        }

        fn link_class(&self) -> LinkClass {
            LinkClass::RawLora
        }

        fn mtu(&self) -> usize {
            500
        }
    }

    #[test]
    fn crate_builds() {}

    #[test]
    fn link_id_preserves_bytes() {
        let bytes = [4; 16];
        let id = LinkId(bytes);

        assert_eq!(id.0, bytes);
    }

    #[test]
    fn link_class_variants_are_distinct() {
        assert_ne!(LinkClass::RawLora, LinkClass::RNodeKiss);
        assert_ne!(LinkClass::Serial, LinkClass::Wifi);
        assert_ne!(LinkClass::Ble, LinkClass::Nostr);
    }

    #[test]
    fn link_trait_exposes_metadata_only() {
        let link = FixedLink;

        assert_eq!(link.link_id(), LinkId([7; 16]));
        assert_eq!(link.link_class(), LinkClass::RawLora);
        assert_eq!(link.mtu(), 500);
    }
}
