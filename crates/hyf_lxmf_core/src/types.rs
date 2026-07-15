use core::fmt;

use crate::{
    LXMF_DESTINATION_HASH_LEN, LXMF_MESSAGE_ID_LEN, LXMF_SIGNATURE_LEN, LXMF_SOURCE_HASH_LEN,
};

macro_rules! lxmf_fixed_type {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn into_bytes(self) -> [u8; $len] {
                self.0
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self::from_bytes(bytes)
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(value: $name) -> Self {
                value.into_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("bytes", &"<redacted>")
                    .field("len", &$len)
                    .finish()
            }
        }
    };
}

lxmf_fixed_type!(LxmfDestinationHash, LXMF_DESTINATION_HASH_LEN);
lxmf_fixed_type!(LxmfSourceHash, LXMF_SOURCE_HASH_LEN);
lxmf_fixed_type!(LxmfSignature, LXMF_SIGNATURE_LEN);
lxmf_fixed_type!(LxmfMessageId, LXMF_MESSAGE_ID_LEN);

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LxmfRawMapRef<'a> {
    pub bytes: &'a [u8],
}

impl fmt::Debug for LxmfRawMapRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LxmfRawMapRef")
            .field("bytes", &"<redacted>")
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LxmfStampRef<'a> {
    pub bytes: &'a [u8],
}

impl fmt::Debug for LxmfStampRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LxmfStampRef")
            .field("bytes", &"<redacted>")
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct LxmfPayloadRef<'a> {
    pub timestamp_secs: f64,
    pub title: &'a [u8],
    pub content: &'a [u8],
    pub fields: LxmfRawMapRef<'a>,
    pub stamp: Option<LxmfStampRef<'a>>,
}

impl fmt::Debug for LxmfPayloadRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LxmfPayloadRef")
            .field("timestamp_secs", &self.timestamp_secs)
            .field("title", &"<redacted>")
            .field("title_len", &self.title.len())
            .field("content", &"<redacted>")
            .field("content_len", &self.content.len())
            .field("fields", &self.fields)
            .field("stamp", &self.stamp)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct LxmfMessageRef<'a> {
    destination_hash: LxmfDestinationHash,
    source_hash: LxmfSourceHash,
    signature: LxmfSignature,
    packed_payload: &'a [u8],
    payload: LxmfPayloadRef<'a>,
}

impl<'a> LxmfMessageRef<'a> {
    pub(crate) const fn from_validated_parts(
        destination_hash: LxmfDestinationHash,
        source_hash: LxmfSourceHash,
        signature: LxmfSignature,
        packed_payload: &'a [u8],
        payload: LxmfPayloadRef<'a>,
    ) -> Self {
        Self {
            destination_hash,
            source_hash,
            signature,
            packed_payload,
            payload,
        }
    }

    pub const fn destination_hash(&self) -> &LxmfDestinationHash {
        &self.destination_hash
    }

    pub const fn source_hash(&self) -> &LxmfSourceHash {
        &self.source_hash
    }

    pub const fn signature(&self) -> &LxmfSignature {
        &self.signature
    }

    pub const fn packed_payload(&self) -> &'a [u8] {
        self.packed_payload
    }

    pub const fn payload(&self) -> LxmfPayloadRef<'a> {
        self.payload
    }
}

impl fmt::Debug for LxmfMessageRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LxmfMessageRef")
            .field("destination_hash", &self.destination_hash)
            .field("source_hash", &self.source_hash)
            .field("signature", &"<redacted>")
            .field("packed_payload", &"<redacted>")
            .field("packed_payload_len", &self.packed_payload.len())
            .field("payload", &self.payload)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LxmfDestinationHash, LxmfMessageId, LxmfMessageRef, LxmfPayloadRef, LxmfRawMapRef,
        LxmfSignature, LxmfSourceHash, LxmfStampRef,
    };

    #[test]
    fn fixed_types_preserve_bytes() {
        let destination = LxmfDestinationHash::from_bytes([1; 16]);
        let source = LxmfSourceHash::from_bytes([2; 16]);
        let signature = LxmfSignature::from_bytes([3; 64]);
        let message_id = LxmfMessageId::from_bytes([4; 32]);

        assert_eq!(destination.as_bytes(), &[1; 16]);
        assert_eq!(source.into_bytes(), [2; 16]);
        assert_eq!(signature.as_bytes(), &[3; 64]);
        assert_eq!(message_id.into_bytes(), [4; 32]);
    }

    #[test]
    fn debug_redacts_sensitive_payload_bytes() {
        let payload = LxmfPayloadRef {
            timestamp_secs: 1.5,
            title: b"secret-title",
            content: b"secret-content",
            fields: LxmfRawMapRef {
                bytes: b"secret-fields",
            },
            stamp: Some(LxmfStampRef {
                bytes: b"secret-stamp",
            }),
        };
        let message = LxmfMessageRef::from_validated_parts(
            LxmfDestinationHash::from_bytes([1; 16]),
            LxmfSourceHash::from_bytes([2; 16]),
            LxmfSignature::from_bytes([3; 64]),
            b"secret-payload",
            payload,
        );
        let debug = format!("{message:?}");

        assert_eq!(message.destination_hash().as_bytes(), &[1; 16]);
        assert_eq!(message.source_hash().as_bytes(), &[2; 16]);
        assert_eq!(message.signature().as_bytes(), &[3; 64]);
        assert_eq!(message.packed_payload(), b"secret-payload");
        assert_eq!(message.payload().title, b"secret-title");
        assert!(debug.contains("LxmfMessageRef"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-title"));
        assert!(!debug.contains("secret-content"));
        assert!(!debug.contains("secret-fields"));
        assert!(!debug.contains("secret-stamp"));
        assert!(!debug.contains("secret-payload"));
        assert!(!debug.contains("3, 3, 3"));
    }
}
