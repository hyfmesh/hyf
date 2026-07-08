#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RnsCryptoError {
    InvalidPublicIdentity,
    InvalidSecretIdentity,
    InvalidSignature,
}
