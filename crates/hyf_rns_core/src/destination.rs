use sha2::{Digest, Sha256};

use crate::{RnsCoreError, RnsDestinationHash, RnsIdentityHash, RnsNameHash};

pub fn validate_destination_name(app_name: &str, aspects: &[&str]) -> Result<(), RnsCoreError> {
    if app_name.contains('.') {
        return Err(RnsCoreError::DestinationAppNameContainsDot);
    }

    for aspect in aspects {
        if aspect.contains('.') {
            return Err(RnsCoreError::DestinationAspectContainsDot);
        }
    }

    Ok(())
}

pub fn destination_name_hash(
    app_name: &str,
    aspects: &[&str],
) -> Result<RnsNameHash, RnsCoreError> {
    validate_destination_name(app_name, aspects)?;

    let mut hasher = Sha256::new();
    hasher.update(app_name.as_bytes());
    for aspect in aspects {
        hasher.update(b".");
        hasher.update(aspect.as_bytes());
    }

    let full: [u8; 32] = hasher.finalize().into();
    let mut name_hash = [0; RnsNameHash::LEN];
    name_hash.copy_from_slice(&full[..RnsNameHash::LEN]);
    Ok(RnsNameHash::new(name_hash))
}

pub fn destination_hash(
    name_hash: RnsNameHash,
    identity_hash: Option<RnsIdentityHash>,
) -> RnsDestinationHash {
    let mut hasher = Sha256::new();
    hasher.update(name_hash.as_bytes());
    if let Some(identity_hash) = identity_hash {
        hasher.update(identity_hash.as_bytes());
    }

    let full: [u8; 32] = hasher.finalize().into();
    let mut destination_hash = [0; RnsDestinationHash::LEN];
    destination_hash.copy_from_slice(&full[..RnsDestinationHash::LEN]);
    RnsDestinationHash::new(destination_hash)
}

#[cfg(test)]
mod tests {
    use super::{destination_hash, destination_name_hash, validate_destination_name};
    use crate::{RnsCoreError, RnsDestinationHash, RnsIdentityHash, RnsNameHash};

    const EMPTY_APP_NAME_HASH: RnsNameHash =
        RnsNameHash::new([0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb]);

    const APP_EMPTY_ASPECT_NAME_HASH: RnsNameHash =
        RnsNameHash::new([0x1e, 0xf4, 0xa5, 0xd1, 0xb6, 0x4f, 0x73, 0x26, 0xee, 0x4c]);

    const APP_NAMED_ASPECT_NAME_HASH: RnsNameHash =
        RnsNameHash::new([0x4b, 0x78, 0x9e, 0x95, 0xce, 0x3b, 0x6e, 0x81, 0x13, 0x1b]);

    const TEST_IDENTITY_HASH: RnsIdentityHash = RnsIdentityHash::new([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ]);

    const EMPTY_APP_DESTINATION_HASH: RnsDestinationHash = RnsDestinationHash::new([
        0x0b, 0x51, 0xf5, 0x29, 0x82, 0x14, 0xb7, 0x81, 0x33, 0x46, 0x2e, 0xed, 0xbe, 0x84, 0x22,
        0xcd,
    ]);

    const APP_EMPTY_ASPECT_DESTINATION_HASH: RnsDestinationHash = RnsDestinationHash::new([
        0xd6, 0x27, 0x2b, 0x65, 0x8b, 0xbb, 0xa4, 0x17, 0x9c, 0xcf, 0x69, 0xb8, 0x72, 0x95, 0xed,
        0xb9,
    ]);

    const APP_NAMED_ASPECT_DESTINATION_HASH: RnsDestinationHash = RnsDestinationHash::new([
        0x1a, 0x9c, 0x81, 0x92, 0x83, 0x77, 0xf1, 0x39, 0x73, 0xd4, 0x75, 0xc0, 0xa1, 0xdc, 0xc5,
        0xb3,
    ]);

    const EMPTY_APP_IDENTITY_BOUND_DESTINATION_HASH: RnsDestinationHash =
        RnsDestinationHash::new([
            0x26, 0xd5, 0x1f, 0x1d, 0x94, 0x8b, 0x26, 0xb9, 0x72, 0xd3, 0x96, 0x0d, 0xfd, 0x4e,
            0x44, 0x4c,
        ]);

    const APP_EMPTY_ASPECT_IDENTITY_BOUND_DESTINATION_HASH: RnsDestinationHash =
        RnsDestinationHash::new([
            0x99, 0x68, 0xd5, 0x36, 0xbc, 0x81, 0x41, 0x0f, 0xd9, 0x26, 0x50, 0x00, 0x70, 0x4e,
            0x3e, 0x55,
        ]);

    const APP_NAMED_ASPECT_IDENTITY_BOUND_DESTINATION_HASH: RnsDestinationHash =
        RnsDestinationHash::new([
            0xb7, 0x75, 0x74, 0xba, 0x43, 0x32, 0x35, 0xa0, 0xc9, 0x1e, 0x80, 0xb1, 0xab, 0x3b,
            0xec, 0x38,
        ]);

    #[test]
    fn destination_name_allows_reticulum_empty_components() {
        assert_eq!(validate_destination_name("", &[]), Ok(()));
        assert_eq!(validate_destination_name("app", &[""]), Ok(()));
    }

    #[test]
    fn destination_name_allows_regular_components() {
        assert_eq!(validate_destination_name("app", &["aspect"]), Ok(()));
        assert_eq!(
            validate_destination_name("app", &["aspect", "subaspect"]),
            Ok(())
        );
    }

    #[test]
    fn destination_name_rejects_dotted_app_name() {
        assert_eq!(
            validate_destination_name("app.bad", &[]),
            Err(RnsCoreError::DestinationAppNameContainsDot)
        );
    }

    #[test]
    fn destination_name_rejects_dotted_aspect() {
        assert_eq!(
            validate_destination_name("app", &["bad.aspect"]),
            Err(RnsCoreError::DestinationAspectContainsDot)
        );
    }

    #[test]
    fn destination_name_hash_matches_reticulum_vectors() {
        assert_eq!(destination_name_hash("", &[]), Ok(EMPTY_APP_NAME_HASH));
        assert_eq!(
            destination_name_hash("app", &[""]),
            Ok(APP_EMPTY_ASPECT_NAME_HASH)
        );
        assert_eq!(
            destination_name_hash("app", &["aspect"]),
            Ok(APP_NAMED_ASPECT_NAME_HASH)
        );
    }

    #[test]
    fn destination_name_hash_reuses_validation_errors() {
        assert_eq!(
            destination_name_hash("app.bad", &[]),
            Err(RnsCoreError::DestinationAppNameContainsDot)
        );
        assert_eq!(
            destination_name_hash("app", &["bad.aspect"]),
            Err(RnsCoreError::DestinationAspectContainsDot)
        );
    }

    #[test]
    fn destination_hash_matches_reticulum_plain_vectors() {
        assert_eq!(
            destination_hash(EMPTY_APP_NAME_HASH, None),
            EMPTY_APP_DESTINATION_HASH
        );
        assert_eq!(
            destination_hash(APP_EMPTY_ASPECT_NAME_HASH, None),
            APP_EMPTY_ASPECT_DESTINATION_HASH
        );
        assert_eq!(
            destination_hash(APP_NAMED_ASPECT_NAME_HASH, None),
            APP_NAMED_ASPECT_DESTINATION_HASH
        );
    }

    #[test]
    fn destination_hash_matches_reticulum_identity_bound_vectors() {
        assert_eq!(
            destination_hash(EMPTY_APP_NAME_HASH, Some(TEST_IDENTITY_HASH)),
            EMPTY_APP_IDENTITY_BOUND_DESTINATION_HASH
        );
        assert_eq!(
            destination_hash(APP_EMPTY_ASPECT_NAME_HASH, Some(TEST_IDENTITY_HASH)),
            APP_EMPTY_ASPECT_IDENTITY_BOUND_DESTINATION_HASH
        );
        assert_eq!(
            destination_hash(APP_NAMED_ASPECT_NAME_HASH, Some(TEST_IDENTITY_HASH)),
            APP_NAMED_ASPECT_IDENTITY_BOUND_DESTINATION_HASH
        );
    }
}
