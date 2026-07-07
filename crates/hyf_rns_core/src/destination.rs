use sha2::{Digest, Sha256};

use crate::{RnsCoreError, RnsNameHash};

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

#[cfg(test)]
mod tests {
    use super::{destination_name_hash, validate_destination_name};
    use crate::{RnsCoreError, RnsNameHash};

    const EMPTY_APP_NAME_HASH: RnsNameHash =
        RnsNameHash::new([0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb]);

    const APP_EMPTY_ASPECT_NAME_HASH: RnsNameHash =
        RnsNameHash::new([0x1e, 0xf4, 0xa5, 0xd1, 0xb6, 0x4f, 0x73, 0x26, 0xee, 0x4c]);

    const APP_NAMED_ASPECT_NAME_HASH: RnsNameHash =
        RnsNameHash::new([0x4b, 0x78, 0x9e, 0x95, 0xce, 0x3b, 0x6e, 0x81, 0x13, 0x1b]);

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
}
