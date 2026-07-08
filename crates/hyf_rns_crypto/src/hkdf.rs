use hkdf::Hkdf;
use sha2::Sha256;

use crate::RnsCryptoError;

const RNS_HKDF_DEFAULT_SALT: [u8; 32] = [0; 32];

pub fn rns_hkdf_sha256(
    output: &mut [u8],
    input_key_material: &[u8],
    salt: Option<&[u8]>,
    context: Option<&[u8]>,
) -> Result<(), RnsCryptoError> {
    if output.is_empty() {
        return Err(RnsCryptoError::EmptyHkdfOutput);
    }
    if input_key_material.is_empty() {
        return Err(RnsCryptoError::EmptyHkdfInputKeyMaterial);
    }

    let salt = match salt {
        Some([]) | None => RNS_HKDF_DEFAULT_SALT.as_slice(),
        Some(salt) => salt,
    };
    let context = context.unwrap_or_default();
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input_key_material);
    hkdf.expand(context, output)
        .map_err(|_| RnsCryptoError::InvalidHkdfLength)
}

#[cfg(test)]
mod tests {
    use super::rns_hkdf_sha256;
    use crate::RnsCryptoError;

    #[test]
    fn hkdf_rejects_empty_output() {
        let mut output = [];

        assert_eq!(
            rns_hkdf_sha256(&mut output, b"ikm", None, None),
            Err(RnsCryptoError::EmptyHkdfOutput)
        );
    }

    #[test]
    fn hkdf_rejects_empty_input_key_material() {
        let mut output = [0; 32];

        assert_eq!(
            rns_hkdf_sha256(&mut output, b"", None, None),
            Err(RnsCryptoError::EmptyHkdfInputKeyMaterial)
        );
    }

    #[test]
    fn hkdf_empty_salt_matches_missing_salt() -> Result<(), RnsCryptoError> {
        let mut missing_salt = [0; 64];
        let mut empty_salt = [0; 64];

        rns_hkdf_sha256(&mut missing_salt, b"ikm", None, Some(b"context"))?;
        rns_hkdf_sha256(&mut empty_salt, b"ikm", Some(&[]), Some(b"context"))?;

        assert_eq!(missing_salt, empty_salt);
        assert_ne!(missing_salt, [0; 64]);
        Ok(())
    }
}
