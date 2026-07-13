use k256::schnorr::{Signature, SigningKey, VerifyingKey};

use crate::{
    NostrError, NostrEvent, NostrPublicKey, NostrSecretKey, NostrSignature, NostrUnsignedEvent,
    event_id,
};

const DETERMINISTIC_AUX_RAND: [u8; 32] = [0; 32];

pub fn derive_nostr_public_key(secret: &NostrSecretKey) -> Result<NostrPublicKey, NostrError> {
    let signing_key = signing_key(secret)?;
    Ok(public_key_from_signing_key(&signing_key))
}

pub fn sign_event<'a>(
    event: NostrUnsignedEvent<'a>,
    secret: &NostrSecretKey,
) -> Result<NostrEvent<'a>, NostrError> {
    let signing_key = signing_key(secret)?;
    let pubkey = public_key_from_signing_key(&signing_key);
    if event.pubkey != pubkey {
        return Err(NostrError::PublicKeyMismatch);
    }

    let id = event_id(&event)?;
    let signature = signing_key
        .sign_raw(id.as_bytes(), &DETERMINISTIC_AUX_RAND)
        .map_err(|_| NostrError::Crypto)?;
    let mut signature_bytes = [0; 64];
    signature_bytes.copy_from_slice(&signature.to_bytes());

    NostrEvent::new(
        id,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content,
        NostrSignature::from_bytes(signature_bytes),
    )
}

pub fn verify_event(event: &NostrEvent<'_>) -> Result<(), NostrError> {
    let expected_id = event_id(&event.unsigned())?;
    if event.id != expected_id {
        return Err(NostrError::EventIdMismatch);
    }

    let verifying_key =
        VerifyingKey::from_slice(event.pubkey.as_bytes()).map_err(|_| NostrError::Crypto)?;
    let signature =
        Signature::from_slice(event.sig.as_bytes()).map_err(|_| NostrError::InvalidSignature)?;
    verifying_key
        .verify_raw(event.id.as_bytes(), &signature)
        .map_err(|_| NostrError::InvalidSignature)
}

fn signing_key(secret: &NostrSecretKey) -> Result<SigningKey, NostrError> {
    SigningKey::from_slice(secret.as_bytes()).map_err(|_| NostrError::Crypto)
}

fn public_key_from_signing_key(signing_key: &SigningKey) -> NostrPublicKey {
    let mut pubkey = [0; 32];
    pubkey.copy_from_slice(&signing_key.verifying_key().to_bytes());
    NostrPublicKey::from_bytes(pubkey)
}

#[cfg(test)]
mod tests {
    use super::{derive_nostr_public_key, sign_event, verify_event};
    use crate::{
        HYF_NOSTR_ENVELOPE_KIND, NostrError, NostrEvent, NostrEventId, NostrPublicKey,
        NostrSecretKey, NostrSignature, NostrTagRef, NostrTagsRef, NostrUnsignedEvent, event_id,
    };

    #[test]
    fn derives_bip340_fixture_public_key() -> Result<(), NostrError> {
        assert_eq!(
            derive_nostr_public_key(&fixture_secret())?,
            fixture_public_key()
        );
        Ok(())
    }

    #[test]
    fn signs_event_id_with_matching_pubkey() -> Result<(), NostrError> {
        let secret = fixture_secret();
        let unsigned = fixture_event()?;
        let signed = sign_event(unsigned, &secret)?;

        assert_eq!(signed.id, event_id(&unsigned)?);
        assert_eq!(signed.pubkey, fixture_public_key());
        assert_eq!(signed.created_at, unsigned.created_at);
        assert_eq!(signed.kind, HYF_NOSTR_ENVELOPE_KIND);
        assert_eq!(signed.content, "abcd");
        verify_event(&signed)?;
        Ok(())
    }

    #[test]
    fn signing_is_deterministic_for_same_event_and_secret() -> Result<(), NostrError> {
        let secret = fixture_secret();
        let unsigned = fixture_event()?;

        let first = sign_event(unsigned, &secret)?;
        let second = sign_event(unsigned, &secret)?;

        assert_eq!(first.id, second.id);
        assert_eq!(first.sig, second.sig);
        Ok(())
    }

    #[test]
    fn verifies_valid_signed_events() -> Result<(), NostrError> {
        let signed = signed_fixture_event()?;

        verify_event(&signed)
    }

    #[test]
    fn verification_rejects_tampered_event_id() -> Result<(), NostrError> {
        let signed = signed_fixture_event()?;
        let tampered = NostrEvent {
            id: NostrEventId::from_bytes([0x42; 32]),
            ..signed
        };

        assert_eq!(verify_event(&tampered), Err(NostrError::EventIdMismatch));
        Ok(())
    }

    #[test]
    fn verification_rejects_tampered_content_kind_pubkey_and_tags() -> Result<(), NostrError> {
        let signed = signed_fixture_event()?;

        let content = NostrEvent {
            content: "abce",
            ..signed
        };
        assert_eq!(verify_event(&content), Err(NostrError::EventIdMismatch));

        let kind = NostrEvent { kind: 1, ..signed };
        assert_eq!(verify_event(&kind), Err(NostrError::EventIdMismatch));

        let pubkey = NostrEvent {
            pubkey: NostrPublicKey::from_bytes([0x42; 32]),
            ..signed
        };
        assert_eq!(verify_event(&pubkey), Err(NostrError::EventIdMismatch));

        let tag_values = [
            "p",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        let tag = NostrTagRef::new(&tag_values)?;
        let tags = [tag];
        let tags = NostrEvent {
            tags: NostrTagsRef::new(&tags),
            ..signed
        };
        assert_eq!(verify_event(&tags), Err(NostrError::EventIdMismatch));
        Ok(())
    }

    #[test]
    fn verification_rejects_tampered_signature() -> Result<(), NostrError> {
        let signed = signed_fixture_event()?;
        let mut signature = *signed.sig.as_bytes();
        signature[0] ^= 0x01;
        let tampered = NostrEvent {
            sig: NostrSignature::from_bytes(signature),
            ..signed
        };

        assert_eq!(verify_event(&tampered), Err(NostrError::InvalidSignature));
        Ok(())
    }

    #[test]
    fn signing_rejects_event_pubkey_mismatch() -> Result<(), NostrError> {
        let unsigned = NostrUnsignedEvent::new(
            NostrPublicKey::from_bytes([0x42; 32]),
            1720000000,
            HYF_NOSTR_ENVELOPE_KIND,
            NostrTagsRef::new(&[]),
            "abcd",
        )?;

        assert!(matches!(
            sign_event(unsigned, &fixture_secret()),
            Err(NostrError::PublicKeyMismatch)
        ));
        Ok(())
    }

    fn fixture_secret() -> NostrSecretKey {
        let mut secret_key = [0; 32];
        secret_key[31] = 3;
        NostrSecretKey::from_bytes(secret_key)
    }

    fn fixture_public_key() -> NostrPublicKey {
        NostrPublicKey::from_bytes([
            0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d,
            0x52, 0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13,
            0xbc, 0xe0, 0x36, 0xf9,
        ])
    }

    fn fixture_event() -> Result<NostrUnsignedEvent<'static>, NostrError> {
        NostrUnsignedEvent::new(
            fixture_public_key(),
            1720000000,
            HYF_NOSTR_ENVELOPE_KIND,
            NostrTagsRef::new(&[]),
            "abcd",
        )
    }

    fn signed_fixture_event() -> Result<NostrEvent<'static>, NostrError> {
        sign_event(fixture_event()?, &fixture_secret())
    }
}
