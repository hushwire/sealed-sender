use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::{IdentityKey, RecipientId, SigningKeyId};

/// A sender's identity certificate, signed by a trusted issuer.
///
/// Binds a sender identity to an [`IdentityKey`] with an expiry time.
/// Serialized with postcard inside the ECIES envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "R: Serialize", deserialize = "R: DeserializeOwned"))]
pub struct SenderCertificate<R: RecipientId> {
    /// The sender's application-level identifier.
    pub sender_id: R,
    /// The sender's long-term X25519 identity key.
    pub identity_key: IdentityKey,
    /// Certificate expiry as a Unix timestamp (seconds since epoch).
    pub expires_at_secs: i64,
    /// Which signing key issued this certificate.
    pub signing_key_id: SigningKeyId,
}

impl<R: RecipientId> SenderCertificate<R> {
    /// Returns the certificate expiry as a `DateTime<Utc>`.
    pub fn expires_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.expires_at_secs, 0).unwrap_or(DateTime::<Utc>::MAX_UTC)
    }
}

/// A [`SenderCertificate`] with an Ed25519 signature from the issuer.
///
/// Included inside the ECIES stage 2 payload so the recipient can verify
/// the sender's identity after decryption.
#[derive(Clone, Debug)]
pub struct SignedSenderCertificate<R: RecipientId> {
    /// The underlying certificate.
    pub certificate: SenderCertificate<R>,
    /// Ed25519 signature over the serialized certificate.
    pub signature: [u8; 64],
}

impl<R: RecipientId> SignedSenderCertificate<R> {
    /// Serialize the inner certificate to postcard bytes (for signature verification).
    pub fn serialize_certificate(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(&self.certificate).map_err(|_| Error::Serialization)
    }
}

mod sig_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        sig.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64-byte signature"))
    }
}

impl<R: RecipientId> Serialize for SignedSenderCertificate<R> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(bound(serialize = "R: Serialize"))]
        struct Helper<'a, R: RecipientId> {
            certificate: &'a SenderCertificate<R>,
            #[serde(with = "sig_serde")]
            signature: &'a [u8; 64],
        }
        Helper {
            certificate: &self.certificate,
            signature: &self.signature,
        }
        .serialize(serializer)
    }
}

impl<'de, R: RecipientId> Deserialize<'de> for SignedSenderCertificate<R> {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(bound(deserialize = "R: DeserializeOwned"))]
        struct Helper<R: RecipientId> {
            #[serde(bound(deserialize = "R: DeserializeOwned"))]
            certificate: SenderCertificate<R>,
            #[serde(with = "sig_serde")]
            signature: [u8; 64],
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(Self {
            certificate: h.certificate,
            signature: h.signature,
        })
    }
}

/// A set of trusted Ed25519 public keys, keyed by [`SigningKeyId`].
///
/// Recipients use this to verify sender certificates. Supports key rotation
/// by holding multiple keys simultaneously.
#[derive(Clone, Debug)]
pub struct TrustRoot {
    keys: BTreeMap<SigningKeyId, VerifyingKey>,
}

impl TrustRoot {
    /// Create a trust root with a single signing key.
    pub fn new(key_id: SigningKeyId, public_key: VerifyingKey) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(key_id, public_key);
        Self { keys }
    }

    /// Add (or replace) a signing key for rotation.
    pub fn add_key(&mut self, key_id: SigningKeyId, public_key: VerifyingKey) {
        self.keys.insert(key_id, public_key);
    }

    /// Look up a signing key by ID.
    pub fn get_key(&self, key_id: SigningKeyId) -> Option<&VerifyingKey> {
        self.keys.get(&key_id)
    }

    /// Verify the Ed25519 signature on a signed sender certificate.
    pub fn verify<R: RecipientId>(&self, cert: &SignedSenderCertificate<R>) -> Result<()> {
        let verifying_key = self
            .get_key(cert.certificate.signing_key_id)
            .ok_or(Error::UnknownSigningKey)?;

        let cert_bytes =
            postcard::to_allocvec(&cert.certificate).map_err(|_| Error::Serialization)?;

        let signature = Signature::from_bytes(&cert.signature);

        verifying_key
            .verify(&cert_bytes, &signature)
            .map_err(|_| Error::InvalidSignature)
    }
}

/// Issue a signed sender certificate.
///
/// The issuer signs the certificate with its Ed25519 key. Senders include
/// the resulting [`SignedSenderCertificate`] in every sealed message.
pub fn issue_certificate<R: RecipientId>(
    signing_key: &SigningKey,
    signing_key_id: SigningKeyId,
    sender: &crate::types::SenderIdentity<R>,
    expires_at: DateTime<Utc>,
) -> Result<SignedSenderCertificate<R>> {
    let certificate = SenderCertificate {
        sender_id: sender.id.clone(),
        identity_key: sender.identity_key,
        expires_at_secs: expires_at.timestamp(),
        signing_key_id,
    };

    let cert_bytes = postcard::to_allocvec(&certificate).map_err(|_| Error::Serialization)?;
    let signature = signing_key.sign(&cert_bytes);

    Ok(SignedSenderCertificate {
        certificate,
        signature: signature.to_bytes(),
    })
}

/// Verify a sender certificate's signature and check that it has not expired.
pub fn verify_certificate<R: RecipientId>(
    trust_root: &TrustRoot,
    cert: &SignedSenderCertificate<R>,
    now: DateTime<Utc>,
) -> Result<()> {
    trust_root.verify(cert)?;

    if cert.certificate.expires_at() <= now {
        return Err(Error::CertificateExpired);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Recipient, SenderIdentity};
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn test_fixtures() -> (
        SigningKey,
        SigningKeyId,
        SenderIdentity<Recipient>,
        TrustRoot,
    ) {
        let issuer_key = SigningKey::generate(&mut OsRng);
        let signing_key_id = SigningKeyId::new(1);
        let trust_root = TrustRoot::new(signing_key_id, issuer_key.verifying_key());

        let sender = SenderIdentity {
            id: Recipient::from_bytes_copy(&[1u8; 16]),
            identity_key: IdentityKey::from_bytes([2u8; 32]),
        };

        (issuer_key, signing_key_id, sender, trust_root)
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let (issuer_key, signing_key_id, sender, trust_root) = test_fixtures();
        let expires = DateTime::<Utc>::MAX_UTC;

        let cert = issue_certificate(&issuer_key, signing_key_id, &sender, expires).unwrap();

        assert_eq!(cert.certificate.sender_id, sender.id);
        assert_eq!(cert.certificate.identity_key, sender.identity_key);

        let now = Utc.timestamp_opt(1000, 0).unwrap();
        verify_certificate(&trust_root, &cert, now).unwrap();
    }

    #[test]
    fn rejects_expired_certificate() {
        let (issuer_key, signing_key_id, sender, trust_root) = test_fixtures();
        let expires = Utc.timestamp_opt(1000, 0).unwrap();

        let cert = issue_certificate(&issuer_key, signing_key_id, &sender, expires).unwrap();

        let err = verify_certificate(&trust_root, &cert, expires).unwrap_err();
        assert!(matches!(err, Error::CertificateExpired));

        let later = Utc.timestamp_opt(2000, 0).unwrap();
        let err = verify_certificate(&trust_root, &cert, later).unwrap_err();
        assert!(matches!(err, Error::CertificateExpired));
    }

    #[test]
    fn accepts_not_yet_expired() {
        let (issuer_key, signing_key_id, sender, trust_root) = test_fixtures();
        let expires = Utc.timestamp_opt(1000, 0).unwrap();

        let cert = issue_certificate(&issuer_key, signing_key_id, &sender, expires).unwrap();

        let before = Utc.timestamp_opt(999, 0).unwrap();
        verify_certificate(&trust_root, &cert, before).unwrap();
    }

    #[test]
    fn rejects_wrong_issuer_key() {
        let (issuer_key, signing_key_id, sender, _) = test_fixtures();
        let expires = DateTime::<Utc>::MAX_UTC;

        let cert = issue_certificate(&issuer_key, signing_key_id, &sender, expires).unwrap();

        let other_key = SigningKey::generate(&mut OsRng);
        let wrong_trust_root = TrustRoot::new(signing_key_id, other_key.verifying_key());

        let now = Utc.timestamp_opt(0, 0).unwrap();
        let err = verify_certificate(&wrong_trust_root, &cert, now).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature));
    }

    #[test]
    fn rejects_unknown_signing_key_id() {
        let (issuer_key, signing_key_id, sender, trust_root) = test_fixtures();
        let expires = DateTime::<Utc>::MAX_UTC;

        let mut cert = issue_certificate(&issuer_key, signing_key_id, &sender, expires).unwrap();
        cert.certificate.signing_key_id = SigningKeyId::new(999);

        let now = Utc.timestamp_opt(0, 0).unwrap();
        let err = verify_certificate(&trust_root, &cert, now).unwrap_err();
        assert!(matches!(err, Error::UnknownSigningKey));
    }

    #[test]
    fn rejects_tampered_certificate() {
        let (issuer_key, signing_key_id, sender, trust_root) = test_fixtures();
        let expires = DateTime::<Utc>::MAX_UTC;

        let mut cert = issue_certificate(&issuer_key, signing_key_id, &sender, expires).unwrap();
        cert.certificate.sender_id = Recipient::from_bytes_copy(&[0xFF; 16]);

        let now = Utc.timestamp_opt(0, 0).unwrap();
        let err = verify_certificate(&trust_root, &cert, now).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature));
    }

    #[test]
    fn postcard_serialization_deterministic() {
        let (issuer_key, signing_key_id, sender, _) = test_fixtures();
        let expires = Utc.timestamp_opt(12345, 0).unwrap();

        let cert = issue_certificate(&issuer_key, signing_key_id, &sender, expires).unwrap();

        let bytes1 = cert.serialize_certificate().unwrap();
        let bytes2 = cert.serialize_certificate().unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn trust_root_key_rotation() {
        let issuer_key_1 = SigningKey::generate(&mut OsRng);
        let issuer_key_2 = SigningKey::generate(&mut OsRng);
        let key_id_1 = SigningKeyId::new(1);
        let key_id_2 = SigningKeyId::new(2);

        let mut trust_root = TrustRoot::new(key_id_1, issuer_key_1.verifying_key());
        trust_root.add_key(key_id_2, issuer_key_2.verifying_key());

        let sender = SenderIdentity {
            id: Recipient::from_bytes_copy(&[1u8; 16]),
            identity_key: IdentityKey::from_bytes([2u8; 32]),
        };
        let expires = DateTime::<Utc>::MAX_UTC;

        let cert1 = issue_certificate(&issuer_key_1, key_id_1, &sender, expires).unwrap();
        let cert2 = issue_certificate(&issuer_key_2, key_id_2, &sender, expires).unwrap();

        let now = Utc.timestamp_opt(0, 0).unwrap();
        verify_certificate(&trust_root, &cert1, now).unwrap();
        verify_certificate(&trust_root, &cert2, now).unwrap();
    }
}
