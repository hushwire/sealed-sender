use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::{DeviceId, IdentityKey, ServerKeyId, UserId};

/// A sender's identity certificate, signed by the server.
///
/// Binds a user + device to an [`IdentityKey`] with an expiry time.
/// Serialized with postcard inside the ECIES envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderCertificate {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub identity_key: IdentityKey,
    pub expires_at_secs: i64,
}

impl SenderCertificate {
    /// Returns the certificate expiry as a `DateTime<Utc>`.
    pub fn expires_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.expires_at_secs, 0).unwrap_or(DateTime::<Utc>::MAX_UTC)
    }
}

/// A [`SenderCertificate`] with an Ed25519 signature from the server.
///
/// Included inside the ECIES stage 2 payload so the recipient can verify
/// the sender's identity after decryption.
#[derive(Clone, Debug)]
pub struct SignedSenderCertificate {
    pub certificate: SenderCertificate,
    pub signature: [u8; 64],
    pub server_key_id: ServerKeyId,
}

impl SignedSenderCertificate {
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

impl Serialize for SignedSenderCertificate {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Helper<'a> {
            certificate: &'a SenderCertificate,
            #[serde(with = "sig_serde")]
            signature: &'a [u8; 64],
            server_key_id: &'a ServerKeyId,
        }
        Helper {
            certificate: &self.certificate,
            signature: &self.signature,
            server_key_id: &self.server_key_id,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedSenderCertificate {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            certificate: SenderCertificate,
            #[serde(with = "sig_serde")]
            signature: [u8; 64],
            server_key_id: ServerKeyId,
        }
        let h = Helper::deserialize(deserializer)?;
        Ok(Self {
            certificate: h.certificate,
            signature: h.signature,
            server_key_id: h.server_key_id,
        })
    }
}

/// A set of trusted server Ed25519 public keys, keyed by [`ServerKeyId`].
///
/// Recipients use this to verify sender certificates. Supports key rotation
/// by holding multiple keys simultaneously.
pub struct TrustRoot {
    keys: BTreeMap<ServerKeyId, VerifyingKey>,
}

impl TrustRoot {
    /// Create a trust root with a single server key.
    pub fn new(key_id: ServerKeyId, public_key: VerifyingKey) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(key_id, public_key);
        Self { keys }
    }

    /// Add (or replace) a server key for rotation.
    pub fn add_key(&mut self, key_id: ServerKeyId, public_key: VerifyingKey) {
        self.keys.insert(key_id, public_key);
    }

    /// Look up a server key by ID.
    pub fn get_key(&self, key_id: ServerKeyId) -> Option<&VerifyingKey> {
        self.keys.get(&key_id)
    }

    /// Verify the Ed25519 signature on a signed sender certificate.
    pub fn verify(&self, cert: &SignedSenderCertificate) -> Result<()> {
        let verifying_key = self
            .get_key(cert.server_key_id)
            .ok_or(Error::UnknownServerKey)?;

        let cert_bytes =
            postcard::to_allocvec(&cert.certificate).map_err(|_| Error::Serialization)?;

        let signature = Signature::from_bytes(&cert.signature);

        verifying_key
            .verify(&cert_bytes, &signature)
            .map_err(|_| Error::InvalidSignature)
    }
}

/// Issue a signed sender certificate (server-side operation).
///
/// The server signs the certificate with its Ed25519 key. Clients include
/// the resulting [`SignedSenderCertificate`] in every sealed message.
pub fn issue_certificate(
    server_signing_key: &SigningKey,
    server_key_id: ServerKeyId,
    sender: &crate::types::SenderIdentity,
    expires_at: DateTime<Utc>,
) -> Result<SignedSenderCertificate> {
    let certificate = SenderCertificate {
        user_id: sender.user_id,
        device_id: sender.device_id,
        identity_key: sender.identity_key,
        expires_at_secs: expires_at.timestamp(),
    };

    let cert_bytes = postcard::to_allocvec(&certificate).map_err(|_| Error::Serialization)?;
    let signature = server_signing_key.sign(&cert_bytes);

    Ok(SignedSenderCertificate {
        certificate,
        signature: signature.to_bytes(),
        server_key_id,
    })
}

/// Verify a sender certificate's signature and check that it has not expired.
pub fn verify_certificate(
    trust_root: &TrustRoot,
    cert: &SignedSenderCertificate,
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
    use crate::types::SenderIdentity;
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn test_fixtures() -> (SigningKey, ServerKeyId, SenderIdentity, TrustRoot) {
        let server_key = SigningKey::generate(&mut OsRng);
        let server_key_id = ServerKeyId::new(1);
        let trust_root = TrustRoot::new(server_key_id, server_key.verifying_key());

        let sender = SenderIdentity {
            user_id: UserId::from_bytes([1u8; 16]),
            device_id: DeviceId::new(42),
            identity_key: IdentityKey::from_bytes([2u8; 32]),
        };

        (server_key, server_key_id, sender, trust_root)
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let (server_key, server_key_id, sender, trust_root) = test_fixtures();
        let expires = DateTime::<Utc>::MAX_UTC;

        let cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();

        assert_eq!(cert.certificate.user_id, sender.user_id);
        assert_eq!(cert.certificate.device_id, sender.device_id);
        assert_eq!(cert.certificate.identity_key, sender.identity_key);

        let now = Utc.timestamp_opt(1000, 0).unwrap();
        verify_certificate(&trust_root, &cert, now).unwrap();
    }

    #[test]
    fn rejects_expired_certificate() {
        let (server_key, server_key_id, sender, trust_root) = test_fixtures();
        let expires = Utc.timestamp_opt(1000, 0).unwrap();

        let cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();

        let err = verify_certificate(&trust_root, &cert, expires).unwrap_err();
        assert!(matches!(err, Error::CertificateExpired));

        let later = Utc.timestamp_opt(2000, 0).unwrap();
        let err = verify_certificate(&trust_root, &cert, later).unwrap_err();
        assert!(matches!(err, Error::CertificateExpired));
    }

    #[test]
    fn accepts_not_yet_expired() {
        let (server_key, server_key_id, sender, trust_root) = test_fixtures();
        let expires = Utc.timestamp_opt(1000, 0).unwrap();

        let cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();

        let before = Utc.timestamp_opt(999, 0).unwrap();
        verify_certificate(&trust_root, &cert, before).unwrap();
    }

    #[test]
    fn rejects_wrong_server_key() {
        let (server_key, server_key_id, sender, _) = test_fixtures();
        let expires = DateTime::<Utc>::MAX_UTC;

        let cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();

        let other_key = SigningKey::generate(&mut OsRng);
        let wrong_trust_root = TrustRoot::new(server_key_id, other_key.verifying_key());

        let now = Utc.timestamp_opt(0, 0).unwrap();
        let err = verify_certificate(&wrong_trust_root, &cert, now).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature));
    }

    #[test]
    fn rejects_unknown_server_key_id() {
        let (server_key, server_key_id, sender, trust_root) = test_fixtures();
        let expires = DateTime::<Utc>::MAX_UTC;

        let mut cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();
        cert.server_key_id = ServerKeyId::new(999);

        let now = Utc.timestamp_opt(0, 0).unwrap();
        let err = verify_certificate(&trust_root, &cert, now).unwrap_err();
        assert!(matches!(err, Error::UnknownServerKey));
    }

    #[test]
    fn rejects_tampered_certificate() {
        let (server_key, server_key_id, sender, trust_root) = test_fixtures();
        let expires = DateTime::<Utc>::MAX_UTC;

        let mut cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();
        cert.certificate.user_id = UserId::from_bytes([0xFF; 16]);

        let now = Utc.timestamp_opt(0, 0).unwrap();
        let err = verify_certificate(&trust_root, &cert, now).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature));
    }

    #[test]
    fn postcard_serialization_deterministic() {
        let (server_key, server_key_id, sender, _) = test_fixtures();
        let expires = Utc.timestamp_opt(12345, 0).unwrap();

        let cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();

        let bytes1 = cert.serialize_certificate().unwrap();
        let bytes2 = cert.serialize_certificate().unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn trust_root_key_rotation() {
        let server_key_1 = SigningKey::generate(&mut OsRng);
        let server_key_2 = SigningKey::generate(&mut OsRng);
        let key_id_1 = ServerKeyId::new(1);
        let key_id_2 = ServerKeyId::new(2);

        let mut trust_root = TrustRoot::new(key_id_1, server_key_1.verifying_key());
        trust_root.add_key(key_id_2, server_key_2.verifying_key());

        let sender = SenderIdentity {
            user_id: UserId::from_bytes([1u8; 16]),
            device_id: DeviceId::new(1),
            identity_key: IdentityKey::from_bytes([2u8; 32]),
        };
        let expires = DateTime::<Utc>::MAX_UTC;

        let cert1 = issue_certificate(&server_key_1, key_id_1, &sender, expires).unwrap();
        let cert2 = issue_certificate(&server_key_2, key_id_2, &sender, expires).unwrap();

        let now = Utc.timestamp_opt(0, 0).unwrap();
        verify_certificate(&trust_root, &cert1, now).unwrap();
        verify_certificate(&trust_root, &cert2, now).unwrap();
    }
}
