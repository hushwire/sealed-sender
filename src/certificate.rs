use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::{DeviceId, IdentityKey, ServerKeyId, Timestamp, UserId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderCertificate {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub identity_key: IdentityKey,
    pub expires_at: Timestamp,
}

#[derive(Clone, Debug)]
pub struct SignedSenderCertificate {
    pub certificate: SenderCertificate,
    pub signature: [u8; 64],
    pub server_key_id: ServerKeyId,
}

impl SignedSenderCertificate {
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

pub struct TrustRoot {
    keys: BTreeMap<ServerKeyId, VerifyingKey>,
}

impl TrustRoot {
    pub fn new(key_id: ServerKeyId, public_key: VerifyingKey) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(key_id, public_key);
        Self { keys }
    }

    pub fn add_key(&mut self, key_id: ServerKeyId, public_key: VerifyingKey) {
        self.keys.insert(key_id, public_key);
    }

    pub fn get_key(&self, key_id: ServerKeyId) -> Option<&VerifyingKey> {
        self.keys.get(&key_id)
    }

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

pub fn issue_certificate(
    server_signing_key: &SigningKey,
    server_key_id: ServerKeyId,
    sender: &crate::types::SenderIdentity,
    expires_at: Timestamp,
) -> Result<SignedSenderCertificate> {
    let certificate = SenderCertificate {
        user_id: sender.user_id,
        device_id: sender.device_id,
        identity_key: sender.identity_key,
        expires_at,
    };

    let cert_bytes = postcard::to_allocvec(&certificate).map_err(|_| Error::Serialization)?;
    let signature = server_signing_key.sign(&cert_bytes);

    Ok(SignedSenderCertificate {
        certificate,
        signature: signature.to_bytes(),
        server_key_id,
    })
}

pub fn verify_certificate(
    trust_root: &TrustRoot,
    cert: &SignedSenderCertificate,
    now: Timestamp,
) -> Result<()> {
    trust_root.verify(cert)?;

    if cert.certificate.expires_at <= now {
        return Err(Error::CertificateExpired);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SenderIdentity;
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
        let expires = Timestamp::from_secs(u64::MAX);

        let cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();

        assert_eq!(cert.certificate.user_id, sender.user_id);
        assert_eq!(cert.certificate.device_id, sender.device_id);
        assert_eq!(cert.certificate.identity_key, sender.identity_key);
        assert_eq!(cert.certificate.expires_at, expires);

        verify_certificate(&trust_root, &cert, Timestamp::from_secs(1000)).unwrap();
    }

    #[test]
    fn rejects_expired_certificate() {
        let (server_key, server_key_id, sender, trust_root) = test_fixtures();
        let expires = Timestamp::from_secs(1000);

        let cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();

        let err = verify_certificate(&trust_root, &cert, Timestamp::from_secs(1000)).unwrap_err();
        assert!(matches!(err, Error::CertificateExpired));

        let err = verify_certificate(&trust_root, &cert, Timestamp::from_secs(2000)).unwrap_err();
        assert!(matches!(err, Error::CertificateExpired));
    }

    #[test]
    fn accepts_not_yet_expired() {
        let (server_key, server_key_id, sender, trust_root) = test_fixtures();
        let expires = Timestamp::from_secs(1000);

        let cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();

        verify_certificate(&trust_root, &cert, Timestamp::from_secs(999)).unwrap();
    }

    #[test]
    fn rejects_wrong_server_key() {
        let (server_key, server_key_id, sender, _) = test_fixtures();
        let expires = Timestamp::from_secs(u64::MAX);

        let cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();

        let other_key = SigningKey::generate(&mut OsRng);
        let wrong_trust_root = TrustRoot::new(server_key_id, other_key.verifying_key());

        let err =
            verify_certificate(&wrong_trust_root, &cert, Timestamp::from_secs(0)).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature));
    }

    #[test]
    fn rejects_unknown_server_key_id() {
        let (server_key, server_key_id, sender, trust_root) = test_fixtures();
        let expires = Timestamp::from_secs(u64::MAX);

        let mut cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();
        cert.server_key_id = ServerKeyId::new(999);

        let err = verify_certificate(&trust_root, &cert, Timestamp::from_secs(0)).unwrap_err();
        assert!(matches!(err, Error::UnknownServerKey));
    }

    #[test]
    fn rejects_tampered_certificate() {
        let (server_key, server_key_id, sender, trust_root) = test_fixtures();
        let expires = Timestamp::from_secs(u64::MAX);

        let mut cert = issue_certificate(&server_key, server_key_id, &sender, expires).unwrap();
        cert.certificate.user_id = UserId::from_bytes([0xFF; 16]);

        let err = verify_certificate(&trust_root, &cert, Timestamp::from_secs(0)).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature));
    }

    #[test]
    fn postcard_serialization_deterministic() {
        let (server_key, server_key_id, sender, _) = test_fixtures();
        let expires = Timestamp::from_secs(12345);

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
        let expires = Timestamp::from_secs(u64::MAX);

        let cert1 = issue_certificate(&server_key_1, key_id_1, &sender, expires).unwrap();
        let cert2 = issue_certificate(&server_key_2, key_id_2, &sender, expires).unwrap();

        verify_certificate(&trust_root, &cert1, Timestamp::from_secs(0)).unwrap();
        verify_certificate(&trust_root, &cert2, Timestamp::from_secs(0)).unwrap();
    }
}
