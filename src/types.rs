use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// A user identifier (16 bytes, typically a UUID).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId([u8; 16]);

impl UserId {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A device identifier within a user account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(u32);

impl DeviceId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// An X25519 public key used as a long-term identity key.
///
/// Equality comparison is constant-time via [`subtle::ConstantTimeEq`].
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct IdentityKey([u8; 32]);

impl IdentityKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ConstantTimeEq for IdentityKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for IdentityKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for IdentityKey {}

impl From<x25519_dalek::PublicKey> for IdentityKey {
    fn from(key: x25519_dalek::PublicKey) -> Self {
        Self(key.to_bytes())
    }
}

impl From<&IdentityKey> for x25519_dalek::PublicKey {
    fn from(key: &IdentityKey) -> Self {
        x25519_dalek::PublicKey::from(key.0)
    }
}

#[cfg(feature = "mls-rs")]
impl TryFrom<&mls_rs_core::crypto::HpkePublicKey> for IdentityKey {
    type Error = crate::error::Error;

    fn try_from(key: &mls_rs_core::crypto::HpkePublicKey) -> crate::error::Result<Self> {
        let bytes: &[u8] = key.as_ref();
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| crate::error::Error::InvalidKey)?;
        Ok(Self(arr))
    }
}

#[cfg(feature = "mls-rs")]
impl From<IdentityKey> for mls_rs_core::crypto::HpkePublicKey {
    fn from(key: IdentityKey) -> Self {
        mls_rs_core::crypto::HpkePublicKey::new(key.0.to_vec())
    }
}

/// Identifies which server Ed25519 signing key issued a certificate.
///
/// Supports key rotation: the [`TrustRoot`](crate::TrustRoot) maps `ServerKeyId` to public keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServerKeyId(u32);

impl ServerKeyId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

#[cfg(feature = "uuid")]
impl From<uuid::Uuid> for UserId {
    fn from(id: uuid::Uuid) -> Self {
        Self(*id.as_bytes())
    }
}

#[cfg(feature = "uuid")]
impl From<UserId> for uuid::Uuid {
    fn from(id: UserId) -> Self {
        uuid::Uuid::from_bytes(id.0)
    }
}

/// The sender's identity fields needed to issue a [`SenderCertificate`](crate::SenderCertificate).
pub struct SenderIdentity {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub identity_key: IdentityKey,
}

/// Protocol configuration.
///
/// The `label` field is the HKDF domain separation label. Override it to
/// prevent cross-protocol key reuse (e.g. `b"HushwireSealedSender-v1"`).
pub struct Config {
    pub label: &'static [u8],
}

impl Default for Config {
    fn default() -> Self {
        Self {
            label: b"SealedSender",
        }
    }
}
